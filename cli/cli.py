import json
import logging
import os
import sys
from collections import Counter
from logging.handlers import SysLogHandler

import click

from auditmatica.access_log import (
    ARCHIVEMATICA_NAME,
    DEFAULT_SS_BASE_URL,
    STORAGE_SERVICE_NAME,
    DateParseError,
    LogParseError,
    parse_access_log_line,
)
from auditmatica.cef import write_cef_event
from auditmatica.events import DEFAULT_EVENT, EVENT_SIGNATURE
from cli.syslog import SYSLOG_FACILITY

cef_logger = logging.getLogger()

EVENTS_WRITTEN = "events_written"
EVENTS_DEFAULT = "events_default"
LINES_FILTERED = "lines_filtered"
USERNAMES = "usernames"

DEFAULT_SYSLOG_ADDRESS = "/dev/log"

SS_BASE_URL_HELP_TEXT = (
    "Override the Storage Service URL to scan for (default='http://127.0.0.1:62081')"
)


def _configure_logging(
    use_syslog: bool,
    syslog_address: str,
    syslog_facility: str,
    syslog_port: int,
    output: str,
):
    """Configure logging to file or syslog as appropriate.

    :param use_syslog: Flag indicating whether to write CEF events to
        syslog rather than to a file
    :param syslog_address: Address for where to send syslog messages
    :param syslog_facility: Facility to use for syslog messages
    :param syslog_port: Port for where to send syslog messages
    :param cef_file: Filepath for output file, if writing CEF events to
         a file rather than syslog
    """
    if use_syslog:
        facility = SysLogHandler.LOG_USER
        try:
            facility = SYSLOG_FACILITY[syslog_facility.lower()]
        except KeyError:
            pass
        # Syslog addresses either take the form of a tuple (host, port)
        # or a string (e.g. "/dev/log"). Here we default to the string
        # format but use a tuple instead if an address and port are
        # both provided.
        if syslog_port and syslog_address != DEFAULT_SYSLOG_ADDRESS:
            syslog_address = (syslog_address, syslog_port)
        elif syslog_port:
            click.echo(
                "Warning: --syslog-port is only used if a valid --syslog-address value is also provided",
                err=True,
            )
        handler = SysLogHandler(address=syslog_address, facility=facility)
    elif output:
        file_path = os.path.abspath(output)
        handler = logging.FileHandler(file_path, mode="w", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
    else:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
    cef_logger.addHandler(handler)
    cef_logger.setLevel(logging.INFO)


def _process_log(log_lines: list, ss_base_url: str, suppress_unspecified: bool):
    """Process log and return statistics and errors.

    :param log_file: List of nginx access log lines
    :param ss_base_url: Base URL of Storage Service
    :param suppress_unspecified: Flag indicating whether to suppress
        default events

    :returns: Tuple of process statistics (dict) and errors (list)
    """
    stats = {EVENTS_WRITTEN: 0, EVENTS_DEFAULT: 0, LINES_FILTERED: 0, USERNAMES: False}
    errors = []

    for line in log_lines:
        try:
            parsed_line = parse_access_log_line(line, ss_base_url)

            # Empty dict means line was filtered out by URL.
            if not parsed_line:
                stats[LINES_FILTERED] += 1
                continue

            if parsed_line.get(EVENT_SIGNATURE) == DEFAULT_EVENT[EVENT_SIGNATURE]:
                stats[EVENTS_DEFAULT] += 1
                if suppress_unspecified:
                    continue

            if parsed_line.get("username") is not None:
                stats[USERNAMES] = True

            cef_event = write_cef_event(parsed_line)
            cef_logger.info(cef_event)
            stats[EVENTS_WRITTEN] += 1
        except (DateParseError, LogParseError) as err:
            errors.append(err)
    return (stats, errors)


@click.group()
@click.version_option()
def auditmatica():
    """Auditmatica: Archivematica auditing package"""


@auditmatica.command("write-cef")
@click.argument("log", type=click.File("r", encoding="utf-8"), default=sys.stdin)
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    default=None,
    help="Filepath for output CEF file (default=None, print to stdout)",
)
@click.option(
    "-s", "--syslog", is_flag=True, help="Write CEF events to syslog instead of file"
)
@click.option(
    "--syslog-address",
    type=str,
    default=DEFAULT_SYSLOG_ADDRESS,
    help="Address for syslog connection (default='/dev/log')",
)
@click.option(
    "--syslog-facility",
    type=str,
    default="USER",
    help="Facility for syslog messages (default='USER')",
)
@click.option(
    "--syslog-port", type=int, default=None, help="Port for remote syslog connections"
)
@click.option(
    "--ss-base-url", type=str, default=DEFAULT_SS_BASE_URL, help=SS_BASE_URL_HELP_TEXT
)
@click.option(
    "--suppress",
    is_flag=True,
    help="Suppress log lines that do not map to a specific event instead of reverting to default event",
)
@click.option(
    "-v", "--verbose", is_flag=True, help="Enable verbose error message reporting"
)
def write_cef_events(
    log,
    output,
    syslog,
    syslog_address,
    syslog_facility,
    syslog_port,
    ss_base_url,
    suppress,
    verbose,
):
    """Write Common Event Format (CEF) log from nginx access log."""
    log_lines = log.readlines()
    if not log_lines:
        click.echo("Nothing found in the logs", err=True)
        sys.exit(1)

    _configure_logging(syslog, syslog_address, syslog_facility, syslog_port, output)

    (stats, errors) = _process_log(log_lines, ss_base_url, suppress)

    # Print user-facing messages to stderr.
    click.echo("Done!", err=True)
    if not stats[USERNAMES]:
        click.echo(
            "Usernames not found in nginx log. If this is unexpected, ensure AuditLogMiddleware is enabled and check nginx log_format",
            err=True,
        )
    click.echo(f"Log lines: {len(log_lines)}", err=True)
    click.echo(f"CEF events written: {stats[EVENTS_WRITTEN]}", err=True)
    if suppress:
        click.echo(f"Suppressed default CEF events: {stats[EVENTS_DEFAULT]}", err=True)
    else:
        click.echo(
            f"  - Specific events: {stats[EVENTS_WRITTEN] - stats[EVENTS_DEFAULT]}",
            err=True,
        )
        click.echo(
            f"  - Default events (no exact match): {stats[EVENTS_DEFAULT]}", err=True
        )
    click.echo(f"Discarded log lines: {stats[LINES_FILTERED]}", err=True)
    if errors:
        click.echo(f"Errors: {len(errors)}", err=True)
        if verbose:
            for error in errors:
                click.echo(str(error).rstrip("\n"), err=True)
        else:
            click.echo(
                "To see more detailed error information, use -v/--verbose.", err=True
            )


def _get_unique_users_list(parsed_log_lines, event_name, product):
    """Return unique list of users associated with event."""
    users = set(
        line["username"]
        for line in parsed_log_lines
        if line.get("event_name") == event_name
        and line.get("product") == product
        and line["username"]
    )
    return [
        user if (user != "None") else "Unauthenticated user" for user in sorted(users)
    ]


@auditmatica.command("overview")
@click.argument("log", type=click.File("r", encoding="utf-8"), default=sys.stdin)
@click.option(
    "--ss-base-url", type=str, default=DEFAULT_SS_BASE_URL, help=SS_BASE_URL_HELP_TEXT
)
def overview(log, ss_base_url):
    """Write JSON overview of user activities from nginx access log."""
    log_lines = log.readlines()
    if not log_lines:
        click.echo("Nothing found in the logs", err=True)
        sys.exit(1)

    parsed_log_lines = []
    errors = []

    output = {}

    archivematica_events = []
    storage_service_events = []

    for line in log_lines:
        try:
            parsed_line = parse_access_log_line(line, ss_base_url)
            if parsed_line:
                parsed_log_lines.append(parsed_line)
        except (DateParseError, LogParseError) as err:
            errors.append(err)

    am_events_by_name = Counter(
        line.get("event_name")
        for line in parsed_log_lines
        if line.get("product") == ARCHIVEMATICA_NAME
    )
    if am_events_by_name:
        for event_name, count in am_events_by_name.most_common():
            event_dict = {}
            event_dict["event_name"] = event_name
            event_dict["count"] = count
            event_dict["users"] = _get_unique_users_list(
                parsed_log_lines, event_name, ARCHIVEMATICA_NAME
            )
            archivematica_events.append(event_dict)
        output["Archivematica events"] = archivematica_events

    ss_events_by_name = Counter(
        line.get("event_name")
        for line in parsed_log_lines
        if line.get("product") == STORAGE_SERVICE_NAME
    )
    if ss_events_by_name:
        for event_name, count in ss_events_by_name.most_common():
            event_dict = {}
            event_dict["event_name"] = event_name
            event_dict["count"] = count
            event_dict["users"] = _get_unique_users_list(
                parsed_log_lines, event_name, STORAGE_SERVICE_NAME
            )
            storage_service_events.append(event_dict)
        output["Storage Service events"] = storage_service_events

    if errors:
        output["Errors"] = {
            "count": len(errors),
            "error_messages": [str(error).rstrip("\n") for error in errors],
        }

    click.echo(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    auditmatica()
