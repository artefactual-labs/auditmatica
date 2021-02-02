"""Nginx access log parsing functions and constants."""
import os
import re
from datetime import datetime

from auditmatica import events

ARCHIVEMATICA_NAME = "Archivematica"
STORAGE_SERVICE_NAME = "Archivematica Storage Service"

DEFAULT_SS_BASE_URL = "http://127.0.0.1:62081"

UUID_REGEX = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

ACCESS_LOG_DATE_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
CEF_DATE_FORMAT = "%b %d %Y %H:%M:%S"

# These regular expressions match the expected log_format configuration
# in the nginx.conf file, and are used to parse the nginx access log
# lines into a re.Match.groupdict dictionary keyed by subgroup name.
# Subgroups are mandatory and non-repeatable. Empty fields in the nginx
# logs are indicated by a single dash (-) and parsed as-is.
LINE_FORMAT_WITH_USERNAME = re.compile(
    r"""(?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (?P<remote_user>.+) \[(?P<datetime>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] ((\"(?P<method>.+) )(?P<url>.+)(http\/[1-2]\.[0-9]")) (?P<status_code>\d{3}) (?P<bytes_sent>\d+) (["](?P<referrer>(\-)|(.+))["]) (["](?P<user_agent>.+)["]) (["](?P<forwarded_for>.+)["]) user=(?P<username>.+)""",
    re.IGNORECASE,
)
LINE_FORMAT_DOCKER_DEFAULT = re.compile(
    r"""(?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (?P<remote_user>.+) \[(?P<datetime>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] ((\"(?P<method>.+) )(?P<url>.+)(http\/[1-2]\.[0-9]")) (?P<status_code>\d{3}) (?P<bytes_sent>\d+) (["](?P<referrer>(\-)|(.+))["]) (["](?P<user_agent>.+)["]) (?:["](?P<forwarded_for>.+)["])""",
    re.IGNORECASE,
)
LINE_FORMAT_NGINX_DEFAULT = re.compile(
    r"""(?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (?P<remote_user>.+) \[(?P<datetime>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] ((\"(?P<method>.+) )(?P<url>.+)(http\/[1-2]\.[0-9]")) (?P<status_code>\d{3}) (?P<bytes_sent>\d+) (["](?P<referrer>(\-)|(.+))["]) (["](?P<user_agent>.+)["])""",
    re.IGNORECASE,
)


PLACEHOLDER_UUID = "<uuid>"
PLACEHOLDER_HTTP_PARAMS = "<http_params>"
PLACEHOLDER_PROCESSING_CONFIG = "<processing_config>"
PLACEHOLDER_USER_PK = "<user_pk>"

URLS_TO_IGNORE = [
    # Polling endpoints.
    "/status/",
    "/transfer/status/",
    "/ingest/status/",
    # DataTable column state management.
    "/archival-storage/load_state/",
    "/archival-storage/save_state/",
    "/backlog/load_state/",
    "/backlog/save_state/",
    # Web assets.
    "/media/",
    "/static/",
    "/jsi18n/",
    "/favicon.ico",
    # Gearman tasks.
    "/tasks/",
    # Calls issued while user browses transfer browser. Since users
    # cannot access the content from here, we can safely ignore.
    "/filesystem/children/location",
    # API calls used internally by Archivematica.
    "/api/ingest/copy_metadata_files",
    "/api/administration/dips/atom/levels",
    "/api/administration/dips/atom/fetch_levels",
    "/api/v2beta/jobs",
    "/api/v2beta/task",
    "/api/filesystem/metadata",
    "/api/processing-configuration",
    "/api/v2beta/validate",
    # The AJAX call issued to populate the Packages tab datatable
    # can be ignored because the associated user activity (viewing
    # package information) is already covered.
    "/packages_ajax",
]


class DateParseError(Exception):
    pass


class LogParseError(Exception):
    pass


def parse_access_log_line(line: str, ss_base_url: str = DEFAULT_SS_BASE_URL):
    """Parse log line into formatted dictionary.

    If URL is in URLS_TO_IGNORE, return empty dictionary instead.

    :param line: Log line (str)
    :param ss_base_url: Base URL for Storage Service, as present in
        nginx access log "referrer" field (str)

    :returns: Parsed, formatted, and augmented log line (dict)
    :raises LogParseError: if log line is in unexpected format

    """
    data = re.search(LINE_FORMAT_WITH_USERNAME, line)

    # If parsing with username didn't work, try parsing with the
    # default Archivematica Docker format, then the default nginx
    # access log format, prior to throwing a LogParseError.
    if not data:
        data = re.search(LINE_FORMAT_DOCKER_DEFAULT, line)
    if not data:
        data = re.search(LINE_FORMAT_NGINX_DEFAULT, line)

    if not data:
        error_msg = f"Unable to parse log line in unexpected format: {line}"
        raise LogParseError(error_msg)

    parsed_line = data.groupdict()
    formatted_line = _format_access_log_data(parsed_line)

    discard_line = _discard_log_line(formatted_line, ss_base_url)
    if discard_line:
        return {}

    augmented_line = _save_uuid(formatted_line)
    augmented_line = _add_product_name(augmented_line, ss_base_url)
    augmented_line = _add_event_info(augmented_line)

    return augmented_line


def _save_uuid(augmented_line):
    """Add UUID that will be replaced by placeholder to dict.

    :param augmented_line: Augmented log line (dict)

    :returns: Augmented log line (dict)
    """
    match = re.search(UUID_REGEX, augmented_line.get("url"))
    if match:
        augmented_line["replaced_uuid"] = match.group(0)
    return augmented_line


def _add_product_name(augmented_line, ss_base_url):
    """Add product name to parsed_line dictionary.

    :param augmented_line: Augmented log line (dict)
    :param ss_base_url: Base URL for Storage Service, as present in
        nginx access log "referrer" field (str)

    :returns: Augmented log line (dict)
    """
    referrer = augmented_line.get("referrer")

    system_source = ARCHIVEMATICA_NAME
    if ss_base_url and referrer:
        if referrer.startswith(ss_base_url):
            system_source = STORAGE_SERVICE_NAME
    augmented_line["product"] = system_source

    return augmented_line


def _add_event_info(augmented_line):
    """Add event information to parsed_line dictionary.

    :param augmented_line: Augmented log line (dict)

    :returns: Augmented log line (dict)
    """
    http_method = augmented_line.get("method")
    status_code = augmented_line.get("status_code")
    url = augmented_line.get("url")

    event_info = {}

    # Prepare URL for comparison against event mapping.
    url = _normalize_url_for_comparison(url)
    url = _ensure_url_trailing_slash(url)

    event_mapping = events.get_am_event_mapping()
    if augmented_line["product"] == STORAGE_SERVICE_NAME:
        event_mapping = events.get_ss_event_mapping()

    if status_code not in (
        events.HTTP_STATUS_UNAUTHORIZED,
        events.HTTP_STATUS_NOT_FOUND,
    ):
        url_dict = event_mapping.get(url)
        if url_dict is not None:
            status_code_dict = url_dict.get(status_code)
            if status_code_dict is not None:
                event_info = status_code_dict.get(http_method)

    if status_code == events.HTTP_STATUS_UNAUTHORIZED:
        event_info = events.DEFAULT_EVENT_401

    if status_code == events.HTTP_STATUS_NOT_FOUND:
        event_info = events.DEFAULT_EVENT_404

    if not event_info:
        event_info = events.DEFAULT_EVENT

    augmented_line.update(event_info)

    return augmented_line


def _format_access_log_data(parsed_line):
    """Format data from access log for use in CEF events.

    :param parsed_line: Parsed log line info (dict)

    :returns: Formatted log line (dict)
    """
    formatted_line = _strip_whitespace_from_url(parsed_line)
    formatted_line = _format_datetime_string(formatted_line)
    formatted_line = _format_none_values(formatted_line)
    formatted_line = _ensure_username_key(formatted_line)
    return formatted_line


def _discard_log_line(formatted_line, ss_base_url: str) -> bool:
    """Determine whether to discard log line.

    Log lines are discarded if any of the following are true:
    - There is no URL
    - The URL is from the GUI and there is no referrer
    - URL begins with value in URLS_TO_IGNORE
    - URL begins with /login/ and is not from Storage Service

    :param formatted_line: Formatted log line (dict)
    :param ss_base_url: Base URL for Storage Service (str)

    :returns: Flag indicating whether to discard line (bool)
    """
    url = formatted_line.get("url")
    referrer = formatted_line.get("referrer")
    if url is None:
        return True
    if referrer is None and not url.startswith("/api/"):
        return True
    for url_to_ignore in URLS_TO_IGNORE:
        if url.startswith(url_to_ignore):
            return True
    if url.startswith("/login/") and not referrer.startswith(ss_base_url):
        return True
    return False


def _strip_whitespace_from_url(parsed_line):
    """Strip whitespace from URL.

    :param parsed_line: Parsed log line info (dict)

    :returns: Formatted log line (dict)
    """
    parsed_line["url"] = parsed_line.get("url").strip()
    return parsed_line


def _format_datetime_string(formatted_line):
    """Convert nginx access log datetime string to CEF format.

    :param formatted_line: Formatted log line (dict)

    :returns: Formatted log line (dict)
    :raises DateParseError: if datetime string is in unexpected format
    """
    nginx_datetime_str = formatted_line.get("datetime")
    try:
        datetime_obj = datetime.strptime(nginx_datetime_str, ACCESS_LOG_DATE_FORMAT)
        formatted_line["datetime"] = datetime.strftime(datetime_obj, CEF_DATE_FORMAT)
    except ValueError:
        error_msg = f"Error parsing date from nginx access log. Date string {nginx_datetime_str} doesn't match expected format."
        raise DateParseError(error_msg)
    return formatted_line


def _format_none_values(formatted_line):
    """Replace '-' values with None.

    :param formatted_line: Formatted log line (dict)

    :returns: Formatted log line (dict)
    """
    for key, value in formatted_line.items():
        if value == "-":
            formatted_line[key] = None
    return formatted_line


def _ensure_username_key(formatted_line):
    """Ensure parsed_line has a username key.

    :param formatted_line: Formatted log line (dict)

    :returns: Formatted log line (dict)
    """
    username = formatted_line.get("username")
    if username is None:
        formatted_line["username"] = None
    return formatted_line


def _normalize_url_for_comparison(url: str) -> str:
    """Normalize URL for comparison against event mappings.

    Here we replace variable data with placeholders to facilitate
    matching between actual URLs in the nginx access logs and the
    normalized URLs in the event mappings.

    Placeholders implemented:
    - <uuid> : replaces UUID4 string
    - <http_params> : replaces arbitrary HTTP parameter string
        starting with "?"
    - <processing_config> : replaces processing configuration name
    - <user_pk> : replaces user primary key

    :param url: URL string

    :returns: Modified URL string
    """
    HTTP_PARAM_REGEX = r"\?.*"
    PROCESSING_CONFIG_URLS = [
        "/administration/processing/edit/",
        "/administration/processing/delete/",
        "/administration/processing/download/",
    ]
    AM_ACCOUNT_BASE_URL = "/administration/accounts/"
    AM_ACCOUNT_SUFFIXES = ["edit", "delete"]
    SS_ACCOUNT_BASE_URL = "/administration/users/"

    if url:
        url = re.sub(UUID_REGEX, PLACEHOLDER_UUID, url)
        url = re.sub(HTTP_PARAM_REGEX, PLACEHOLDER_HTTP_PARAMS, url)

        for config_url in PROCESSING_CONFIG_URLS:
            if url.startswith(config_url):
                url = f"{config_url}{PLACEHOLDER_PROCESSING_CONFIG}/"

        if url.startswith(AM_ACCOUNT_BASE_URL):
            for suffix in AM_ACCOUNT_SUFFIXES:
                if suffix in url:
                    url = f"{AM_ACCOUNT_BASE_URL}{PLACEHOLDER_USER_PK}/{suffix}/"

        if url.startswith(SS_ACCOUNT_BASE_URL):
            if "edit" in url:
                url = f"{SS_ACCOUNT_BASE_URL}{PLACEHOLDER_USER_PK}/edit/"
    return url


def _ensure_url_trailing_slash(url: str) -> str:
    """Ensure URL terminates in a trailing slash.

    URLs in the event mappings terminate with a forward slash (/). URLs
    Archivematica nginx access log lines may or may not terminate in a
    slash. To aid in comparison between actual URLs and the event
    mappings, ensure URL terminates in a slash prior to comparison
    against the event mapping.

    :param url: URL string

    :returns: Modified URL string
    """
    return os.path.join(url, "")
