"""CEF functions and constants."""
from datetime import datetime

from auditmatica.access_log import ARCHIVEMATICA_NAME

CEF_FORMAT = (
    "CEF:%(cef_version)s|%(vendor)s|%(product)s|"
    "%(device_version)s|%(signature)s|%(name)s|%(severity)s|"
    "cs1Label=requestClientApplication cs1=%(user_agent)s "
    "rt=%(date)s requestMethod=%(method)s request=%(url)s "
    "src=%(source)s"
)
CEF_OPTIONAL_EXTENSIONS = ["suser", "msg"]
CEF_DATE_FORMAT = "%b %d %Y %H:%M:%S"

DEFAULT_UNSPECIFIED = "Unspecified"


def write_cef_event(parsed_line) -> str:
    """Return CEF event from parsed and formatted log line info.

    :param parsed_line: Parsed and formatted log line dictionary
        produced by auditmatica.audit_log.parse_access_log_line().
        Key-value pairs used for writing CEF events include:
        "ip_address": <request ip address> (str)
        "datetime": <datetime string formatted "MMM DD YYYY HH:MM:SS"> (str)
        "method": <http method> (str)
        "url": <url> (str)
        "status_code": <status code> (str)
        "user_agent": <user agent> (str)
        "event_name": <event name> (str)
        "event_severity": <event severity> (int, 0-10)
        "event_signature": <event signature> (int)
        "product": <name of software being audited> (str)
        "replaced_uuid": <optional uuid4 stripped from URL> (str)
        "username": <optional username> (str)

    :returns: CEF message string
    """
    # Prepare header field data.
    cef_version = "0"
    vendor = "Artefactual Systems, Inc."
    product = escape_str(parsed_line.get("product", ARCHIVEMATICA_NAME))
    device_version = escape_str(parsed_line.get("device_version", "hosted"))
    event_signature = parsed_line.get("event_signature", 1)
    event_name = escape_str(parsed_line.get("event_name", DEFAULT_UNSPECIFIED))
    event_severity = parsed_line.get("event_severity", 1)

    # Prepare extension fields data.
    user_agent = escape_str(
        parsed_line.get("user_agent", DEFAULT_UNSPECIFIED), extension=True
    )
    date = escape_str(
        parsed_line.get("datetime", datetime.now().strftime(CEF_DATE_FORMAT)),
        extension=True,
    )
    http_method = escape_str(
        parsed_line.get("method", DEFAULT_UNSPECIFIED), extension=True
    )
    url = escape_str(parsed_line.get("url", DEFAULT_UNSPECIFIED), extension=True)
    ip_address = escape_str(
        parsed_line.get("ip_address", DEFAULT_UNSPECIFIED), extension=True
    )
    username = escape_str(parsed_line.get("username"), extension=True)

    # Write base CEF message.
    cef_message = CEF_FORMAT % {
        "cef_version": cef_version,
        "vendor": vendor,
        "product": product,
        "device_version": device_version,
        "signature": event_signature,
        "name": event_name,
        "severity": event_severity,
        "user_agent": user_agent,
        "date": date,
        "method": http_method,
        "url": url,
        "source": ip_address,
    }

    # Format and add optional extensions to CEF message.
    msg = None
    replaced_uuid = parsed_line.get("replaced_uuid")
    if replaced_uuid:
        msg = f"UUID:{replaced_uuid}"
    extensions = _format_cef_extensions({"suser": username, "msg": msg})
    return f"{cef_message}{extensions}"


def escape_str(unescaped_str: str, extension: bool = False) -> str:
    """Escape characters in string per CEF specification.

    :param unescaped_str: Un-escaped string (str)
    :param extension: Flag indicating whether input string belongs to
        an extension field (bool)

    :returns: String escaped per CEF specification (str)
    """
    BACKSLASH = "\\"
    NEW_LINE_CHARS = ["\\n", "\\r"]
    PIPE = "|"
    EQUALS_SIGN = "="

    output = unescaped_str

    if output is None:
        return output

    if BACKSLASH in output:
        output = output.replace(BACKSLASH, f"{BACKSLASH}{BACKSLASH}")

    for new_line_char in NEW_LINE_CHARS:
        # Add backslash to account for backslash escaping above.
        escaped_new_line_char = f"{BACKSLASH}{new_line_char}"
        if escaped_new_line_char in output:
            if extension:
                # Revert backslash escaping for new line characters.
                output = output.replace(escaped_new_line_char, new_line_char)
            else:
                # Remove new line character.
                output = output.replace(escaped_new_line_char, "")

    if PIPE in output and not extension:
        output = output.replace(PIPE, f"{BACKSLASH}{PIPE}")

    if EQUALS_SIGN in output and extension:
        output = output.replace(EQUALS_SIGN, f"{BACKSLASH}{EQUALS_SIGN}")

    return output


def _format_cef_extensions(extensions) -> str:
    """Format CEF extensions.

    :param extensions: Dictionary with optional extension metadata:
        suser: Name of authenticated user (str)
        msg: Optional message (str)

    :returns: Extensions string in format "|msg=something" or
        "|suser=test msg=something" (str)
    """
    extension_string = ""
    for extension in CEF_OPTIONAL_EXTENSIONS:
        value = extensions.get(extension)
        if value is not None:
            extension_string += f" {extension}={value}"
    return extension_string
