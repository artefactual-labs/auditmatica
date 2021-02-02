import pytest

from auditmatica.cef import escape_str, write_cef_event

TEST_SUSER_STRING = "test user 1"
TEST_MSG_STRING = "e53e9edd-4ffd-42c5-9bfc-541936f4be6d"

TEST_EXTENSION_SUSER = f" suser={TEST_SUSER_STRING}"
TEST_EXTENSION_MSG = f" msg=UUID:{TEST_MSG_STRING}"
TEST_EXTENSION = TEST_EXTENSION_SUSER + TEST_EXTENSION_MSG

EXPECTED_OUTPUT_BASE = "CEF:0|Artefactual Systems, Inc.|test product|hosted|2|Test name|1|cs1Label=requestClientApplication cs1=test user agent rt=Dec 01 2020 12:01:52 requestMethod=GET request=/test/url src=127.0.0.1"

EXPECTED_OUTPUT_ALL_EXTENSIONS = EXPECTED_OUTPUT_BASE + TEST_EXTENSION
EXPECTED_OUTPUT_SUSER_EXTENSION = EXPECTED_OUTPUT_BASE + TEST_EXTENSION_SUSER
EXPECTED_OUTPUT_MSG_EXTENSION = EXPECTED_OUTPUT_BASE + TEST_EXTENSION_MSG


@pytest.mark.parametrize(
    "parsed_log_line, expected_output",
    [
        # All required fields with no optional fields should produce
        # expected output.
        (
            {
                "datetime": "Dec 01 2020 12:01:52",
                "host": "host",
                "cef_version": 0,
                "product": "test product",
                "event_signature": 2,
                "event_name": "Test name",
                "event_severity": 1,
                "user_agent": "test user agent",
                "method": "GET",
                "url": "/test/url",
                "ip_address": "127.0.0.1",
            },
            EXPECTED_OUTPUT_BASE,
        ),
        # Both optional extension fields should be added correctly.
        (
            {
                "datetime": "Dec 01 2020 12:01:52",
                "host": "host",
                "cef_version": 0,
                "product": "test product",
                "event_signature": 2,
                "event_name": "Test name",
                "event_severity": 1,
                "user_agent": "test user agent",
                "method": "GET",
                "url": "/test/url",
                "ip_address": "127.0.0.1",
                "username": TEST_SUSER_STRING,
                "replaced_uuid": TEST_MSG_STRING,
            },
            EXPECTED_OUTPUT_ALL_EXTENSIONS,
        ),
        # One valid optional extension field should be added correctly.
        (
            {
                "datetime": "Dec 01 2020 12:01:52",
                "host": "host",
                "cef_version": 0,
                "product": "test product",
                "event_signature": 2,
                "event_name": "Test name",
                "event_severity": 1,
                "user_agent": "test user agent",
                "method": "GET",
                "url": "/test/url",
                "ip_address": "127.0.0.1",
                "username": TEST_SUSER_STRING,
            },
            EXPECTED_OUTPUT_SUSER_EXTENSION,
        ),
        # An invalid optional extension field should be ignored.
        (
            {
                "datetime": "Dec 01 2020 12:01:52",
                "host": "host",
                "cef_version": 0,
                "product": "test product",
                "event_signature": 2,
                "event_name": "Test name",
                "event_severity": 1,
                "user_agent": "test user agent",
                "method": "GET",
                "url": "/test/url",
                "ip_address": "127.0.0.1",
                "invalid": "will be ignored",
            },
            EXPECTED_OUTPUT_BASE,
        ),
        # A valid optional extension should be used while an invalid
        # extension should be ignored if both included.
        (
            {
                "datetime": "Dec 01 2020 12:01:52",
                "host": "host",
                "cef_version": 0,
                "product": "test product",
                "event_signature": 2,
                "event_name": "Test name",
                "event_severity": 1,
                "user_agent": "test user agent",
                "method": "GET",
                "url": "/test/url",
                "ip_address": "127.0.0.1",
                "invalid": "will be ignored",
                "replaced_uuid": TEST_MSG_STRING,
            },
            EXPECTED_OUTPUT_MSG_EXTENSION,
        ),
    ],
)
def test_format_cef_message(parsed_log_line, expected_output):
    """Test CEF message formatting."""
    assert write_cef_event(parsed_log_line) == expected_output


@pytest.mark.parametrize(
    "str_input, extension, expected_output",
    [
        # Test that pipes (|) in header are escaped with a backslash.
        ("ceci n'est pas une |", False, "ceci n'est pas une \\|"),
        # Test that pipes in extension are not escaped.
        ("oui, ceci est une |", True, "oui, ceci est une |"),
        # Test that backslashes (\) in header or extension are escaped
        # with a backslash.
        ("string with \\ a backslash", False, "string with \\\\ a backslash"),
        ("string with \\ a backslash", True, "string with \\\\ a backslash"),
        # Test that equals signs (=) in header are not escaped.
        ("e=mc2", False, "e=mc2"),
        # Test that equals signs in extensions are escaped with a
        # backslash.
        ("e=mc2", True, "e\\=mc2"),
        # Test that newline characters (\n or \r) are not present in
        # header.
        ("I span\\n lines", False, "I span lines"),
        ("I span\\r lines", False, "I span lines"),
        ("I span\\n\\r several\\r lines", False, "I span several lines"),
        # Test that newline characters in extension are not removed.
        ("I span\\n lines", True, "I span\\n lines"),
        ("I span\\r lines", True, "I span\\r lines"),
        ("I span\\n\\r several\\r lines", True, "I span\\n\\r several\\r lines"),
        # Verify tests with raw strings just to be extra sure we didn't
        # accidentally mess up any escaping in the tests.
        (r"raw ceci n'est pas une |", False, r"raw ceci n'est pas une \|"),
        (r"raw string with \ a backslash", False, r"raw string with \\ a backslash"),
        (r"raw string with \ a backslash", True, r"raw string with \\ a backslash"),
        (r"I span\n lines", False, "I span lines"),
        (r"raw I span\n lines", True, r"raw I span\n lines"),
    ],
)
def test_escape_string(str_input, extension, expected_output):
    assert escape_str(str_input, extension) == expected_output
