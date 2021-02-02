import hashlib
import json
import os

from click.testing import CliRunner

from cli.cli import auditmatica as click_main_fn

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
FIXTURES_PATH = os.path.join(SCRIPT_DIR, "fixtures")

ACCESS_LOG = os.path.join(FIXTURES_PATH, "integration_test_nginx_access.log")
BROKEN_ACCESS_LOG = os.path.join(FIXTURES_PATH, "sample_broken_access_log.log")
CEF_LOG = os.path.join(FIXTURES_PATH, "integration_test_cef.log")


def file_sha256_hash(filepath):
    """Return SHA256 hash for contents of file."""
    with open(filepath, "rb") as f:
        expected_bytes = f.read()
        return hashlib.sha256(expected_bytes).hexdigest()


def string_sha256_hash(string):
    """Return SHA256 hash for string."""
    return hashlib.sha256(string).hexdigest()


def test_cef_integration_write_cef_to_stdout():
    """Test integration writing CEF events to stdout."""
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(click_main_fn, ["write-cef", ACCESS_LOG])
    assert result.exit_code == 0
    assert string_sha256_hash(result.output.encode("utf-8")) == file_sha256_hash(
        CEF_LOG
    )


def test_cef_integration_write_cef_to_file():
    """Test integration writing CEF events to file with --output."""
    TEST_OUTPUT = "test.log"
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            click_main_fn, ["write-cef", "--output", TEST_OUTPUT, ACCESS_LOG]
        )
        assert result.exit_code == 0
        assert file_sha256_hash(TEST_OUTPUT) == file_sha256_hash(CEF_LOG)


def test_cef_integration_write_cef_to_syslog():
    """Test integration writing CEF events to syslog."""
    ONE_LINE_ACCESS_LOG = os.path.join(
        FIXTURES_PATH, "one_line_access_log_with_user.log"
    )
    SYSLOG = "/var/log/syslog"
    CEF_TEST_STRING = "CEF:0|Artefactual Systems, Inc.|Archivematica|hosted|9|Transfer downloaded from backlog|3"
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            click_main_fn, ["write-cef", "--syslog", ONE_LINE_ACCESS_LOG]
        )
        assert result.exit_code == 0
        assert os.path.exists(SYSLOG)
        with open(SYSLOG) as log_file:
            log_contents = log_file.readlines()
            last_line = log_contents[-1:]
        assert CEF_TEST_STRING in str(last_line)


def test_cef_integration_write_cef_errors():
    """Test integration writing CEF events with errors."""
    runner = CliRunner(mix_stderr=False)
    with runner.isolated_filesystem():
        result = runner.invoke(click_main_fn, ["write-cef", BROKEN_ACCESS_LOG])
        assert result.exit_code == 0
        assert "Errors: 4" in result.stderr


def test_cef_integration_overview():
    """Test integration writing JSON output."""
    EXPECTED_OUTPUT = """{
  "Archivematica events": [
    {
      "count": 2,
      "event_name": "File previewed from backlog",
      "users": [
        "test3",
        "test4"
      ]
    },
    {
      "count": 1,
      "event_name": "AIP downloaded from Archival Storage",
      "users": [
        "test"
      ]
    }
  ],
  "Storage Service events": [
    {
      "count": 1,
      "event_name": "Package information viewed",
      "users": [
        "test2"
      ]
    }
  ]
}"""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(click_main_fn, ["overview", ACCESS_LOG])
        assert result.exit_code == 0
        assert result.output.strip() == EXPECTED_OUTPUT.strip()


def test_cef_integration_overview_errors():
    """Test integration writing JSON output with errors."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(click_main_fn, ["overview", BROKEN_ACCESS_LOG])
        assert result.exit_code == 0
        dict_output = json.loads(result.output)
        assert dict_output["Errors"]["count"] == 4
