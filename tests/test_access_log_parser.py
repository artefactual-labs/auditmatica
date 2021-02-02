import os

import pytest

from auditmatica.access_log import (
    ARCHIVEMATICA_NAME,
    DEFAULT_SS_BASE_URL,
    STORAGE_SERVICE_NAME,
    _add_event_info,
    parse_access_log_line,
)
from auditmatica.events import (
    DEFAULT_EVENT,
    DEFAULT_EVENT_401,
    DEFAULT_EVENT_404,
    EVENT_NAME,
    EVENT_SEVERITY,
    EVENT_SIGNATURE,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_GET,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_STATUS_ACCEPTED,
    HTTP_STATUS_CREATED,
    HTTP_STATUS_FOUND,
    HTTP_STATUS_MOVED_PERMANENTLY,
    HTTP_STATUS_NO_CONTENT,
    HTTP_STATUS_NOT_FOUND,
    HTTP_STATUS_OK,
    HTTP_STATUS_UNAUTHORIZED,
)

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
FIXTURES_PATH = os.path.join(SCRIPT_DIR, "fixtures")

TEST_REFERRER_ARCHIVEMATICA = "http://test-archivematica-dashboard"
TEST_REFERRER_STORAGE_SERVICE = "http://test-storage-service"


@pytest.mark.parametrize(
    "fixture_path, expected_return_value",
    [
        # Sample log line with authenticated username should be parsed
        # correctly.
        (
            os.path.join(FIXTURES_PATH, "one_line_access_log_with_user.log"),
            {
                "ip_address": "172.19.0.1",
                "remote_user": None,
                "datetime": "Jan 13 2021 19:53:10",
                "method": "GET",
                "url": "/backlog/download/2e28b8a9-351c-4da7-92d2-837ac04cd2d9/",
                "status_code": "200",
                "bytes_sent": "19436360",
                "referrer": "http://127.0.0.1:62080/backlog/",
                "user_agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0",
                "forwarded_for": None,
                "username": "test",
                "event_name": "Transfer downloaded from backlog",
                "event_severity": 3,
                "event_signature": 9,
                "replaced_uuid": "2e28b8a9-351c-4da7-92d2-837ac04cd2d9",
                "product": ARCHIVEMATICA_NAME,
            },
        ),
        # Sample log line with authenticated username containing
        # diacritics should be parsed correctly.
        (
            os.path.join(FIXTURES_PATH, "one_line_access_log_with_user_diacritics.log"),
            {
                "ip_address": "172.19.0.1",
                "remote_user": None,
                "datetime": "Jan 13 2021 19:53:10",
                "method": "GET",
                "url": "/backlog/download/2e28b8a9-351c-4da7-92d2-837ac04cd2d9/",
                "status_code": "200",
                "bytes_sent": "19436360",
                "referrer": "http://127.0.0.1:62080/backlog/",
                "user_agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0",
                "forwarded_for": None,
                "username": "zoë",
                "event_name": "Transfer downloaded from backlog",
                "event_severity": 3,
                "event_signature": 9,
                "replaced_uuid": "2e28b8a9-351c-4da7-92d2-837ac04cd2d9",
                "product": ARCHIVEMATICA_NAME,
            },
        ),
        # Sample log line without authenticated username should also
        # be parsed correctly, with a username of None.
        (
            os.path.join(FIXTURES_PATH, "one_line_access_log_no_user.log"),
            {
                "ip_address": "172.19.0.1",
                "remote_user": None,
                "datetime": "Jan 13 2021 19:53:10",
                "method": "GET",
                "url": "/backlog/download/2e28b8a9-351c-4da7-92d2-837ac04cd2d9/",
                "status_code": "200",
                "bytes_sent": "19436360",
                "referrer": "http://127.0.0.1:62080/backlog/",
                "user_agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0",
                "forwarded_for": None,
                "username": None,
                "event_name": "Transfer downloaded from backlog",
                "event_severity": 3,
                "event_signature": 9,
                "replaced_uuid": "2e28b8a9-351c-4da7-92d2-837ac04cd2d9",
                "product": ARCHIVEMATICA_NAME,
            },
        ),
        # Sample log line with URL to filter out should return empty
        # dictionary.
        (os.path.join(FIXTURES_PATH, "access_log_with_urls_to_filter.log"), {}),
        # Sample log line with Archivematica /login/ URL should return
        # empty dictionary.
        (os.path.join(FIXTURES_PATH, "one_line_access_log_am_login.log"), {}),
        # Sample log line with Storage Service /login/ URL should be
        # parsed correctly.
        (
            os.path.join(FIXTURES_PATH, "one_line_access_log_ss_login.log"),
            {
                "ip_address": "172.19.0.1",
                "remote_user": None,
                "datetime": "Jan 13 2021 19:49:57",
                "method": "POST",
                "url": "/login/",
                "status_code": "302",
                "bytes_sent": "0",
                "referrer": "http://127.0.0.1:62081/login/",
                "user_agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0",
                "forwarded_for": None,
                "username": "test",
                "event_name": "Successful authentication",
                "event_severity": 1,
                "event_signature": 100,
                "product": STORAGE_SERVICE_NAME,
            },
        ),
        # Sample log line using default nginx access log_format should
        # be parsed correctly.
        (
            os.path.join(FIXTURES_PATH, "one_line_access_log_default_log_format.log"),
            {
                "ip_address": "192.1.45.215",
                "remote_user": None,
                "datetime": "Feb 11 2021 22:59:57",
                "method": "GET",
                "url": "/archival-storage/download/aip/92788701-12ef-4cd3-a12b-71413d9d4d49/mets_download/",
                "status_code": "200",
                "bytes_sent": "187498",
                "referrer": "http://test-server.net/archival-storage/92788701-12ef-4cd3-a12b-71413d9d4d49/",
                "user_agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0",
                "username": None,
                "event_name": "AIP METS file downloaded from Archival Storage",
                "event_severity": 3,
                "event_signature": 17,
                "replaced_uuid": "92788701-12ef-4cd3-a12b-71413d9d4d49",
                "product": ARCHIVEMATICA_NAME,
            },
        ),
        # Sample log line with API request from cURL should be parsed
        # correctly.
        (
            os.path.join(FIXTURES_PATH, "one_line_api_call_curl.log"),
            {
                "ip_address": "172.25.9.2",
                "remote_user": None,
                "datetime": "Feb 15 2021 23:02:35",
                "method": "GET",
                "url": "/api/transfer/completed/",
                "status_code": "200",
                "bytes_sent": "71",
                "referrer": None,
                "user_agent": "curl/7.68.0",
                "username": None,
                "event_name": "Completed transfer UUIDs fetched from API",
                "event_severity": 1,
                "event_signature": 48,
                "forwarded_for": None,
                "product": ARCHIVEMATICA_NAME,
            },
        ),
    ],
)
def test_parse_log_line(fixture_path, expected_return_value):
    with open(fixture_path, "r") as log_file:
        line = log_file.readline()
        return_value = parse_access_log_line(line, DEFAULT_SS_BASE_URL)
        assert return_value == expected_return_value


@pytest.mark.parametrize(
    "parsed_log_line, expected_name, expected_signature, expected_severity",
    [
        # Log lines with 404 status code should return the default 404
        # event information.
        (
            {
                "status_code": HTTP_STATUS_NOT_FOUND,
                "url": "/",
                "product": ARCHIVEMATICA_NAME,
            },
            DEFAULT_EVENT_404[EVENT_NAME],
            DEFAULT_EVENT_404[EVENT_SIGNATURE],
            DEFAULT_EVENT_404[EVENT_SEVERITY],
        ),
        (
            {
                "status_code": HTTP_STATUS_NOT_FOUND,
                "method": HTTP_METHOD_GET,
                "url": "/administration/accounts/login/",
                "product": ARCHIVEMATICA_NAME,
            },
            DEFAULT_EVENT_404[EVENT_NAME],
            DEFAULT_EVENT_404[EVENT_SIGNATURE],
            DEFAULT_EVENT_404[EVENT_SEVERITY],
        ),
        # Log lines with 401 status code should return the default 401
        # event information.
        (
            {
                "status_code": HTTP_STATUS_UNAUTHORIZED,
                "url": "/",
                "product": ARCHIVEMATICA_NAME,
            },
            DEFAULT_EVENT_401[EVENT_NAME],
            DEFAULT_EVENT_401[EVENT_SIGNATURE],
            DEFAULT_EVENT_401[EVENT_SEVERITY],
        ),
        (
            {
                "status_code": HTTP_STATUS_UNAUTHORIZED,
                "method": HTTP_METHOD_GET,
                "url": "/administration/accounts/logout/",
                "product": ARCHIVEMATICA_NAME,
            },
            DEFAULT_EVENT_401[EVENT_NAME],
            DEFAULT_EVENT_401[EVENT_SIGNATURE],
            DEFAULT_EVENT_401[EVENT_SEVERITY],
        ),
        # Log lines that don't match mapping should return the default
        # event information.
        (
            {
                # I'm a teapot, short and stout.
                "status_code": "418",
                "url": "/",
                "product": ARCHIVEMATICA_NAME,
            },
            DEFAULT_EVENT[EVENT_NAME],
            DEFAULT_EVENT[EVENT_SIGNATURE],
            DEFAULT_EVENT[EVENT_SEVERITY],
        ),
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/nonexistent/url",
                "product": ARCHIVEMATICA_NAME,
            },
            DEFAULT_EVENT[EVENT_NAME],
            DEFAULT_EVENT[EVENT_SIGNATURE],
            DEFAULT_EVENT[EVENT_SEVERITY],
        ),
        # Verify lines that match successful authentication.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/administration/accounts/login/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Successful authentication",
            4,
            1,
        ),
        # Verify log lines that match redirection to login form.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/administration/accounts/login/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Unauthenticated user directed to login form",
            5,
            2,
        ),
        # Verify log lines that match successful logout.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_GET,
                "url": "/administration/accounts/logout/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Successful logout",
            6,
            1,
        ),
        # Verify log lines that match successfully starting a transfer.
        (
            {
                "status_code": HTTP_STATUS_ACCEPTED,
                "method": HTTP_METHOD_POST,
                "url": "/api/v2beta/package/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "New transfer started",
            7,
            1,
        ),
        # Verify log lines that match executing a processing choice in
        # the GUI.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_POST,
                "url": "/mcp/execute/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Processing decision made",
            8,
            1,
        ),
        # Verify log lines that match downloading a transfer from the
        # transfer backlog (HTTP STATUS OK).
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/backlog/download/b7ed1bbf-0153-40dd-82c1-46aaa4bd99c9/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Transfer downloaded from backlog",
            9,
            3,
        ),
        # Verify log lines that match downloading a transfer from the
        # transfer backlog (HTTP STATUS MOVED PERMANENTLY).
        (
            {
                "status_code": HTTP_STATUS_MOVED_PERMANENTLY,
                "method": HTTP_METHOD_GET,
                "url": "/backlog/download/b7ed1bbf-0153-40dd-82c1-46aaa4bd99c9/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Transfer downloaded from backlog",
            9,
            3,
        ),
        # Verify log lines that match previewing a file from the
        # transfer backlog.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/filesystem/9aed1bd3-41bd-4ed5-9ef1-9653430c577f/preview/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "File previewed from backlog",
            10,
            3,
        ),
        # Verify log lines that match downloading a file from the
        # transfer backlog.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/filesystem/9aed1bd3-41bd-4ed5-9ef1-9653430c577f/download/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "File downloaded from backlog",
            11,
            3,
        ),
        # Verify log lines that match searching the transfer backlog.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/backlog/search/?query=&field=&type=term&sEcho=1&iColumns=8&sColumns=%2C%2C%2C%2C%2C%2C%2C&iDisplayStart=0&iDisplayLength=10&mDataProp_0=name&bSortable_0=true&mDataProp_1=uuid&bSortable_1=true&mDataProp_2=size&bSortable_2=true&mDataProp_3=file_count&bSortable_3=true&mDataProp_4=accessionid&bSortable_4=true&mDataProp_5=ingest_date&bSortable_5=true&mDataProp_6=pending_deletion&bSortable_6=true&mDataProp_7=uuid&bSortable_7=false&iSortCol_0=0&sSortDir_0=asc&iSortingCols=1&file_mode=false",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Backlog search performed",
            12,
            1,
        ),
        # Verify log lines that match searching archival storage.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/archival-storage/search/?query=&field=&fieldName=&type=term&sEcho=1&iColumns=11&sColumns=%2C%2C%2C%2C%2C%2C%2C%2C%2C%2C&iDisplayStart=0&iDisplayLength=10&mDataProp_0=name&bSortable_0=true&mDataProp_1=uuid&bSortable_1=true&mDataProp_2=AICID&bSortable_2=true&mDataProp_3=size&bSortable_3=true&mDataProp_4=file_count&bSortable_4=true&mDataProp_5=accessionids&bSortable_5=true&mDataProp_6=created&bSortable_6=true&mDataProp_7=status&bSortable_7=true&mDataProp_8=encrypted&bSortable_8=true&mDataProp_9=location&bSortable_9=true&mDataProp_10=uuid&bSortable_10=false&iSortCol_0=0&sSortDir_0=asc&iSortingCols=1&file_mode=false",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Archival Storage search performed",
            13,
            1,
        ),
        # Verify log lines that match fetching file thumbnail from
        # archival storage.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/archival-storage/thumbnail/bb1fb730-104d-4bd0-88fa-1976dde44c99/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "File thumbnail retrieved from Archival Storage",
            14,
            2,
        ),
        # Verify log lines that match visiting AIP page in archival
        # storage.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/archival-storage/8fa54cfc-f5c5-4673-b44e-fc514496bad7/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "AIP detail page visited",
            15,
            1,
        ),
        # Verify log lines that match downloading AIP from archival
        # storage.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/archival-storage/download/aip/8fa54cfc-f5c5-4673-b44e-fc514496bad7/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "AIP downloaded from Archival Storage",
            16,
            3,
        ),
        # Verify log lines that match downloading AIP METS file from
        # archival storage.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/archival-storage/download/aip/8fa54cfc-f5c5-4673-b44e-fc514496bad7/mets_download/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "AIP METS file downloaded from Archival Storage",
            17,
            3,
        ),
        # Verify log lines that match downloading AIP pointer file from
        # archival storage.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/archival-storage/download/aip/8fa54cfc-f5c5-4673-b44e-fc514496bad7/pointer_file/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "AIP pointer file downloaded from Archival Storage",
            18,
            3,
        ),
        # Verify log lines that match initiating an AIP reingest or
        # deletion request.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/archival-storage/8fa54cfc-f5c5-4673-b44e-fc514496bad7/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "AIP reingest or deletion request initiated",
            19,
            2,
        ),
        # Verify log lines that match metadata-only DIP upload.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_POST,
                "url": "/archival-storage/8fa54cfc-f5c5-4673-b44e-fc514496bad7/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Metadata-only DIP upload initiated",
            20,
            2,
        ),
        # Verify log lines that match previewing an AIP.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/ingest/preview/aip/8fa54cfc-f5c5-4673-b44e-fc514496bad7/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "AIP previewed prior to storage",
            21,
            3,
        ),
        # Verify log lines that match previewing a DIP.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/ingest/preview/dip/8fa54cfc-f5c5-4673-b44e-fc514496bad7/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "DIP previewed prior to storage",
            22,
            3,
        ),
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/fpr/fprule/create/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "FPR rule created",
            23,
            2,
        ),
        # Verify log lines that match editing a FPR rule.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/fpr/fprule/c0ff4558-ddd6-4fd0-b0a1-c25db112b573/edit/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "FPR rule edited",
            24,
            2,
        ),
        # Verify log lines that match enabling or disabling a FPR rule.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/fpr/fprule/c0ff4558-ddd6-4fd0-b0a1-c25db112b573/delete/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "FPR rule enabled or disabled",
            25,
            2,
        ),
        # Verify log lines that match creating a new FPR command.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/fpr/fpcommand/create/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "FPR command created",
            26,
            2,
        ),
        # Verify log lines that match editing a FPR command.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/fpr/fpcommand/98439ed6-9047-44ab-86a8-16ae74d78c95/edit/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "FPR command edited",
            27,
            2,
        ),
        # Verify log lines that match enabling or disabling a FPR
        # command.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/fpr/fpcommand/98439ed6-9047-44ab-86a8-16ae74d78c95/delete/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "FPR command enabled or disabled",
            28,
            2,
        ),
        # Verify log lines that match creating a new processing config.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/administration/processing/add/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Processing configuration created",
            29,
            2,
        ),
        # Verify log lines that match editing a processing config.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_GET,
                "url": "/administration/processing/edit/default/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Processing configuration edited",
            30,
            2,
        ),
        # Verify log lines that match deleting a processing config.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/administration/processing/delete/automated/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Processing configuration deleted",
            31,
            2,
        ),
        # Verify log lines that match downloading a processing config.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/administration/processing/download/customConfig/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Processing configuration downloaded",
            32,
            2,
        ),
        # Verify log lines that match editing general Archivematica
        # configuration.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_POST,
                "url": "/administration/general/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "General Archivematica configuration edited",
            33,
            2,
        ),
        # Verify log lines that match editing AtoM DIP upload
        # configuration.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_POST,
                "url": "/administration/dips/atom/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "AtoM DIP upload configuration edited",
            34,
            2,
        ),
        # Verify log lines that match editing ArchivesSpace DIP upload
        # configuration.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_POST,
                "url": "/administration/dips/as/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "ArchivesSpace DIP upload configuration edited",
            35,
            2,
        ),
        # Verify log lines that match editing PREMIS Agent.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_POST,
                "url": "/administration/premis/agent/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "PREMIS Agent edited",
            36,
            2,
        ),
        # Verify log lines that match editing API allowlist.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_POST,
                "url": "/administration/api/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "API allowlist edited",
            37,
            2,
        ),
        # Verify log lines that match successfully adding new user.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/administration/accounts/add/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "New user successfully created",
            38,
            2,
        ),
        # Verify log lines that match unsuccessful attempt to add new
        # user (e.g. if password fails to validate).
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_POST,
                "url": "/administration/accounts/add/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Unsuccessful attempt to create new user",
            39,
            2,
        ),
        # Verify log lines that match editing a user.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/administration/accounts/1/edit/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "User edited",
            40,
            2,
        ),
        # Verify log lines that match deleting a user.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/administration/accounts/1/delete/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "User deleted",
            41,
            2,
        ),
        # Verify log lines that match editing handle server config.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_POST,
                "url": "/administration/handle/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Handle server configuration edited",
            42,
            2,
        ),
        # Verify log lines that match changing UI language setting.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/administration/i18n/setlang/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "User interface language changed",
            43,
            1,
        ),
        # Verify log lines that match starting a new transfer via the
        # API. Use the existing event for the /api/v2beta/package/
        # endpoint used by the transfer tab.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_POST,
                "url": "/api/transfer/start_transfer/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "New transfer started",
            7,
            1,
        ),
        # Verify log lines that match listing unapproved transfers via
        # the API.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/api/transfer/unapproved/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Unapproved transfers fetched from API",
            44,
            1,
        ),
        # Verify log lines that match approving transfers via the API.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_POST,
                "url": "/api/transfer/approve/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Transfer approved via API",
            45,
            1,
        ),
        # Verify log lines that match fetching transfer status from the
        # API.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/api/transfer/status/e2545b71-d6aa-4838-b995-42e9d640b7b2/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Transfer status fetched from API",
            46,
            1,
        ),
        # Verify log lines that match hiding a transfer via the API.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_DELETE,
                "url": "/api/transfer/e2545b71-d6aa-4838-b995-42e9d640b7b2/delete/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Transfer hidden in dashboard via API",
            47,
            1,
        ),
        # Verify log lines that match fetching completed transfers from
        # the API.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/api/transfer/completed/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Completed transfer UUIDs fetched from API",
            48,
            1,
        ),
        # Verify log lines that match reingesting a transfer via the
        # API.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_POST,
                "url": "/api/transfer/reingest",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Transfer reingested via API",
            49,
            1,
        ),
        # Verify log lines that match fetching ingest status from the
        # API.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/api/ingest/status/5a71ec7f-f70f-412f-98a1-435708b7cf88/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Ingest status fetched from API",
            50,
            1,
        ),
        # Verify log lines that match hiding an ingest via the API.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_DELETE,
                "url": "/api/ingest/5a71ec7f-f70f-412f-98a1-435708b7cf88/delete/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Ingest hidden in dashboard via API",
            51,
            1,
        ),
        # Verify log lines that match fetching SIPs awaiting user input
        # from the API.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/api/ingest/waiting",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "SIPs awaiting user input fetched from API",
            52,
            1,
        ),
        # Verify log lines that match fetching completed ingests from
        # the API.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/api/ingest/completed/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "Completed SIP UUIDs fetched from API",
            53,
            1,
        ),
        # Verify log lines that match reingesting a SIP via the API.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_POST,
                "url": "/api/ingest/reingest",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "SIP reingested via API",
            54,
            1,
        ),
        # Verify log lines that match creating a SIP from files in the
        # backlog.
        (
            {
                "status_code": HTTP_STATUS_CREATED,
                "method": HTTP_METHOD_POST,
                "url": "/filesystem/copy_from_arrange/",
                "referrer": TEST_REFERRER_ARCHIVEMATICA,
                "product": ARCHIVEMATICA_NAME,
            },
            "SIP created from files in backlog",
            55,
            2,
        ),
    ],
)
def test_add_archivematica_event_info(
    parsed_log_line, expected_name, expected_signature, expected_severity
):
    return_value = _add_event_info(parsed_log_line)
    assert return_value[EVENT_NAME] == expected_name
    assert return_value[EVENT_SIGNATURE] == expected_signature
    assert return_value[EVENT_SEVERITY] == expected_severity
    assert return_value["product"] == ARCHIVEMATICA_NAME


@pytest.mark.parametrize(
    "parsed_log_line, expected_name, expected_signature, expected_severity",
    [
        # Log lines that don't match mapping should return the default
        # event information.
        (
            {
                # I'm a teapot, short and stout.
                "status_code": "418",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "url": "/",
                "product": STORAGE_SERVICE_NAME,
            },
            DEFAULT_EVENT[EVENT_NAME],
            DEFAULT_EVENT[EVENT_SIGNATURE],
            DEFAULT_EVENT[EVENT_SEVERITY],
        ),
        (
            {
                "status_code": HTTP_STATUS_OK,
                "referrer": TEST_REFERRER_STORAGE_SERVICE + "/nonexistent/url/",
                "method": HTTP_METHOD_GET,
                "url": "/nonexistent/url/",
                "product": STORAGE_SERVICE_NAME,
            },
            DEFAULT_EVENT[EVENT_NAME],
            DEFAULT_EVENT[EVENT_SIGNATURE],
            DEFAULT_EVENT[EVENT_SEVERITY],
        ),
        # Verify lines that match successful authentication.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/login/",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "Successful authentication",
            100,
            1,
        ),
        # Verify log lines that match redirection to login form.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/login/",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "Unauthenticated user directed to login form",
            101,
            2,
        ),
        # Verify log lines that match successful logout.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_GET,
                "url": "/logout/",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "Successful logout",
            102,
            1,
        ),
        # Verify log lines that match viewing information about
        # Packages.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/packages/",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "Package information viewed",
            103,
            2,
        ),
        # Verify log lines that match downloading a package (GET).
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/api/v2/file/0d95f14f-30ba-4541-af80-a6ecd96d9baf/download/",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "Package downloaded",
            104,
            3,
        ),
        # Verify log lines that match downloading a package (HEAD).
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_HEAD,
                "url": "/api/v2/file/0d95f14f-30ba-4541-af80-a6ecd96d9baf/download/",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "Package downloaded",
            104,
            3,
        ),
        # Verify log lines that match downloading a pointer file.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/api/v2/file/0d95f14f-30ba-4541-af80-a6ecd96d9baf/pointer_file/",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "Pointer file downloaded",
            105,
            3,
        ),
        # Verify log lines that match requesting package deletion.
        (
            {
                "status_code": HTTP_STATUS_ACCEPTED,
                "method": HTTP_METHOD_POST,
                "url": "/api/v2/file/0d95f14f-30ba-4541-af80-a6ecd96d9baf/delete_aip/",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "Package deletion requested",
            106,
            3,
        ),
        # Verify log lines that match viewing package deletion requests.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/packages/package_delete_request/",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "Package deletion requests viewed",
            107,
            2,
        ),
        # Verify log lines that match a decision being made on a
        # package deletion request.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/packages/package_delete_request/",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "Decision made on package deletion request",
            108,
            2,
        ),
        # Verify log lines that match successfully adding new user.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/administration/users/create/",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "New user successfully created",
            109,
            2,
        ),
        # Verify log lines that match unsuccessful attempt to add new
        # user (e.g. if password fails to validate).
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_POST,
                "url": "/administration/users/create/",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "Unsuccessful attempt to create new user",
            110,
            2,
        ),
        # Verify log lines that match editing a user.
        (
            {
                "status_code": HTTP_STATUS_FOUND,
                "method": HTTP_METHOD_POST,
                "url": "/administration/users/3/edit/",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "User edited",
            111,
            2,
        ),
        # Verify log lines that match downloading a single file from a
        # package via the API (GET).
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/api/v2/file/400462d8-673d-4542-b681-b1720da90913/extract_file",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "File downloaded from stored package",
            112,
            3,
        ),
        # Verify log lines that match downloading a single file from a
        # package via the API (HEAD).
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_HEAD,
                "url": "/api/v2/file/400462d8-673d-4542-b681-b1720da90913/extract_file/",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "File downloaded from stored package",
            112,
            3,
        ),
        # Verify log lines that match fetching metadata on files within
        # a package from the API.
        (
            {
                "status_code": HTTP_STATUS_OK,
                "method": HTTP_METHOD_GET,
                "url": "/api/v2/file/400462d8-673d-4542-b681-b1720da90913/contents",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "Metadata about files within package fetched from API",
            113,
            2,
        ),
        # Verify log lines that match adding metadata for files within
        # a package via the API.
        (
            {
                "status_code": HTTP_STATUS_CREATED,
                "method": HTTP_METHOD_PUT,
                "url": "/api/v2/file/400462d8-673d-4542-b681-b1720da90913/contents",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "Metadata about files within package added via API",
            114,
            1,
        ),
        # Verify log lines that match deleting metadata for files
        # within a package via the API.
        (
            {
                "status_code": HTTP_STATUS_NO_CONTENT,
                "method": HTTP_METHOD_DELETE,
                "url": "/api/v2/file/400462d8-673d-4542-b681-b1720da90913/contents",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "Metadata about files within package deleted via API",
            115,
            2,
        ),
        # Verify log lines that match successful initiation of AIP
        # reingest via the API.
        (
            {
                "status_code": HTTP_STATUS_ACCEPTED,
                "method": HTTP_METHOD_POST,
                "url": "/api/v2/file/400462d8-673d-4542-b681-b1720da90913/reingest",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "Package reingest successfully initiated via API",
            116,
            2,
        ),
        # Verify log lines that match moving a package to a new
        # location via the API.
        (
            {
                "status_code": HTTP_STATUS_ACCEPTED,
                "method": HTTP_METHOD_POST,
                "url": "/api/v2/file/400462d8-673d-4542-b681-b1720da90913/move",
                "referrer": TEST_REFERRER_STORAGE_SERVICE,
                "product": STORAGE_SERVICE_NAME,
            },
            "Package moved to new location via API",
            117,
            2,
        ),
    ],
)
def test_add_storage_service_event_info(
    parsed_log_line, expected_name, expected_signature, expected_severity
):
    return_value = _add_event_info(parsed_log_line)
    assert return_value[EVENT_NAME] == expected_name
    assert return_value[EVENT_SIGNATURE] == expected_signature
    assert return_value[EVENT_SEVERITY] == expected_severity
    assert return_value["product"] == STORAGE_SERVICE_NAME
