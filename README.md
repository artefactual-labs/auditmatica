# auditmatica

Audit Archivematica user activities via nginx access logs.

## Install

Requires Python 3.6+

```
git clone https://github.com/artefactual-labs/auditmatica
cd auditmatica/
pip install .
```

For development, it may be useful to install `auditmatica` with `pip install -e .`, which will apply changes made to the source code immediately.

## Setup

To ensure that the authenticated user for requests is logged in the nginx access logs and the resulting CEF event logs, first:

- Enable auditing middleware in Archivematica and the Archivematica Storage Service.
- Configure nginx to use the following `log_format` (in the `nginx.conf` http block):
```
log_format main '$remote_addr - $remote_user [$time_local] "$request" '
	'$status $body_bytes_sent "$http_referer" '
	'"$http_user_agent" "$http_x_forwarded_for" '
	'user=$upstream_http_x_username';
```

Optionally (but it's probably a good idea), add `proxy_hide_header x-username;` to the nginx server blocks to prevent the authenticated username from being sent back to the client device.

If the above is configured correctly, the resulting nginx access log lines should look like:
```
172.19.0.1 - - [13/Jan/2021:19:53:10 +0000] "GET /backlog/download/2e28b8a9-351c-4da7-92d2-837ac04cd2d9/ HTTP/1.1" 200 19436360 "http://127.0.0.1:62080/backlog/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0" "-" user=test
```

When `user=$upstream_http_x_username` is not present in the nginx access log, `auditmatica` will attempt to parse the line again, using the [more standard Archivematica `log_format` configuration](https://github.com/artefactual/archivematica/blob/69be7f0581b2a2f31ca5d2d84ca45fb9330ed2b2/hack/etc/nginx/nginx.conf#L18-L20). The resulting audit logs and overviews will not include usernames when they are not present in the nginx access logs according to the format specified above.

## Usage

`auditmatica` has two subcommands, `write-cef` and `overview`:

```
Usage: auditmatica [OPTIONS] COMMAND [ARGS]...

  Auditmatica: Archivematica auditing package

Options:
  --help  Show this message and exit.

Commands:
  overview   Print overview of user activities from nginx access log.
  write-cef  Write Common Event Format (CEF) log from nginx access logs.

```

### `write-cef`

To create an audit log in the Common Event Format (CEF), use the `write-cef` subcommand:

`auditmatica write-cef /path/to/nginx/access.log`

This command accepts several optional arguments:

```
Usage: auditmatica write-cef [OPTIONS] LOG

  Write Common Event Format (CEF) log from nginx access logs.

Options:
  -c, --cef-file PATH     Filepath for output CEF file
                          (default='archivematica_cef.log')

  -s, --syslog            Write CEF events to syslog instead of file
  --syslog-address TEXT   Address for syslog connection (default='/dev/log')
  --syslog-facility TEXT  Facility for syslog messages (default='USER')
  --syslog-port INTEGER   Port for remote syslog connections
  --ss-base-url TEXT      Base URL for Archivematica Storage Service
                          (default='http://127.0.0.1:62081')

  --suppress              Suppress log lines that do not map to a specific
                          event instead of reverting to default event

  -v, --verbose           Enable verbose error message reporting
  --help                  Show this message and exit.

```

A sample CEF event written by `auditmatica` looks like:

```
CEF:0|Artefactual Systems, Inc.|Archivematica|hosted|16|AIP downloaded from Archival Storage|3|cs1Label=requestClientApplication cs1="Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0" rt=Jan 13 2021 20:01:33 requestMethod=GET request=/archival-storage/download/aip/8fa54cfc-f5c5-4673-b44e-fc514496bad7/ src=172.19.0.1 suser=test msg=UUID:8fa54cfc-f5c5-4673-b44e-fc514496bad7
```

#### Storage Service

For machines that have both Archivematica and the Storage Service on a shared machine in front of a single nginx reverse proxy, the value specified by `--ss-base-url` is used to distinguish Storage Service log lines from those originating from the Archivematica dashboard. To use this option, pass the base URL of your Storage Service. This may include the port number, e.g. `auditmatica --ss-base-url http://archivematica.example.com:8000`.

If you're not sure which value to use for `--ss-base-url`, inspect nginx access log lines that result from Storage Service activity. In the following nginx access log line:

```
172.19.0.1 - - [13/Jan/2021:19:57:52 +0000] "GET /spaces/246b8bc2-46db-4db9-b64b-450834c82208/edit/ HTTP/1.1" 200 4206 "http://127.0.0.1:62081/spaces/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0" "-" user=test2
```

`"http://127.0.0.1:62081/spaces/"` is the referrer field. Take the base url was written in the referrer and pass it to auditmatica: `auditmatica write-cef --ss-base-url http://127.0.0.1:62081`. Log lines with a matching `referrer` will be matched against the Storage Service event mapping.

#### Output

By default, `auditmatica` writes CEF events to a log file. To write to syslog instead, use the `-s/--syslog` option. The `--syslog-address`, `--syslog-port`, and `--syslog-facility` options can be used to customize the syslog connection.

For example:
```
auditmatica write-cef -s --syslog --syslog-address localhost --syslog-port 514 --syslog-facility LOCAL0
```

Valid --syslog-facility values include:

```
"KERN"
"USER"
"MAIL"
"DAEMON"
"AUTH"
"LPR"
"NEWS"
"UUCP"
"CRON"
"LOCAL0"
"LOCAL1"
"LOCAL2"
"LOCAL3"
"LOCAL4"
"LOCAL5"
"LOCAL6"
"LOCAL7"
```

### `overview`

To print a very basic high-level overview of Archivematica user activities to the terminal, use the `overview` subcommand:

`auditmatica overview /path/to/nginx/access.log`

Like `write-cef`, `auditmatica overview` accepts the `--ss-base-url` option, which can be used to distinguish events from Archivematica and the Storage Service when both applications are running behind the same nginx reverse proxy. For more detail, see the Storage Service section above.

```
Usage: auditmatica overview [OPTIONS] LOG

  Print overview of user activities from nginx access log.

Options:
  --ss-base-url TEXT  Base URL for Archivematica Storage Service
                      (default='http://127.0.0.1:62081')

  --help              Show this message and exit.
```


## Test

- Install requirements: `pip install -r requirements-test.txt`
- Run tests: `pytest`

## Implemented CEF events

```
### Format

<Event Signature>: <Event name> (severity: <Event severity>)

- Event signature: Unique ID for event
- Event name: Name for event
- Event severity: Integer representing severity of event on a scale of 0-10 (0-3=Low, 4-6=Medium, 7- 8=High, 9-10=Very-High)

### Default event

1: Unspecified user activity (severity: 1)

### Generic events

2: Attempt to navigate to page not found (severity: 2)
3: Attempt to access unauthorized or forbidden page (severity: 5)

### Archivematica events

4: Successful authentication (severity: 1)
5: Unauthenticated user directed to login form (severity: 1)
6: Successful logout (severity: 1)
7: New transfer started (severity: 1)
8: Processing decision made (severity: 1)
9: Transfer downloaded from backlog (severity: 3)
10: File previewed from backlog (severity: 3)
11: File downloaded from backlog (severity: 3)
12: Backlog search performed (severity: 1)
13: Archival Storage search performed (severity: 1),
14: File thumbnail retrieved from Archival Storage (severity: 2)
15: AIP detail page visited (severity: 1)
16: AIP downloaded from Archival Storage (severity: 3)
17: AIP METS file downloaded from Archival Storage (severity: 3)
18: AIP pointer file downloaded from Archival Storage (severity: 3)
19: AIP reingest or deletion request initiated (severity: 2)
20: Metadata-only DIP upload initiated (severity: 2)
21: AIP previewed prior to storage (severity: 3)
22: DIP previewed prior to storage (severity: 3)
23: FPR rule created (severity: 2)
24: FPR rule edited (severity: 2)
25: FPR rule enabled or disabled (severity: 2)
26: FPR command created (severity: 2)
27: FPR command edited (severity: 2)
28: FPR command enabled or disabled (severity: 2)
29: Processing configuration created (severity: 2)
30: Processing configuration edited (severity: 2)
31: Processing configuration deleted (severity: 2)
32: Processing configuration downloaded (severity: 2)
33: General Archivematica configuration edited (severity: 2)
34: AtoM DIP upload configuration edited (severity: 2)
35: ArchivesSpace DIP upload configuration edited (severity: 2)
36: PREMIS Agent edited (severity: 2)
37: API allowlist edited (severity: 2)
38: New user successfully created (severity: 2)
39: Unsuccessful attempt to create new user (severity: 2)
40: User edited (severity: 2)
41: User deleted (severity: 2)
42: Handle server configuration edited (severity: 2)
43: User interface language changed (severity: 1)
44: Unapproved transfers fetched from API (severity: 1)
45: Transfer approved via API (severity: 1)
46: Transfer status fetched from API (severity: 1)
47: Transfer hidden in dashboard via API (severity: 1)
48: Completed transfer UUIDs fetched from API (severity: 1)
49: Transfer reingested via API (severity: 1)
50: Ingest status fetched from API (severity: 1)
51: Ingest hidden in dashboard via API (severity: 1)
52: SIPs awaiting user input fetched from API (severity: 1)
53: Completed SIP UUIDs fetched from API (severity: 1)
54: SIP reingested via API (severity: 1)
55: SIP created from files in backlog (severity: 2)

### Storage Service events

100: Successful authentication (severity: 1)
101: Unauthenticated user redirected to login form (severity: 2)
102: Successful logout (severity: 1)
103: Package information viewed (severity: 2)
104: Package downloaded (severity: 3)
105: Pointer file downloaded (severity: 3)
106: Package deletion requested (severity: 3)
107: Package deletion requests viewed (severity: 2)
108: Decision made on package deletion request (severity: 2)
109: New user successfully created (severity: 2)
110: Unsuccessful attempt to create new user (severity: 2)
111: User edited (severity: 2)
112: File downloaded from stored package (severity: 3)
113: Metadata about files within package fetched from API (severity: 2)
114: Metadata about files within package added via API (severity: 1)
115: Metadata about files within package deleted via API (severity: 2)
116: Package reingest successfully initiated via API (severity: 2)
117: Package moved to new location via API (severity: 2)
```

Not all Archivematica and Archivematica Storage Service requests/responses have been mapped to specific events. When a specific event does not exist for a given combination of URL, HTTP method, and status code, the default CEF event is used. The `--suppress-unspecified` option can be used to suppress log lines that do not match a specific event instead of using the default event.

## Wishlist

* Continue adding to Archivematica and Storage Service event mappings.
* Inspect the body of POST requests to further disambiguate between events that have the same URL and status code (e.g. requesting AIP deletion vs. initiating an AIP reingest in the Archival Storage tab).
* Be able to pick up writing an nginx access log from the place where the last run of `auditmatica` left off. This would require keeping some sort of state of lines already processed, e.g. a hash of each processed line.
* Add support for gzipped log files.
* Increase unit test coverage.
