# auditmatica

## About

Audit [Archivematica][am] user activities via nginx access logs.

## Overview

`auditmatica` is intended to facilitate auditing of user activities in
Archivematica and the Archivematica Storage Service. It uses nginx access logs
as its data source, and outputs either logs in [Common Event Format (CEF)][cef]
or a JSON overview of user activities.

## Usage

`auditmatica` has two subcommands, `write-cef` and `overview`.

```
Usage: auditmatica [OPTIONS] COMMAND [ARGS]...

  Auditmatica: Archivematica auditing package

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.

Commands:
  overview   Print overview of user activities from nginx access log.
  write-cef  Write Common Event Format (CEF) log from nginx access log.

```

### `write-cef`

To write CEF events, use the `write-cef` subcommand. E.g.:

```bash
auditmatica write-cef /path/to/nginx/access.log
```

or

```bash
cat /var/log/nginx/access.log | auditmatica write-cef
```

CEF is a widely used standard for network and security analysis. CEF events
can be sent to applications for review, monitoring, and visualization via a
file or over syslog. CEF events written by `auditmatica` include an event name,
signature (unique identifier), and severity level (0-10), which are determined
based on details from the nginx access log such as URL, HTTP method, and HTTP
return code.

A sample CEF event written by `auditmatica` looks like the following:

```
CEF:0|Artefactual Systems, Inc.|Archivematica|hosted|16|AIP downloaded from Archival Storage|3|cs1Label=requestClientApplication cs1="Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0" rt=Jan 13 2021 20:01:33 requestMethod=GET request=/archival-storage/download/aip/8fa54cfc-f5c5-4673-b44e-fc514496bad7/ src=172.19.0.1 suser=test msg=UUID:8fa54cfc-f5c5-4673-b44e-fc514496bad7
```

For a comprehensive list of Archivematica CEF events, see
[IMPLEMENTATION.md](IMPLEMENTATION.md).

For more details on CEF, see the [CEF specification][cef].

This command accepts several optional arguments:

```
Usage: auditmatica write-cef [OPTIONS] [LOG]

  Write Common Event Format (CEF) log from nginx access log.

Options:
  -o, --output PATH       Filepath for output CEF file (default=None, print to
                          stdout)

  -s, --syslog            Write CEF events to syslog instead of file
  --syslog-address TEXT   Address for syslog connection (default='/dev/log')
  --syslog-facility TEXT  Facility for syslog messages (default='USER')
  --syslog-port INTEGER   Port for remote syslog connections
  --ss-base-url TEXT      Override the Storage Service URL to scan for
                          (default='http://127.0.0.1:62081')

  --suppress              Suppress log lines that do not map to a specific
                          event instead of reverting to default event

  -v, --verbose           Enable verbose error message reporting
  --help                  Show this message and exit.


```

#### Storage Service

`auditmatica` looks for Storage Service events in the nginx access log by
checking each URL to determine if it begins with the expected base URL of the
Storage Service. By default, this is `http://127.0.0.1:62081`.

To override the Storage Service URL to scan for, use `--ss-base-url`. E.g.:

```
auditmatica --ss-base-url http://archivematica.example.com:8000
```

#### Output

By default, `auditmatica` writes CEF events to stdout and some end-user facing
messages to stderr.

To write CEF events to a file, use the `-o/--output` option to specify a
filepath for the output file. E.g.:

```
auditmatica write-cef /path/to/nginx/access.log --output my-output-file.log
```

To write CEF events to [syslog][syslog], use the `-s/--syslog` option. By
default, this will write syslog messages to `/dev/log/` using the `USER`
facility. The `--syslog-address`, `--syslog-port`, and `--syslog-facility`
options can be used to customize the syslog connection. E.g.: 

```bash
auditmatica write-cef -s \
  --syslog-address localhost \
  --syslog-port 514 \
  --syslog-facility local0 \
  /path/to/nginx/access.log
```

`--syslog-port` will only be used if an address other than `/dev/log` is also
passed with`--syslog-address`.

Valid `--syslog-facility` values are `local0`-`local7`, which are reserved by
syslog for local use.

### `overview`

To generate a high-level JSON overview of Archivematica user activities, use
the `overview` subcommand. E.g.:

```bash
cat access.log | auditmatica overview
```
```
Usage: auditmatica overview [OPTIONS] [LOG]

  Write JSON overview of user activities from nginx access log.

Options:
  --ss-base-url TEXT  Override the Storage Service URL to scan for
                      (default='http://127.0.0.1:62081')
  --help              Show this message and exit.

```

#### Storage Service

`auditmatica` looks for Storage Service events in the nginx access log by
checking each URL to determine if it begins with the expected base URL of the
Storage Service. By default, this is `http://127.0.0.1:62081`.

To override the Storage Service URL to scan for, use `--ss-base-url`. E.g.:

```
auditmatica --ss-base-url http://archivematica.example.com:8000
```

## Download

Download from GitHub:

```bash
git clone https://github.com/artefactual-labs/auditmatica.git
```

## Install

### General

`auditmatica` requires Python 3.6+.

Change into the cloned directory and install:

```bash
cd auditmatica/
pip install .
```

### Usernames

Including authenticated usernames in `auditmatica`'s outputs requires some
additional setup:

1. Enable auditing middleware in Archivematica and the Storage Service via
environment variables
```bash
# Archivematica 1.13+
ARCHIVEMATICA_DASHBOARD_DASHBOARD_AUDIT_LOG_MIDDLEWARE: "true"

# Storage Service 0.18+
SS_AUTH_LOG_MIDDLEWARE: "true"
```

2. Restart Archivematica and Storage Service services
```bash
sudo service archivematica-dashboard restart
sudo service archivematica-storage-service restart
```

3. Add the following configuration to the `http` block of the `nginx.conf`
configuration file (likely `/etc/nginx/nginx.conf`, though this may vary)
```bash
log_format main '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for" user=$upstream_http_x_username';
access_log "/var/log/nginx/access.log" main;
```
This format must be exact, as it maps directly to a pattern `auditmatica` uses
to parse nginx access log lines with usernames. If an `access_log` is already
specified, replace it or name it something other than `main`. The `access_log`
path (by default `/var/log/nginx/access.log`) can be changed as needed.

4. Optionally, add `proxy_hide_header x-username;` to the nginx `server` blocks
to prevent the authenticated username from being sent back with each response
to the client device.

5. Restart nginx service:
```bash
sudo service nginx restart
```

If the above is configured correctly, the resulting nginx access log lines
should look as follows:
```
172.10.5.1 - - [13/Jan/2021:19:53:10 +0000] "GET /backlog/download/2e28b8a9-351c-4da7-92d2-837ac04cd2d9/ HTTP/1.1" 200 19436360 "http://127.0.0.1:62080/backlog/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0" "-" user=test
```

## Development

For development, it may be useful to install `auditmatica` with
`pip install -e .`, which will apply changes made to the source code
immediately.

To run all tests with tox: `tox`

Or run tests directly with pytest:
```bash
pip install -r requirements/test.txt
pytest
```

[am]: https://archivematica.org
[cef]: https://community.microfocus.com/t5/ArcSight-Connectors/ArcSight-Common-Event-Format-CEF-Implementation-Standard/ta-p/1645557
[syslog]: https://tools.ietf.org/html/rfc5424
