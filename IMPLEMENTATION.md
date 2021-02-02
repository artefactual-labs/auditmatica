# Archivematica CEF implementation

This document lists the [Common Event Format (CEF)][cef] events implemented for
Archivematica and the Archivematica Storage Service.

Each event consists of three elements:

* Event signature: Unique ID for event
* Event name: Name of event
* Event severity: Integer representing severity of event on a scale of 0-10 (0-3=Low, 4-6=Medium, 7- 8=High, 9-10=Very-High)

`auditmatica` determines the event for a log line entry by comparing the URL,
HTTP method, and HTTP return code in the line against its internal event
mappings.

## Implemented Archivematica CEF events

| Event signature | Event name | Event severity |
| --------------- | ---------- | -------------- |
| 1 | Unspecified user activity | 1 |
| 2 | Attempt to navigate to page not found | 2 |
| 3 | Attempt to access unauthorized or forbidden page | 5 |
| 4 | Successful authentication | 1 |
| 5 | Unauthenticated user directed to login form | 1 |
| 6 | Successful logout | 1 |
| 7 | New transfer started | 1 |
| 8 | Processing decision made | 1 |
| 9 | Transfer downloaded from backlog | 3 |
| 10 | File previewed from backlog | 3 |
| 11 | File downloaded from backlog | 3 |
| 12 | Backlog search performed | 1 |
| 13 | Archival Storage search performed | 1 |
| 14 | File thumbnail retrieved from Archival Storage | 2 |
| 15 | AIP detail page visited | 1 |
| 16 | AIP downloaded from Archival Storage | 3 |
| 17 | AIP METS file downloaded from Archival Storage | 3 |
| 18 | AIP pointer file downloaded from Archival Storage | 3 |
| 19 | AIP reingest or deletion request initiated | 2 |
| 20 | Metadata-only DIP upload initiated | 2 |
| 21 | AIP previewed prior to storage | 3 |
| 22 | DIP previewed prior to storage | 3 |
| 23 | FPR rule created | 2 |
| 24 | FPR rule edited | 2 |
| 25 | FPR rule enabled or disabled | 2 |
| 26 | FPR command created | 2 |
| 27 | FPR command edited | 2 |
| 28 | FPR command enabled or disabled | 2 |
| 29 | Processing configuration created | 2 |
| 30 | Processing configuration edited | 2 |
| 31 | Processing configuration deleted | 2 |
| 32 | Processing configuration downloaded | 2 |
| 33 | General Archivematica configuration edited | 2 |
| 34 | AtoM DIP upload configuration edited | 2 |
| 35 | ArchivesSpace DIP upload configuration edited | 2 |
| 36 | PREMIS Agent edited | 2 |
| 37 | API allowlist edited | 2 |
| 38 | New user successfully created | 2 |
| 39 | Unsuccessful attempt to create new user | 2 |
| 40 | User edited | 2 |
| 41 | User deleted | 2 |
| 42 | Handle server configuration edited | 2 |
| 43 | User interface language changed | 1 |
| 44 | Unapproved transfers fetched from API | 1 |
| 45 | Transfer approved via API | 1 |
| 46 | Transfer status fetched from API | 1 |
| 47 | Transfer hidden in dashboard via API | 1 |
| 48 | Completed transfer UUIDs fetched from API | 1 |
| 49 | Transfer reingested via API | 1 |
| 50 | Ingest status fetched from API | 1 |
| 51 | Ingest hidden in dashboard via API | 1 |
| 52 | SIPs awaiting user input fetched from API | 1 |
| 53 | Completed SIP UUIDs fetched from API | 1 |
| 54 | SIP reingested via API | 1 |
| 55 | SIP created from files in backlog | 2 |

## Implemented Storage Service CEF events

| Event signature | Event name | Event severity |
| --------------- | ---------- | -------------- |
| 100 | Successful authentication | 1 |
| 101 | Unauthenticated user redirected to login form | 2 |
| 102 | Successful logout | 1 |
| 103 | Package information viewed | 2 |
| 104 | Package downloaded | 3 |
| 105 | Pointer file downloaded | 3 |
| 106 | Package deletion requested | 3 |
| 107 | Package deletion requests viewed | 2 |
| 108 | Decision made on package deletion request | 2 |
| 109 | New user successfully created | 2 |
| 110 | Unsuccessful attempt to create new user | 2 |
| 111 | User edited | 2 |
| 112 | File downloaded from stored package | 3 |
| 113 | Metadata about files within package fetched from API | 2 |
| 114 | Metadata about files within package added via API | 1 |
| 115 | Metadata about files within package deleted via API | 2 |
| 116 | Package reingest successfully initiated via API | 2 |
| 117 | Package moved to new location via API | 2 |

## Archivematica actions not yet implemented

Events not yet implemented are represented by the default event.

* General page views (e.g. `/transfer/` or `/ingest/`, HTTP method `GET`,
return code `200`)
* FPR actions besides FPRules and FPCommands (e.g. adding a tool)
* Actions on access tab

## Storage Service actions not yet implemented

Events not yet implemented are represented by the default event.

* Packages
    * Updating package status
    * Package recovery request
* Administration
    * Adding, editing, and deleting post-store callbacks
    * Adding, editing, and deleting encryption keys
* API
    * `/api/v2/file/`
    * `/api/v2/file/<uuid>/`
    * `/api/v2/file/<uuid>/recover_aip/`
    * `/api/v2/file/<uuid>/download/<LOCKSS chunk number>/`
    * `/api/v2/file/<uuid>/check_fixity/`
    * `/api/v2/file/<uuid>/send_callback/post_store/`
    * `/api/v2/file/<uuid>/metadata/`
    * `/api/v2/file/<uuid>/sword/`
    * `/api/v2/file/<uuid>/sword/media/`
    * `/api/v2/file/<uuid>/sword/state/`
* Adding, editing, and deleting Pipelines
* Adding, editing, and deleting Spaces
* Adding, editing, and deleting Locations


[cef]: https://community.microfocus.com/t5/ArcSight-Connectors/ArcSight-Common-Event-Format-CEF-Implementation-Standard/ta-p/1645557
