"""Event mappings and related constants.

Structure of *_EVENT_MAPPING:
{
  url: {
    status_code: {
      http_method: {
        "event_name": event name (str)
        "event_signature": event signature (int)
        "event_severity": event severity (int, 0-10)
      }
    }
  }
}

Placeholders are used in the mappings in place of several types of
dynamic data that otherwise complicates comparison between actual URLs
and the URLS in the event mappings. Placeholders include:
- <uuid> : replaces uuid4
- <http_params> : replaces arbitrary HTTP parameter string starting
      with "?"
- <processing_config> : replaces processing configuration name
- <user_pk> : replaces user primary key

Any URL recorded in the mappings below must be terminated with a
forward-slash.
"""

HTTP_STATUS_OK = "200"
HTTP_STATUS_CREATED = "201"
HTTP_STATUS_ACCEPTED = "202"
HTTP_STATUS_NO_CONTENT = "204"
HTTP_STATUS_MOVED_PERMANENTLY = "301"
HTTP_STATUS_FOUND = "302"
HTTP_STATUS_UNAUTHORIZED = "401"
HTTP_STATUS_NOT_FOUND = "404"

HTTP_METHOD_GET = "GET"
HTTP_METHOD_HEAD = "HEAD"
HTTP_METHOD_POST = "POST"
HTTP_METHOD_PUT = "PUT"
HTTP_METHOD_DELETE = "DELETE"

EVENT_NAME = "event_name"
EVENT_SIGNATURE = "event_signature"
EVENT_SEVERITY = "event_severity"

DEFAULT_EVENT = {
    EVENT_NAME: "Unspecified user activity",
    EVENT_SIGNATURE: 1,
    EVENT_SEVERITY: 2,
}

DEFAULT_EVENT_404 = {
    EVENT_NAME: "Attempt to navigate to page not found",
    EVENT_SIGNATURE: 2,
    EVENT_SEVERITY: 2,
}

DEFAULT_EVENT_401 = {
    EVENT_NAME: "Attempt to access unauthorized content",
    EVENT_SIGNATURE: 3,
    EVENT_SEVERITY: 5,
}


def get_am_event_mapping():
    """Return a copy of Archivematica event mapping.

    This prevents any accidental modifications to the event mapping.
    """
    return dict(__ARCHIVEMATICA_EVENT_MAPPING)


def get_ss_event_mapping():
    """Return a copy of the Storage Service event mapping.

    This prevents any accidental modifications to the event mapping.
    """
    return dict(__STORAGE_SERVICE_EVENT_MAPPING)


__ARCHIVEMATICA_EVENT_MAPPING = {
    "/administration/accounts/login/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "Successful authentication",
                EVENT_SIGNATURE: 4,
                EVENT_SEVERITY: 1,
            }
        },
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Unauthenticated user directed to login form",
                EVENT_SIGNATURE: 5,
                EVENT_SEVERITY: 2,
            }
        },
    },
    "/administration/accounts/logout/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Successful logout",
                EVENT_SIGNATURE: 6,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/api/v2beta/package/": {
        HTTP_STATUS_ACCEPTED: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "New transfer started",
                EVENT_SIGNATURE: 7,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/mcp/execute/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "Processing decision made",
                EVENT_SIGNATURE: 8,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/backlog/download/<uuid>/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Transfer downloaded from backlog",
                EVENT_SIGNATURE: 9,
                EVENT_SEVERITY: 3,
            }
        },
        HTTP_STATUS_MOVED_PERMANENTLY: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Transfer downloaded from backlog",
                EVENT_SIGNATURE: 9,
                EVENT_SEVERITY: 3,
            }
        },
    },
    "/filesystem/<uuid>/preview/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "File previewed from backlog",
                EVENT_SIGNATURE: 10,
                EVENT_SEVERITY: 3,
            }
        }
    },
    "/filesystem/<uuid>/download/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "File downloaded from backlog",
                EVENT_SIGNATURE: 11,
                EVENT_SEVERITY: 3,
            }
        }
    },
    "/backlog/search/<http_params>/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Backlog search performed",
                EVENT_SIGNATURE: 12,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/archival-storage/search/<http_params>/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Archival Storage search performed",
                EVENT_SIGNATURE: 13,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/archival-storage/thumbnail/<uuid>/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "File thumbnail retrieved from Archival Storage",
                EVENT_SIGNATURE: 14,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/archival-storage/<uuid>/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "AIP detail page visited",
                EVENT_SIGNATURE: 15,
                EVENT_SEVERITY: 1,
            },
            HTTP_METHOD_POST: {
                EVENT_NAME: "Metadata-only DIP upload initiated",
                EVENT_SIGNATURE: 20,
                EVENT_SEVERITY: 2,
            },
        },
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "AIP reingest or deletion request initiated",
                EVENT_SIGNATURE: 19,
                EVENT_SEVERITY: 2,
            }
        },
    },
    "/archival-storage/download/aip/<uuid>/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "AIP downloaded from Archival Storage",
                EVENT_SIGNATURE: 16,
                EVENT_SEVERITY: 3,
            }
        }
    },
    "/archival-storage/download/aip/<uuid>/mets_download/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "AIP METS file downloaded from Archival Storage",
                EVENT_SIGNATURE: 17,
                EVENT_SEVERITY: 3,
            }
        }
    },
    "/archival-storage/download/aip/<uuid>/pointer_file/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "AIP pointer file downloaded from Archival Storage",
                EVENT_SIGNATURE: 18,
                EVENT_SEVERITY: 3,
            }
        }
    },
    "/ingest/preview/aip/<uuid>/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "AIP previewed prior to storage",
                EVENT_SIGNATURE: 21,
                EVENT_SEVERITY: 3,
            }
        }
    },
    "/ingest/preview/dip/<uuid>/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "DIP previewed prior to storage",
                EVENT_SIGNATURE: 22,
                EVENT_SEVERITY: 3,
            }
        }
    },
    "/fpr/fprule/create/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "FPR rule created",
                EVENT_SIGNATURE: 23,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/fpr/fprule/<uuid>/edit/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "FPR rule edited",
                EVENT_SIGNATURE: 24,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/fpr/fprule/<uuid>/delete/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "FPR rule enabled or disabled",
                EVENT_SIGNATURE: 25,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/fpr/fpcommand/create/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "FPR command created",
                EVENT_SIGNATURE: 26,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/fpr/fpcommand/<uuid>/edit/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "FPR command edited",
                EVENT_SIGNATURE: 27,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/fpr/fpcommand/<uuid>/delete/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "FPR command enabled or disabled",
                EVENT_SIGNATURE: 28,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/administration/processing/add/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "Processing configuration created",
                EVENT_SIGNATURE: 29,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/administration/processing/edit/<processing_config>/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Processing configuration edited",
                EVENT_SIGNATURE: 30,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/administration/processing/delete/<processing_config>/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Processing configuration deleted",
                EVENT_SIGNATURE: 31,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/administration/processing/download/<processing_config>/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Processing configuration downloaded",
                EVENT_SIGNATURE: 32,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/administration/general/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "General Archivematica configuration edited",
                EVENT_SIGNATURE: 33,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/administration/dips/atom/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "AtoM DIP upload configuration edited",
                EVENT_SIGNATURE: 34,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/administration/dips/as/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "ArchivesSpace DIP upload configuration edited",
                EVENT_SIGNATURE: 35,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/administration/premis/agent/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "PREMIS Agent edited",
                EVENT_SIGNATURE: 36,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/administration/api/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "API allowlist edited",
                EVENT_SIGNATURE: 37,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/administration/accounts/add/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "New user successfully created",
                EVENT_SIGNATURE: 38,
                EVENT_SEVERITY: 2,
            }
        },
        HTTP_STATUS_OK: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "Unsuccessful attempt to create new user",
                EVENT_SIGNATURE: 39,
                EVENT_SEVERITY: 2,
            }
        },
    },
    "/administration/accounts/<user_pk>/edit/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "User edited",
                EVENT_SIGNATURE: 40,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/administration/accounts/<user_pk>/delete/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "User deleted",
                EVENT_SIGNATURE: 41,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/administration/handle/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "Handle server configuration edited",
                EVENT_SIGNATURE: 42,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/administration/i18n/setlang/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "User interface language changed",
                EVENT_SIGNATURE: 43,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/api/transfer/start_transfer/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "New transfer started",
                EVENT_SIGNATURE: 7,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/api/transfer/unapproved/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Unapproved transfers fetched from API",
                EVENT_SIGNATURE: 44,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/api/transfer/approve/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "Transfer approved via API",
                EVENT_SIGNATURE: 45,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/api/transfer/status/<uuid>/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Transfer status fetched from API",
                EVENT_SIGNATURE: 46,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/api/transfer/<uuid>/delete/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_DELETE: {
                EVENT_NAME: "Transfer hidden in dashboard via API",
                EVENT_SIGNATURE: 47,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/api/transfer/completed/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Completed transfer UUIDs fetched from API",
                EVENT_SIGNATURE: 48,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/api/transfer/reingest/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "Transfer reingested via API",
                EVENT_SIGNATURE: 49,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/api/ingest/status/<uuid>/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Ingest status fetched from API",
                EVENT_SIGNATURE: 50,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/api/ingest/<uuid>/delete/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_DELETE: {
                EVENT_NAME: "Ingest hidden in dashboard via API",
                EVENT_SIGNATURE: 51,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/api/ingest/waiting/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "SIPs awaiting user input fetched from API",
                EVENT_SIGNATURE: 52,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/api/ingest/completed/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Completed SIP UUIDs fetched from API",
                EVENT_SIGNATURE: 53,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/api/ingest/reingest/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "SIP reingested via API",
                EVENT_SIGNATURE: 54,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/filesystem/copy_from_arrange/": {
        HTTP_STATUS_CREATED: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "SIP created from files in backlog",
                EVENT_SIGNATURE: 55,
                EVENT_SEVERITY: 2,
            }
        }
    },
}

__STORAGE_SERVICE_EVENT_MAPPING = {
    "/login/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "Successful authentication",
                EVENT_SIGNATURE: 100,
                EVENT_SEVERITY: 1,
            }
        },
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Unauthenticated user directed to login form",
                EVENT_SIGNATURE: 101,
                EVENT_SEVERITY: 2,
            }
        },
    },
    "/logout/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Successful logout",
                EVENT_SIGNATURE: 102,
                EVENT_SEVERITY: 1,
            }
        }
    },
    "/packages/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Package information viewed",
                EVENT_SIGNATURE: 103,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/api/v2/file/<uuid>/download/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Package downloaded",
                EVENT_SIGNATURE: 104,
                EVENT_SEVERITY: 3,
            },
            HTTP_METHOD_HEAD: {
                EVENT_NAME: "Package downloaded",
                EVENT_SIGNATURE: 104,
                EVENT_SEVERITY: 3,
            },
        }
    },
    "/api/v2/file/<uuid>/pointer_file/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Pointer file downloaded",
                EVENT_SIGNATURE: 105,
                EVENT_SEVERITY: 3,
            }
        }
    },
    "/api/v2/file/<uuid>/delete_aip/": {
        HTTP_STATUS_ACCEPTED: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "Package deletion requested",
                EVENT_SIGNATURE: 106,
                EVENT_SEVERITY: 3,
            }
        }
    },
    "/packages/package_delete_request/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Package deletion requests viewed",
                EVENT_SIGNATURE: 107,
                EVENT_SEVERITY: 2,
            }
        },
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "Decision made on package deletion request",
                EVENT_SIGNATURE: 108,
                EVENT_SEVERITY: 2,
            }
        },
    },
    "/administration/users/create/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "New user successfully created",
                EVENT_SIGNATURE: 109,
                EVENT_SEVERITY: 2,
            }
        },
        HTTP_STATUS_OK: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "Unsuccessful attempt to create new user",
                EVENT_SIGNATURE: 110,
                EVENT_SEVERITY: 2,
            }
        },
    },
    "/administration/users/<user_pk>/edit/": {
        HTTP_STATUS_FOUND: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "User edited",
                EVENT_SIGNATURE: 111,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/api/v2/file/<uuid>/extract_file/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "File downloaded from stored package",
                EVENT_SIGNATURE: 112,
                EVENT_SEVERITY: 3,
            },
            HTTP_METHOD_HEAD: {
                EVENT_NAME: "File downloaded from stored package",
                EVENT_SIGNATURE: 112,
                EVENT_SEVERITY: 3,
            },
        }
    },
    "/api/v2/file/<uuid>/contents/": {
        HTTP_STATUS_OK: {
            HTTP_METHOD_GET: {
                EVENT_NAME: "Metadata about files within package fetched from API",
                EVENT_SIGNATURE: 113,
                EVENT_SEVERITY: 2,
            }
        },
        HTTP_STATUS_CREATED: {
            HTTP_METHOD_PUT: {
                EVENT_NAME: "Metadata about files within package added via API",
                EVENT_SIGNATURE: 114,
                EVENT_SEVERITY: 1,
            }
        },
        HTTP_STATUS_NO_CONTENT: {
            HTTP_METHOD_DELETE: {
                EVENT_NAME: "Metadata about files within package deleted via API",
                EVENT_SIGNATURE: 115,
                EVENT_SEVERITY: 2,
            }
        },
    },
    "/api/v2/file/<uuid>/reingest/": {
        HTTP_STATUS_ACCEPTED: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "Package reingest successfully initiated via API",
                EVENT_SIGNATURE: 116,
                EVENT_SEVERITY: 2,
            }
        }
    },
    "/api/v2/file/<uuid>/move/": {
        HTTP_STATUS_ACCEPTED: {
            HTTP_METHOD_POST: {
                EVENT_NAME: "Package moved to new location via API",
                EVENT_SIGNATURE: 117,
                EVENT_SEVERITY: 2,
            }
        }
    },
}
