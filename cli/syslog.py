"""Syslog constants.

By default, auditmatica uses the SysLogHandler.LOG_USER facility for
writing CEF messages to syslog. SYSLOG_FACILITY defines alternatives
available to the user - namely, local0 - local7.
"""
from logging.handlers import SysLogHandler

SYSLOG_FACILITY = {
    "local0": SysLogHandler.LOG_LOCAL0,
    "local1": SysLogHandler.LOG_LOCAL1,
    "local2": SysLogHandler.LOG_LOCAL2,
    "local3": SysLogHandler.LOG_LOCAL3,
    "local4": SysLogHandler.LOG_LOCAL4,
    "local5": SysLogHandler.LOG_LOCAL5,
    "local6": SysLogHandler.LOG_LOCAL6,
    "local7": SysLogHandler.LOG_LOCAL7,
}
