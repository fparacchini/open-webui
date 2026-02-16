"""
Custom Access Logging Middleware — Open WebUI
================================================================
NIS2-compliant access log middleware (EU Directive 2022/2555).
Bypasses Uvicorn's built-in access logging entirely to produce a
structured, security-enriched log line for every HTTP request.

Overview
--------
The middleware intercepts every inbound request, extracts identity
and context from JWT cookies / OIDC tokens / DB lookups, classifies
the action as one of ~80 NIS2-relevant types, then emits a single
pipe-delimited log line to stdout.  Security-relevant actions are
logged at WARNING level so SIEM systems can filter on severity.

Key features:
  • User identity resolved via JWT cookie → DB (email, role).
  • OIDC subject (``sub``) and MFA status (``amr``/``acr``)
    extracted from server-side OAuth sessions (id_token).
  • ~80 regex rules classify every API route into a semantic
    action type (AUTH_LOGIN, GROUP_MEMBER_ADD, CONFIG_IMPORT, …).
  • Failed authentication attempts auto-detected (status ≥ 400
    on AUTH_LOGIN* → AUTH_LOGIN_FAIL with nis2=Y).
  • Target object (type + id) extracted from URL path for
    audit trail completeness.
  • Thread-safe LRU cache (2 048 entries, 5 min TTL) avoids
    repeated DB hits; short TTL (10 s) for entries missing
    OIDC claims (login race window).
  • Query string included in log output for full request
    traceability (e.g. ``?page=2``, ``?id=model-name``).

Uvicorn Log Deduplication
--------------------------
``setup_access_logging()`` silences **three** Uvicorn loggers to
prevent duplicate lines for every request:

  1. ``uvicorn.access``                              — standard access log
  2. ``uvicorn.protocols.http.httptools_impl``        — httptools send()
  3. ``uvicorn.protocols.http.h11_impl``              — h11 send()

All three are set to WARNING level with ``propagate = False``.

Static Asset Filtering
-----------------------
Requests for static / immutable assets are **skipped entirely**
(no log line emitted) because they carry no audit value and can
represent ~70 % of total log volume for browser sessions.

Excluded prefixes (checked via ``str.startswith()``):
  • ``/_app/immutable/``   — SvelteKit hashed JS/CSS chunks
  • ``/_app/version.json`` — SvelteKit version polling
  • ``/static/``           — application static files
  • ``/assets/``           — fonts, images

Health-check endpoints (``/health``, ``/api/health``) are also
excluded via the ``exclude_paths`` parameter.

Outcome Mapping
----------------
HTTP status codes are mapped to CEF-compatible outcome strings:

  +-----------+----------------------------------------------+
  | outcome   | HTTP status codes                            |
  +===========+==============================================+
  | success   | 2xx, **304 Not Modified** (cache validation) |
  | redirect  | 3xx (301, 302, 303, 307, 308)                |
  | failure   | 4xx (auth failures, forbidden, not found)    |
  | error     | 5xx (server / infrastructure errors)         |
  +-----------+----------------------------------------------+

**Note:** 304 is mapped to ``success`` (not ``redirect``) because
it represents a successful cache revalidation, not a location
redirect.  This avoids inflating redirect metrics in SIEM dashboards.

Azure WAF / Front Door Integration
-----------------------------------
When deployed behind Azure WAF, Application Gateway, or Front Door
the middleware extracts the real client IP from the following headers
(in priority order):

  1. ``X-Azure-ClientIP``           — Azure Front Door / AppGW
  2. ``X-Original-Forwarded-For``   — original before WAF rewrite
  3. ``X-Forwarded-For``            — standard reverse-proxy
  4. ``X-Real-IP``                  — nginx-style
  5. ``request.client.host``        — direct ASGI fallback

The correlation ID is picked up from:
  • ``X-Request-ID``       — generic / Azure API Management
  • ``X-Correlation-ID``   — ManageEngine ADSSPM
  • ``X-Azure-Ref``        — Azure Front Door unique reference

ManageEngine Log360 SIEM Integration
-------------------------------------
Each log field maps to a CEF / syslog field that Log360 can parse
and index automatically:

  +-----------------+---------------------------+------------------------------------+
  | Log field       | CEF / Log360 field        | Purpose                            |
  +=================+===========================+====================================+
  | email           | duser / suser             | User identity                      |
  | session_id      | cs3                       | Session tracking (UEBA)            |
  | correlation_id  | externalId                | Cross-system event correlation     |
  | oidc_sub        | cs9                       | Federated identity (OIDC subject)  |
  | mfa             | cs8                       | MFA method (Art.21.2.j)            |
  | role            | spriv                     | Privilege level (escalation det.)  |
  | action          | act                       | Semantic action type               |
  | outcome         | outcome                   | success/failure (brute-force det.) |
  | nis2            | cs10                      | NIS2 relevance flag (Y/N)          |
  | object          | cs4 (id) + cs5 (type)     | Target resource for audit trail    |
  | ua              | requestClientApplication  | User-Agent (UEBA anomaly det.)    |
  | client IP       | src                       | Source IP address                  |
  | HTTP method+path| request                   | Request URL (with query string)    |
  | status code     | cs6                       | HTTP response status               |
  | time            | cs7                       | Response latency (anomaly det.)    |
  +-----------------+---------------------------+------------------------------------+

Log360 UEBA uses ``outcome`` for brute-force scoring, ``spriv``
for privilege-escalation detection, and ``requestClientApplication``
for device-fingerprint anomalies.

Log format example
------------------
::

  2026-02-15 16:50:00 | WARNING  | email=admin@co.com | session_id=a1b2c3d4 |
  correlation_id=azure-ref-xyz | oidc_sub=sub123 | mfa=pwd,otp | role=admin |
  action=GROUP_MEMBER_ADD | outcome=success | nis2=Y | object=group:g-456 |
  ua=Mozilla/5.0 … | 10.0.0.1 - "POST /api/v1/groups/id/g-456/users/add" 200 |
  time=0.045s

NIS2 Action Categories
-----------------------
  AUTH_*       — Authentication & session lifecycle
  USER_*       — User account management
  GROUP_*      — Group & membership management
  CONFIG_*     — System configuration changes
  ACCESS_*     — Access control & sharing changes
  CHAT_*       — Chat lifecycle (create, delete, archive)  **[nis2=Y]**
  NOTE_*       — Note management
  FILE_*       — File upload/deletion  **[nis2=Y]**
  KNOWLEDGE_*  — Knowledge base management
  RESOURCE_*   — Tools, functions, models management
  CHANNEL_*    — Channel & webhook management
  DATA_*       — Data export/import
  READ         — Read-only operations (lower severity)

Changelog
---------
2026-02-16
  • **Fix: Uvicorn deduplication** — silence ``httptools_impl`` and
    ``h11_impl`` loggers in addition to ``uvicorn.access`` to
    eliminate duplicate log lines for every HTTP request.
  • **Fix: 304 outcome** — map 304 Not Modified to ``success``
    instead of ``redirect`` to avoid inflating redirect metrics.
  • **Feature: static asset exclusion** — skip logging for
    ``/_app/immutable/``, ``/_app/version.json``, ``/static/``,
    and ``/assets/`` prefixes (~70 % volume reduction).
  • **Feature: query string in log** — include ``request.query_params``
    in the logged URL for full request traceability.
  • **Fix: NIS2 coverage** — add ``CHAT_CREATE``, ``CHAT_DELETE``,
    ``CHAT_ARCHIVE``, ``CHAT_ARCHIVE_ALL``, ``FILE_UPLOAD``,
    ``FILE_DELETE``, and ``FILE_CONTENT_UPDATE`` to the
    ``_NIS2_SECURITY_ACTIONS`` set so they emit ``nis2=Y``
    at WARNING level.
"""

import hashlib
import re
import uuid
import logging
import sys
import time
import threading
from typing import Callable, Optional, NamedTuple
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

try:
    import jwt as pyjwt
except ImportError:
    pyjwt = None

# ---------------------------------------------------------------------------
# Thread-safe cache: resolve user UUID → (email, oidc_sub, mfa_status) via DB.
#
# Design notes for 2 000 users / 200 concurrent:
#   - maxsize=2048 covers the full user base → ~100 % hit rate after warm-up.
#   - TTL of 300 s ensures changes propagate within 5 min.
#   - threading.Lock protects the dict; released during I/O.
#   - DB lookups are synchronous but fast (PK index, single row).
#     They run inside BaseHTTPMiddleware's worker thread, so the
#     asyncio event loop is NOT blocked.
# ---------------------------------------------------------------------------

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# NIS2 Action Type Classification
#
# Maps API routes (path + method) to security-relevant action types.
# NIS2 (Directive 2022/2555) requires logging of security-relevant events
# including: authentication, authorization changes, configuration changes,
# access control modifications, data sharing, and administrative actions.
#
# Categories:
#   AUTH_*       — Authentication & session lifecycle
#   USER_*       — User account management
#   GROUP_*      — Group & membership management
#   CONFIG_*     — System configuration changes
#   ACCESS_*     — Access control & sharing changes
#   CHAT_*       — Chat lifecycle (create, delete, archive)
#   NOTE_*       — Note management
#   FILE_*       — File upload/deletion
#   KNOWLEDGE_*  — Knowledge base management
#   RESOURCE_*   — Tools, functions, models management
#   CHANNEL_*    — Channel & webhook management
#   DATA_*       — Data export/import
#   READ         — Read-only operations (lower severity)
# ---------------------------------------------------------------------------

# Compiled regex rules: list of (compiled_pattern, http_method_or_None, action_type)
# Order matters: first match wins. More specific patterns come first.
# method=None means "any HTTP method".
_NIS2_ACTION_RULES: list[tuple[re.Pattern, Optional[str], str]] = []


def _compile_action_rules() -> list[tuple[re.Pattern, Optional[str], str]]:
    """Build and compile the NIS2 action classification rules.

    Called once at module load time. Each rule is:
        (path_regex, http_method | None, action_type)
    """
    _ID = r"[^/]+"  # matches a path segment (UUID, slug, etc.)

    raw_rules: list[tuple[str, Optional[str], str]] = [
        # ── Authentication & Session ─────────────────────────────────────
        (rf"^/api/v1/auths/signin$", "POST", "AUTH_LOGIN"),
        (rf"^/api/v1/auths/ldap$", "POST", "AUTH_LOGIN_LDAP"),
        (rf"^/api/v1/auths/signup$", "POST", "AUTH_SIGNUP"),
        (rf"^/api/v1/auths/signout$", "GET", "AUTH_LOGOUT"),
        (rf"^/api/v1/auths/update/password$", "POST", "AUTH_PASSWORD_CHANGE"),
        (rf"^/api/v1/auths/update/profile$", "POST", "AUTH_PROFILE_UPDATE"),
        (rf"^/api/v1/auths/api_key$", "POST", "AUTH_API_KEY_CREATE"),
        (rf"^/api/v1/auths/api_key$", "DELETE", "AUTH_API_KEY_DELETE"),
        (rf"^/api/v1/auths/oauth/{_ID}/token/exchange$", "POST", "AUTH_OAUTH_TOKEN"),
        (rf"^/api/v1/auths/admin/config/ldap/server$", "POST", "CONFIG_LDAP_SERVER"),
        (rf"^/api/v1/auths/admin/config/ldap$", "POST", "CONFIG_LDAP"),
        (rf"^/api/v1/auths/admin/config$", "POST", "CONFIG_AUTH"),
        (rf"^/api/v1/auths/add$", "POST", "USER_CREATE"),

        # ── User Management ──────────────────────────────────────────────
        (rf"^/api/v1/users/default/permissions$", "POST", "USER_PERMISSIONS_DEFAULT"),
        (rf"^/api/v1/users/{_ID}/update$", "POST", "USER_UPDATE"),
        (rf"^/api/v1/users/{_ID}$", "DELETE", "USER_DELETE"),
        (rf"^/api/v1/users/user/settings/update$", "POST", "USER_SETTINGS_UPDATE"),
        (rf"^/api/v1/users/user/info/update$", "POST", "USER_INFO_UPDATE"),

        # ── Group Management ─────────────────────────────────────────────
        (rf"^/api/v1/groups/create$", "POST", "GROUP_CREATE"),
        (rf"^/api/v1/groups/id/{_ID}/update$", "POST", "GROUP_UPDATE"),
        (rf"^/api/v1/groups/id/{_ID}/delete$", "DELETE", "GROUP_DELETE"),
        (rf"^/api/v1/groups/id/{_ID}/users/add$", "POST", "GROUP_MEMBER_ADD"),
        (rf"^/api/v1/groups/id/{_ID}/users/remove$", "POST", "GROUP_MEMBER_REMOVE"),
        (rf"^/api/v1/groups/id/{_ID}/export$", "GET", "DATA_EXPORT"),

        # ── System Configuration ─────────────────────────────────────────
        (rf"^/api/v1/configs/import$", "POST", "CONFIG_IMPORT"),
        (rf"^/api/v1/configs/export$", "GET", "CONFIG_EXPORT"),
        (rf"^/api/v1/configs/connections$", "POST", "CONFIG_CONNECTIONS"),
        (rf"^/api/v1/configs/oauth/clients/register$", "POST", "CONFIG_OAUTH_CLIENT"),
        (rf"^/api/v1/configs/tool_servers$", "POST", "CONFIG_TOOL_SERVERS"),
        (rf"^/api/v1/configs/code_execution$", "POST", "CONFIG_CODE_EXECUTION"),
        (rf"^/api/v1/configs/models$", "POST", "CONFIG_MODELS"),
        (rf"^/api/v1/configs/suggestions$", "POST", "CONFIG_SUGGESTIONS"),
        (rf"^/api/v1/configs/banners$", "POST", "CONFIG_BANNERS"),

        # ── Chat Operations ──────────────────────────────────────────────
        (rf"^/api/v1/chats/new$", "POST", "CHAT_CREATE"),
        (rf"^/api/v1/chats/import$", "POST", "DATA_IMPORT"),
        (rf"^/api/v1/chats/{_ID}/share$", "POST", "ACCESS_SHARE_CHAT"),
        (rf"^/api/v1/chats/{_ID}/share$", "DELETE", "ACCESS_UNSHARE_CHAT"),
        (rf"^/api/v1/chats/{_ID}/archive$", "POST", "CHAT_ARCHIVE"),
        (rf"^/api/v1/chats/archive/all$", "POST", "CHAT_ARCHIVE_ALL"),
        (rf"^/api/v1/chats/unarchive/all$", "POST", "CHAT_UNARCHIVE_ALL"),
        (rf"^/api/v1/chats/{_ID}/clone$", "POST", "CHAT_CLONE"),
        (rf"^/api/v1/chats/{_ID}/clone/shared$", "POST", "CHAT_CLONE_SHARED"),
        (rf"^/api/v1/chats/{_ID}$", "DELETE", "CHAT_DELETE"),
        (rf"^/api/v1/chats/$", "DELETE", "CHAT_DELETE_ALL"),
        (rf"^/api/v1/chats/{_ID}$", "POST", "CHAT_UPDATE"),
        (rf"^/api/v1/chats/stats/export", "GET", "DATA_EXPORT"),

        # ── Note Operations ──────────────────────────────────────────────
        (rf"^/api/v1/notes/create$", "POST", "NOTE_CREATE"),
        (rf"^/api/v1/notes/{_ID}/update$", "POST", "NOTE_UPDATE"),
        (rf"^/api/v1/notes/{_ID}/access/update$", "POST", "ACCESS_NOTE_UPDATE"),
        (rf"^/api/v1/notes/{_ID}/delete$", "DELETE", "NOTE_DELETE"),

        # ── File Operations ──────────────────────────────────────────────
        (rf"^/api/v1/files/$", "POST", "FILE_UPLOAD"),
        (rf"^/api/v1/files/all$", "DELETE", "FILE_DELETE_ALL"),
        (rf"^/api/v1/files/{_ID}$", "DELETE", "FILE_DELETE"),
        (rf"^/api/v1/files/{_ID}/data/content/update$", "POST", "FILE_CONTENT_UPDATE"),

        # ── Knowledge Base ───────────────────────────────────────────────
        (rf"^/api/v1/knowledge/create$", "POST", "KNOWLEDGE_CREATE"),
        (rf"^/api/v1/knowledge/{_ID}/update$", "POST", "KNOWLEDGE_UPDATE"),
        (rf"^/api/v1/knowledge/{_ID}/access/update$", "POST", "ACCESS_KNOWLEDGE_UPDATE"),
        (rf"^/api/v1/knowledge/{_ID}/delete$", "DELETE", "KNOWLEDGE_DELETE"),
        (rf"^/api/v1/knowledge/{_ID}/reset$", "POST", "KNOWLEDGE_RESET"),
        (rf"^/api/v1/knowledge/{_ID}/file/add$", "POST", "KNOWLEDGE_FILE_ADD"),
        (rf"^/api/v1/knowledge/{_ID}/file/remove$", "POST", "KNOWLEDGE_FILE_REMOVE"),
        (rf"^/api/v1/knowledge/{_ID}/files/batch/add$", "POST", "KNOWLEDGE_FILE_ADD"),
        (rf"^/api/v1/knowledge/{_ID}/export$", "GET", "DATA_EXPORT"),
        (rf"^/api/v1/knowledge/reindex$", "POST", "KNOWLEDGE_REINDEX"),

        # ── Functions (Plugins) ──────────────────────────────────────────
        (rf"^/api/v1/functions/create$", "POST", "RESOURCE_CREATE_FUNCTION"),
        (rf"^/api/v1/functions/id/{_ID}/update$", "POST", "RESOURCE_UPDATE_FUNCTION"),
        (rf"^/api/v1/functions/id/{_ID}/delete$", "DELETE", "RESOURCE_DELETE_FUNCTION"),
        (rf"^/api/v1/functions/id/{_ID}/toggle$", "POST", "RESOURCE_TOGGLE_FUNCTION"),
        (rf"^/api/v1/functions/id/{_ID}/toggle/global$", "POST", "RESOURCE_TOGGLE_FUNCTION_GLOBAL"),
        (rf"^/api/v1/functions/id/{_ID}/valves/update$", "POST", "RESOURCE_UPDATE_FUNCTION_VALVES"),
        (rf"^/api/v1/functions/sync$", "POST", "RESOURCE_SYNC_FUNCTIONS"),
        (rf"^/api/v1/functions/export$", "GET", "DATA_EXPORT"),
        (rf"^/api/v1/functions/load/url$", "POST", "RESOURCE_LOAD_FUNCTION_URL"),

        # ── Tools ────────────────────────────────────────────────────────
        (rf"^/api/v1/tools/create$", "POST", "RESOURCE_CREATE_TOOL"),
        (rf"^/api/v1/tools/id/{_ID}/update$", "POST", "RESOURCE_UPDATE_TOOL"),
        (rf"^/api/v1/tools/id/{_ID}/access/update$", "POST", "ACCESS_TOOL_UPDATE"),
        (rf"^/api/v1/tools/id/{_ID}/delete$", "DELETE", "RESOURCE_DELETE_TOOL"),
        (rf"^/api/v1/tools/id/{_ID}/valves/update$", "POST", "RESOURCE_UPDATE_TOOL_VALVES"),
        (rf"^/api/v1/tools/export$", "GET", "DATA_EXPORT"),
        (rf"^/api/v1/tools/load/url$", "POST", "RESOURCE_LOAD_TOOL_URL"),

        # ── Models ───────────────────────────────────────────────────────
        (rf"^/api/v1/models/create$", "POST", "RESOURCE_CREATE_MODEL"),
        (rf"^/api/v1/models/model/update$", "POST", "RESOURCE_UPDATE_MODEL"),
        (rf"^/api/v1/models/model/access/update$", "POST", "ACCESS_MODEL_UPDATE"),
        (rf"^/api/v1/models/model/delete$", "POST", "RESOURCE_DELETE_MODEL"),
        (rf"^/api/v1/models/model/toggle$", "POST", "RESOURCE_TOGGLE_MODEL"),
        (rf"^/api/v1/models/delete/all$", "DELETE", "RESOURCE_DELETE_ALL_MODELS"),
        (rf"^/api/v1/models/import$", "POST", "DATA_IMPORT"),
        (rf"^/api/v1/models/export$", "GET", "DATA_EXPORT"),
        (rf"^/api/v1/models/sync$", "POST", "RESOURCE_SYNC_MODELS"),

        # ── Channels ─────────────────────────────────────────────────────
        (rf"^/api/v1/channels/create$", "POST", "CHANNEL_CREATE"),
        (rf"^/api/v1/channels/{_ID}/update$", "POST", "CHANNEL_UPDATE"),
        (rf"^/api/v1/channels/{_ID}/delete$", "DELETE", "CHANNEL_DELETE"),
        (rf"^/api/v1/channels/{_ID}/update/members/add$", "POST", "CHANNEL_MEMBER_ADD"),
        (rf"^/api/v1/channels/{_ID}/update/members/remove$", "POST", "CHANNEL_MEMBER_REMOVE"),
        (rf"^/api/v1/channels/{_ID}/webhooks/create$", "POST", "CHANNEL_WEBHOOK_CREATE"),
        (rf"^/api/v1/channels/{_ID}/webhooks/{_ID}/update$", "POST", "CHANNEL_WEBHOOK_UPDATE"),
        (rf"^/api/v1/channels/{_ID}/webhooks/{_ID}/delete$", "DELETE", "CHANNEL_WEBHOOK_DELETE"),
        (rf"^/api/v1/channels/{_ID}/messages/post$", "POST", "CHANNEL_MESSAGE_POST"),
        (rf"^/api/v1/channels/{_ID}/messages/{_ID}/delete$", "DELETE", "CHANNEL_MESSAGE_DELETE"),
        (rf"^/api/v1/channels/{_ID}/messages/{_ID}/update$", "POST", "CHANNEL_MESSAGE_UPDATE"),

        # ── Catch-all for remaining API write operations ─────────────────
        # These catch any unmatched POST/PUT/PATCH/DELETE on /api/ paths
        (rf"^/api/", "DELETE", "DELETE_OTHER"),
        (rf"^/api/", "POST", "WRITE_OTHER"),
        (rf"^/api/", "PUT", "WRITE_OTHER"),
        (rf"^/api/", "PATCH", "WRITE_OTHER"),

        # ── Read operations ──────────────────────────────────────────────
        (rf"^/api/", "GET", "READ"),
    ]

    return [
        (re.compile(pattern, re.IGNORECASE), method, action)
        for pattern, method, action in raw_rules
    ]


_NIS2_ACTION_RULES = _compile_action_rules()

# Pre-computed set of action types that are NIS2 security-relevant
# (higher severity — should be flagged in SIEM/audit tools)
_NIS2_SECURITY_ACTIONS = frozenset({
    # Authentication
    "AUTH_LOGIN", "AUTH_LOGIN_LDAP", "AUTH_SIGNUP", "AUTH_LOGOUT",
    "AUTH_PASSWORD_CHANGE", "AUTH_API_KEY_CREATE", "AUTH_API_KEY_DELETE",
    "AUTH_OAUTH_TOKEN",
    # User management
    "USER_CREATE", "USER_UPDATE", "USER_DELETE", "USER_PERMISSIONS_DEFAULT",
    # Group management
    "GROUP_CREATE", "GROUP_UPDATE", "GROUP_DELETE",
    "GROUP_MEMBER_ADD", "GROUP_MEMBER_REMOVE",
    # Configuration
    "CONFIG_AUTH", "CONFIG_LDAP", "CONFIG_LDAP_SERVER",
    "CONFIG_CONNECTIONS", "CONFIG_OAUTH_CLIENT", "CONFIG_TOOL_SERVERS",
    "CONFIG_CODE_EXECUTION", "CONFIG_MODELS", "CONFIG_IMPORT",
    # Access control / sharing
    "ACCESS_SHARE_CHAT", "ACCESS_UNSHARE_CHAT",
    "ACCESS_NOTE_UPDATE", "ACCESS_KNOWLEDGE_UPDATE",
    "ACCESS_TOOL_UPDATE", "ACCESS_MODEL_UPDATE",
    # Data export (potential data exfiltration)
    "CONFIG_EXPORT", "DATA_EXPORT", "DATA_IMPORT",
    # Chat lifecycle (NIS2: conversation data creation/modification)
    "CHAT_CREATE", "CHAT_DELETE", "CHAT_ARCHIVE", "CHAT_ARCHIVE_ALL",
    # Destructive operations
    "CHAT_DELETE_ALL", "FILE_DELETE_ALL", "RESOURCE_DELETE_ALL_MODELS",
    "KNOWLEDGE_DELETE", "KNOWLEDGE_RESET",
    # File operations (NIS2: data upload/modification)
    "FILE_UPLOAD", "FILE_DELETE", "FILE_CONTENT_UPDATE",
    # Resource management with security implications
    "RESOURCE_CREATE_FUNCTION", "RESOURCE_UPDATE_FUNCTION",
    "RESOURCE_DELETE_FUNCTION", "RESOURCE_LOAD_FUNCTION_URL",
    "RESOURCE_CREATE_TOOL", "RESOURCE_UPDATE_TOOL",
    "RESOURCE_DELETE_TOOL", "RESOURCE_LOAD_TOOL_URL",
    # Channel/webhook (external integrations)
    "CHANNEL_WEBHOOK_CREATE", "CHANNEL_WEBHOOK_UPDATE", "CHANNEL_WEBHOOK_DELETE",
})


def _classify_action(method: str, path: str) -> tuple[str, bool]:
    """Classify an HTTP request into a NIS2 action type.

    Returns (action_type, is_security_relevant).
    """
    for pattern, rule_method, action in _NIS2_ACTION_RULES:
        if rule_method is not None and method.upper() != rule_method:
            continue
        if pattern.search(path):
            return action, action in _NIS2_SECURITY_ACTIONS
    return "-", False


# ---------------------------------------------------------------------------
# Object reference extraction  (Log360 cs4 / cs5)
#
# Extracts the target resource type and ID from URL paths so that Log360
# can build a complete audit trail ("which group was modified?", "which
# file was deleted?").
# ---------------------------------------------------------------------------

_OBJECT_ID_PATTERNS: list[tuple[re.Pattern, str]] = []


def _compile_object_id_patterns() -> list[tuple[re.Pattern, str]]:
    """Compile patterns for extracting object identifiers from URL paths.

    Returns list of (compiled_regex, object_type) where the regex has a
    named group 'oid' that captures the object ID.
    """
    _ID = r"(?P<oid>[^/]+)"

    raw = [
        (rf"/groups/id/{_ID}", "group"),
        (rf"/users/{_ID}/update", "user"),
        (rf"/users/{_ID}$", "user"),
        (rf"/chats/{_ID}", "chat"),
        (rf"/notes/{_ID}", "note"),
        (rf"/files/{_ID}", "file"),
        (rf"/knowledge/{_ID}", "knowledge"),
        (rf"/functions/id/{_ID}", "function"),
        (rf"/tools/id/{_ID}", "tool"),
        (rf"/channels/{_ID}", "channel"),
    ]

    return [(re.compile(p, re.IGNORECASE), obj_type) for p, obj_type in raw]


_OBJECT_ID_PATTERNS = _compile_object_id_patterns()


def _extract_object_ref(path: str) -> tuple[Optional[str], Optional[str]]:
    """Extract object_type and object_id from a URL path.

    Returns (object_type, object_id) or (None, None) if no match.
    Used to populate ManageEngine Log360 ``cs4`` (target resource)
    and ``cs5`` (resource type).
    """
    for pattern, obj_type in _OBJECT_ID_PATTERNS:
        m = pattern.search(path)
        if m:
            return obj_type, m.group("oid")
    return None, None


# ---------------------------------------------------------------------------
# Outcome mapping  (Log360 outcome / CEF outcome)
# ---------------------------------------------------------------------------

def _outcome_from_status(status_code: int) -> str:
    """Map HTTP status code to Log360-compatible outcome string.

    ManageEngine Log360 UEBA uses outcome for brute-force detection,
    anomaly scoring, and compliance reporting.

    Values align with CEF outcome field:
      success  — 2xx responses and 304 Not Modified (cache validation)
      redirect — 3xx redirects (301, 302, 303, 307, 308 — OAuth flows, etc.)
      failure  — 4xx client errors (auth failures, forbidden, not found)
      error    — 5xx server errors (infrastructure issues)
    """
    if 200 <= status_code < 300:
        return "success"
    elif status_code == 304:
        # 304 Not Modified is a cache validation response, not a redirect.
        # Treating it as "success" avoids inflating redirect metrics in SIEM.
        return "success"
    elif 300 <= status_code < 400:
        return "redirect"
    elif 400 <= status_code < 500:
        return "failure"
    else:
        return "error"


class _UserContext(NamedTuple):
    email: Optional[str]
    oidc_sub: Optional[str]
    mfa_status: Optional[str]
    role: Optional[str]


_CACHE_MAX = 2048
_CACHE_TTL = 300  # seconds
_CACHE_TTL_SHORT = 10  # seconds — for entries missing OIDC claims (login race)
_cache_lock = threading.Lock()
_cache_data: dict[str, tuple[_UserContext, float]] = {}  # user_id → (ctx, ts)


def invalidate_user_cache(user_id: str) -> None:
    """Invalidate cached user context so the next request re-fetches from DB.

    Call this after saving/updating an OAuth session for the user.
    """
    with _cache_lock:
        _cache_data.pop(user_id, None)
    _log.debug("Invalidated access-log cache for user %s", user_id)


# ---------------------------------------------------------------------------
# NIS2-required claims inside the OIDC id_token.
#   sub  — unique subject identifier (mandatory per OIDC Core)
#   amr  — Authentication Methods References (RFC 8176) — proves MFA
#   acr  — Authentication Context Class Reference — alternative MFA signal
# If any of these are absent the access-log cannot be fully NIS2-compliant.
# ---------------------------------------------------------------------------
_NIS2_REQUIRED_CLAIMS = ("sub",)
_NIS2_MFA_CLAIMS = ("amr", "acr")  # at least one must be present


def _decode_id_token_claims(id_token_raw: str, user_hint: str = "") -> tuple[Optional[str], Optional[str]]:
    """Decode an OIDC id_token (without signature verification) and extract sub + MFA claims.

    Emits a WARNING when claims required for NIS2 compliance are missing.
    *user_hint* is included in warnings to ease troubleshooting.
    """
    if not id_token_raw or pyjwt is None:
        return None, None
    try:
        decoded = pyjwt.decode(
            id_token_raw,
            options={"verify_signature": False},
            algorithms=["RS256", "HS256", "ES256", "PS256", "EdDSA"],
        )

        # --- NIS2 compliance check ----------------------------------------
        missing_required = [c for c in _NIS2_REQUIRED_CLAIMS if not decoded.get(c)]
        has_mfa_claim = any(decoded.get(c) for c in _NIS2_MFA_CLAIMS)

        if missing_required:
            _log.warning(
                "NIS2-COMPLIANCE: OIDC id_token for user [%s] is missing required claim(s): %s. "
                "The IdP (ManageEngine ADSSPM) must be configured to include these claims. "
                "Available claims: %s",
                user_hint or "unknown",
                ", ".join(missing_required),
                ", ".join(sorted(decoded.keys())),
            )
        if not has_mfa_claim:
            _log.warning(
                "NIS2-COMPLIANCE: OIDC id_token for user [%s] contains neither 'amr' nor 'acr'. "
                "MFA status cannot be determined. "
                "Configure the IdP (ManageEngine ADSSPM) to emit 'amr' (RFC 8176) or 'acr' claims. "
                "Available claims: %s",
                user_hint or "unknown",
                ", ".join(sorted(decoded.keys())),
            )
        # ------------------------------------------------------------------

        oidc_sub = decoded.get("sub")
        amr = decoded.get("amr")
        acr = decoded.get("acr")
        if amr:
            mfa_status = ",".join(amr) if isinstance(amr, list) else str(amr)
        elif acr:
            mfa_status = str(acr)
        else:
            mfa_status = None
        return oidc_sub, mfa_status
    except Exception as e:
        _log.warning(
            "NIS2-COMPLIANCE: Failed to decode OIDC id_token for user [%s]: %s. "
            "OIDC sub and MFA status will be unavailable.",
            user_hint or "unknown", e,
        )
        return None, None


def _resolve_user_context(user_id: str) -> _UserContext:
    """Resolve email, oidc_sub, mfa_status and role for a user UUID.

    Uses the Users table for email + role and the OAuthSessions table for
    OIDC claims (decrypts the stored id_token server-side — no dependency
    on browser cookies).
    Thread-safe, bounded cache with TTL.
    """
    now = time.monotonic()

    with _cache_lock:
        entry = _cache_data.get(user_id)
        if entry is not None:
            ctx, ts = entry
            # Use shorter TTL when OIDC claims are missing (login race condition)
            ttl = _CACHE_TTL if ctx.oidc_sub else _CACHE_TTL_SHORT
            if now - ts < ttl:
                return ctx
            del _cache_data[user_id]

    # --- DB lookups (outside lock) ---
    email: Optional[str] = None
    oidc_sub: Optional[str] = None
    mfa_status: Optional[str] = None
    role: Optional[str] = None

    # 1) Resolve email + role from Users table (Log360: duser + spriv)
    try:
        from open_webui.models.users import Users
        user = Users.get_user_by_id(user_id)
        if user:
            if getattr(user, "email", None):
                email = str(user.email)
            if getattr(user, "role", None):
                role = str(user.role)
    except Exception:
        pass

    # 2) Resolve OIDC claims from server-side OAuth session
    try:
        from open_webui.models.oauth_sessions import OAuthSessions
        sessions = OAuthSessions.get_sessions_by_user_id(user_id)
        if sessions:
            # Take the most recent session
            session = sessions[0]
            token_dict = session.token  # already decrypted by the model
            if isinstance(token_dict, dict):
                id_token_raw = token_dict.get("id_token")
                if id_token_raw and isinstance(id_token_raw, str):
                    oidc_sub, mfa_status = _decode_id_token_claims(
                        id_token_raw, user_hint=email or user_id
                    )
                else:
                    _log.warning(
                        "NIS2-COMPLIANCE: OAuth session for user [%s] does not contain an id_token. "
                        "The IdP (ManageEngine ADSSPM) token response must include an id_token "
                        "for NIS2-compliant logging. Token keys present: %s",
                        email or user_id,
                        ", ".join(sorted(token_dict.keys())) if token_dict else "(empty)",
                    )
                # Fallback: some providers put userinfo directly in the token response
                if not oidc_sub:
                    userinfo = token_dict.get("userinfo")
                    if isinstance(userinfo, dict):
                        oidc_sub = userinfo.get("sub")
        else:
            # User is authenticated but has no OAuth session — local account or API key
            _log.debug(
                "No OAuth session found for user %s — OIDC claims unavailable (local auth?)",
                user_id,
            )
    except Exception as e:
        _log.debug("Failed to resolve OIDC claims from OAuth session for user %s: %s", user_id, e)

    ctx = _UserContext(email=email, oidc_sub=oidc_sub, mfa_status=mfa_status, role=role)

    with _cache_lock:
        while len(_cache_data) >= _CACHE_MAX:
            _cache_data.pop(next(iter(_cache_data)))
        _cache_data[user_id] = (ctx, time.monotonic())

    return ctx


class AccessLogMiddleware(BaseHTTPMiddleware):
    """NIS2-compliant access logging middleware for Open WebUI.

    Logs every HTTP request with identity, action classification, outcome,
    and target object reference.  Bypasses Uvicorn access logging.

    ManageEngine Log360 SIEM field mapping (CEF):
      email           → duser       (user identity)
      session_id      → cs3         (session tracking for UEBA)
      correlation_id  → externalId  (cross-system event linking)
      oidc_sub        → cs9         (federated identity)
      mfa             → cs8         (MFA authentication method)
      role            → spriv       (privilege level for escalation detection)
      action          → act         (action performed)
      outcome         → outcome     (success/failure for brute-force detection)
      nis2            → cs10        (NIS2 relevance flag)
      object          → cs4+cs5     (target resource type:id)
      ua              → requestClientApplication (device fingerprint for UEBA)
    """
    
    # Path prefixes for static/immutable assets that have no audit value.
    # These are checked with str.startswith() for performance.
    _STATIC_PREFIXES = (
        "/_app/immutable/",
        "/_app/version.json",
        "/static/",
        "/assets/",
    )

    def __init__(self, app, logger_name: str = "open_webui.access", exclude_paths: list = None):
        super().__init__(app)
        self.logger = logging.getLogger(logger_name)
        # Percorsi da escludere dal logging (es. health checks)
        self.exclude_paths = exclude_paths or ["/health", "/api/health"]
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Salta logging per percorsi esclusi (health checks)
        if request.url.path in self.exclude_paths:
            return await call_next(request)

        # Salta logging per static/immutable assets (no audit value, reduces volume ~70%)
        if request.url.path.startswith(self._STATIC_PREFIXES):
            return await call_next(request)
        
        # Genera o recupera session_id
        session_id = self._get_session_id(request)
        
        # Estrai user UUID dal JWT, poi risolvi email + OIDC claims dal DB (con cache)
        user_uuid = self._extract_user_uuid(request)
        if user_uuid:
            ctx = _resolve_user_context(user_uuid)
            user_display = ctx.email or user_uuid
            oidc_sub = ctx.oidc_sub
            mfa_status = ctx.mfa_status
            role = ctx.role
        else:
            user_display = "anonymous"
            role = None
            # Fast path: try to extract OIDC claims from cookies (pre-login, API keys, etc.)
            oidc_sub, mfa_status = self._get_oidc_claims_from_cookies(request)

        # NIS2: Extract correlation ID from WAF/ADSSPM
        correlation_id = self._get_correlation_id(request)

        # NIS2: Classify action type based on HTTP method + path
        action_type, is_nis2 = _classify_action(request.method, request.url.path)

        # Log360: Extract target object reference from URL path (CEF cs4 + cs5)
        object_type, object_id = _extract_object_ref(request.url.path)

        # Log360 UEBA: Capture User-Agent for anomaly detection
        user_agent = request.headers.get("user-agent", "-")
        # Truncate to avoid log injection; Log360 parses first ~200 chars
        if len(user_agent) > 200:
            user_agent = user_agent[:200] + "…"
        # Sanitise: replace pipe characters to preserve log field delimiters
        user_agent = user_agent.replace("|", "/")

        # Client info: prefer Azure WAF / proxy headers over direct connection
        client_host = self._get_client_ip(request)
        # Only append port if using direct connection (not proxy headers)
        # Proxy headers like X-Forwarded-For may already include port info
        _has_proxy_header = any(
            request.headers.get(h) for h in (
                "X-Azure-ClientIP", "X-Original-Forwarded-For",
                "X-Forwarded-For", "X-Real-IP",
            )
        )
        if _has_proxy_header:
            client_display = client_host
        else:
            client_port = request.client.port if request.client else 0
            client_display = f"{client_host}:{client_port}"
        
        # Timestamp inizio
        start_time = time.time()
        
        # Esegui la richiesta
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as e:
            # Log anche in caso di eccezione
            process_time = time.time() - start_time
            self.logger.error(
                f"email={user_display} | session_id={session_id[:8]} | "
                f"correlation_id={correlation_id or '-'} | "
                f"oidc_sub={oidc_sub or '-'} | mfa={mfa_status or '-'} | "
                f"role={role or '-'} | "
                f"action={action_type} | outcome=error | nis2={'Y' if is_nis2 else 'N'} | "
                f"object={object_type or '-'}:{object_id or '-'} | "
                f"ua={user_agent} | "
                f"{client_display} - "
                f'"{request.method} {request.url.path}" EXCEPTION - '
                f"{str(e)[:100]} | time={process_time:.3f}s"
            )
            raise
        
        # Calcola tempo di elaborazione
        process_time = time.time() - start_time

        # Log360-compatible outcome (success/failure/error/redirect)
        outcome = _outcome_from_status(status_code)

        # Detect failed auth attempts (NIS2 Art.21 — incident detection)
        if action_type in ("AUTH_LOGIN", "AUTH_LOGIN_LDAP", "AUTH_SIGNUP") and status_code >= 400:
            effective_action = f"{action_type}_FAIL"
            effective_nis2 = True
        else:
            effective_action = action_type
            effective_nis2 = is_nis2
        
        # Log NIS2-compliant con tutti i campi richiesti da Log360 SIEM
        # Campi: duser, cs3, externalId, cs9, cs8, spriv, act, outcome, cs10,
        #        cs4+cs5, requestClientApplication, src, request, cs6, cs7
        log_msg = (
            f"email={user_display} | session_id={session_id[:8]} | "
            f"correlation_id={correlation_id or '-'} | "
            f"oidc_sub={oidc_sub or '-'} | mfa={mfa_status or '-'} | "
            f"role={role or '-'} | "
            f"action={effective_action} | outcome={outcome} | nis2={'Y' if effective_nis2 else 'N'} | "
            f"object={object_type or '-'}:{object_id or '-'} | "
            f"ua={user_agent} | "
            f"{client_display} - "
            f'"{request.method} {request.url.path}{("?" + str(request.query_params)) if request.query_params else ""}" {status_code} | '
            f"time={process_time:.3f}s"
        )

        # Use WARNING level for NIS2 security-relevant actions to aid SIEM/alerting
        if effective_nis2:
            self.logger.warning(log_msg)
        else:
            self.logger.info(log_msg)
        
        # Aggiungi header alla risposta (opzionale)
        response.headers["X-Session-ID"] = session_id
        
        return response
    
    def _get_correlation_id(self, request: Request) -> Optional[str]:
        """Extract correlation ID from WAF/ADSSPM/Azure Front Door."""
        return (
            request.headers.get("X-Request-ID")
            or request.headers.get("X-Correlation-ID")
            or request.headers.get("X-Azure-Ref")
            or None
        )

    def _get_client_ip(self, request: Request) -> str:
        """
        Extract real client IP from Azure WAF / reverse proxy headers.

        Priority:
          1. X-Azure-ClientIP    — Azure Front Door / Application Gateway
          2. X-Original-Forwarded-For — original before WAF rewrite
          3. X-Forwarded-For     — standard proxy (first entry = real client)
          4. X-Real-IP           — nginx-style
          5. request.client.host — direct ASGI connection (container-internal)
        """
        for header in (
            "X-Azure-ClientIP",
            "X-Original-Forwarded-For",
            "X-Forwarded-For",
            "X-Real-IP",
        ):
            value = request.headers.get(header)
            if value:
                return value.split(",")[0].strip()

        return request.client.host if request.client else "-"

    def _get_oidc_claims_from_cookies(self, request: Request) -> tuple[Optional[str], Optional[str]]:
        """
        Fast path: extract OIDC sub + MFA from cookies without DB access.
        Used only for unauthenticated requests (no user UUID available).
        Tries oauth_id_token and Authorization Bearer tokens.
        """
        tokens_to_try = []

        oauth_id_token = request.cookies.get("oauth_id_token")
        if oauth_id_token:
            tokens_to_try.append(("oauth_id_token cookie", oauth_id_token))

        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            bearer = auth_header[len("Bearer "):]
            if not bearer.startswith("sk-"):
                tokens_to_try.append(("Bearer token", bearer))

        for source, token_value in tokens_to_try:
            oidc_sub, mfa_status = _decode_id_token_claims(token_value)
            if oidc_sub or mfa_status:
                return oidc_sub, mfa_status

        return None, None

    def _extract_user_uuid(self, request: Request) -> Optional[str]:
        """Extract the user UUID from request.state.user or from the session JWT cookie.

        Returns the UUID string, or None if the user is not authenticated.
        Does NOT do any DB lookups — that is deferred to _resolve_user_context.
        """
        try:
            # Method 1: request.state.user (set by auth middleware upstream)
            if hasattr(request.state, "user") and request.state.user:
                user = request.state.user
                uid = user.get("id") if isinstance(user, dict) else getattr(user, "id", None)
                if uid:
                    return str(uid)

            # Method 2: decode session JWT cookie
            token = request.cookies.get("token")
            if token and pyjwt is not None:
                decoded = pyjwt.decode(token, options={"verify_signature": False})
                uid = decoded.get("id")
                if uid:
                    return str(uid)
        except Exception:
            pass
        return None

    def _get_session_id(self, request: Request) -> str:
        """
        Recupera o genera un session_id
        La session_id dovrebbe essere persistente per tutta la sessione dell'utente
        """
        # PRIORITÀ 1: Cookie 'session_id' (più persistente)
        session_id = request.cookies.get("session_id")
        if session_id:
            return session_id
        
        # PRIORITÀ 2: Cookie 'token' (JWT token come session ID)
        token = request.cookies.get("token")
        if token:
            return hashlib.md5(token.encode()).hexdigest()[:16]
        
        # PRIORITÀ 3: Header 'X-Session-ID'
        session_id = request.headers.get("X-Session-ID")
        if session_id:
            return session_id
        
        # PRIORITÀ 4: Combinazione IP + User-Agent come identificatore temporaneo
        try:
            user_agent = request.headers.get("user-agent", "")
            client_ip = request.client.host if request.client else "unknown"
            composite = f"{client_ip}:{user_agent}"
            return hashlib.md5(composite.encode()).hexdigest()[:16]
        except Exception:
            pass
        
        # FALLBACK: Genera nuovo UUID
        return str(uuid.uuid4())[:16]
    

def setup_access_logging(app, log_level: str = "INFO", exclude_paths: list = None):
    """
    Setup del logging per l'applicazione
    Da chiamare in main.py DOPO aver creato l'app FastAPI
    
    Args:
        app: FastAPI application
        log_level: Livello di logging (INFO, DEBUG, WARNING, ERROR)
        exclude_paths: Lista di percorsi da escludere dal logging (es. ["/health"])
    """
    # Crea logger personalizzato
    logger = logging.getLogger("open_webui.access")
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Handler per stdout (esplicito sys.stdout per Azure Container Apps console)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, log_level.upper()))
    
    # Formato semplice e leggibile
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    logger.propagate = False
    
    # Aggiungi il middleware all'app con percorsi da escludere
    if exclude_paths is None:
        exclude_paths = ["/health", "/api/health"]
    
    app.add_middleware(AccessLogMiddleware, exclude_paths=exclude_paths)
    
    # DISABILITA il logging di Uvicorn per evitare duplicati.
    # Nota: uvicorn emette log sia tramite "uvicorn.access" che tramite
    # "uvicorn.protocols.http.httptools_impl" (il logger del modulo send()).
    # Entrambi devono essere silenziati per evitare righe duplicate.
    for _uv_logger_name in (
        "uvicorn.access",
        "uvicorn.protocols.http.httptools_impl",
        "uvicorn.protocols.http.h11_impl",
    ):
        _uv = logging.getLogger(_uv_logger_name)
        _uv.setLevel(logging.WARNING)
        _uv.propagate = False
    
    logger.info(f"Custom access logging attivato - Percorsi esclusi: {exclude_paths}")

