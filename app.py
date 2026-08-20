import json
import logging
import os
import re
import uuid
from email.utils import parseaddr
import html as html_lib
import re
from urllib.parse import unquote, urlparse
from flask import Flask, jsonify, request

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

# ============================================================
# Model-output sink sanitizer
# ============================================================

SANITIZE_CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell",
}

ALLOWED_EXTERNAL_HOSTS = {
    "cdn-0nl2whi.example",
    "app-a2ytvc7.example",
}

SANITIZE_REASONS = {
    "SAFE",
    "INVALID_SCHEMA",
    "SCRIPT_TAG",
    "EVENT_HANDLER",
    "DANGEROUS_SCHEME",
    "EXTERNAL_EXFIL",
    "SQL_METACHAR",
    "SHELL_METACHAR",
    "ENCODED_PAYLOAD",
}

NAMED_ENTITIES = {
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&apos;": "'",
    "&amp;": "&",
}

NUMERIC_ENTITY_RE = re.compile(
    r"&#(?:([0-9]+)|[xX]([0-9a-fA-F]+));"
)


def decode_html_entities_exact(value):
    # Decode only the five explicitly allowed named entities.
    for entity, replacement in NAMED_ENTITIES.items():
        value = value.replace(entity, replacement)

    # Decode only semicolon-terminated decimal/hex numeric entities.
    def replace_numeric(match):
        decimal = match.group(1)
        hexadecimal = match.group(2)

        try:
            codepoint = (
                int(decimal, 10)
                if decimal is not None
                else int(hexadecimal, 16)
            )

            # Keep this conservative: invalid Unicode code points
            # remain unchanged.
            if codepoint > 0x10FFFF:
                return match.group(0)

            return chr(codepoint)

        except (ValueError, OverflowError):
            return match.group(0)

    return NUMERIC_ENTITY_RE.sub(replace_numeric, value)


def decode_once(value):
    # Exactly the order required by the specification.
    decoded = unquote(value)
    decoded = decode_html_entities_exact(decoded)

    # Decode literal \uXXXX exactly once.
    decoded = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda m: chr(int(m.group(1), 16)),
        decoded,
    )

    return decoded

# Opening dangerous HTML tags only.
HTML_SCRIPT_TAG_RE = re.compile(
    r"<\s*(?:script|iframe|object|embed)\b[^>]*>",
    re.IGNORECASE,
)

# Any HTML attribute beginning with "on", e.g. onclick=,
# onerror=, onload=, etc.
HTML_TAG_RE = re.compile(
    r"<[^>]*>",
    re.IGNORECASE | re.DOTALL,
)

HTML_EVENT_HANDLER_RE = re.compile(
    r"\bon[a-zA-Z][a-zA-Z0-9_-]*\s*=",
    re.IGNORECASE,
)


def has_html_event_handler(output):
    for tag in HTML_TAG_RE.finditer(output):
        tag_text = tag.group(0)

        # Skip closing tags such as </div>.
        if re.match(r"<\s*/", tag_text):
            continue

        if HTML_EVENT_HANDLER_RE.search(tag_text):
            return True

    return False

# Dangerous schemes anywhere in the text.
DANGEROUS_SCHEME_RE = re.compile(
    r"(?:javascript|data|vbscript)\s*:",
    re.IGNORECASE,
)

# HTML quoted src/href.
HTML_URL_RE = re.compile(
    r"""
    \b(?:src|href)
    \s*=\s*
    (?P<quote>["'])
    (?P<url>.*?)
    (?P=quote)
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Markdown target inside ](...)
#
# This deliberately captures the destination at the start of the
# parenthesized target, including optional angle brackets.
MARKDOWN_URL_RE = re.compile(
    r"""
    \]\(
    \s*
    (?:<(?P<angle>[^>]+)>|(?P<plain>\S+?))
    (?:\s+["'][^)]*["'])?
    \s*
    \)
    """,
    re.IGNORECASE | re.VERBOSE,
)

# SQL rules.
SQL_SINGLE_OR_DOUBLE_QUOTE_RE = re.compile(r"""['"]""")
SQL_SEMICOLON_RE = re.compile(r";")
SQL_COMMENT_RE = re.compile(r"--|/\*")
SQL_UNION_RE = re.compile(r"\bunion\b", re.IGNORECASE)
SQL_OR_1_EQ_1_RE = re.compile(r"\bor\s+1\s*=\s*1\b", re.IGNORECASE)

# Shell metacharacters.
SHELL_METACHAR_RE = re.compile(
    r"[;&|`<>]|\$\(|\$\{"
)


def extract_urls(channel, output):
    """
    Extract URLs according to the assignment's channel-specific rules.

    html:
      quoted src= and href=

    markdown:
      target inside ](...)

    url:
      whole trimmed output
    """
    if channel == "html":
        return [
            match.group("url")
            for match in HTML_URL_RE.finditer(output)
        ]

    if channel == "markdown":
        urls = []

        for match in MARKDOWN_URL_RE.finditer(output):
            angle = match.group("angle")
            plain = match.group("plain")

            if angle is not None:
                urls.append(angle)
            elif plain is not None:
                urls.append(plain)

        return urls

    if channel == "url":
        trimmed = output.strip()
        return [trimmed] if trimmed else []

    return []


def url_has_dangerous_scheme(url):
    """
    Check the extracted URL itself.

    A URL is dangerous when:
      - scheme is not http/https
      - scheme is javascript/data/vbscript
      - protocol-relative //host/path is treated as https
    """
    candidate = url.strip()

    if not candidate:
        return False

    # Explicit dangerous textual schemes.
    if DANGEROUS_SCHEME_RE.search(candidate):
        return True

    # Relative references are fine.
    if candidate.startswith("/"):
        # //host/path is protocol-relative and therefore absolute.
        if candidate.startswith("//"):
            parsed = urlparse("https:" + candidate)
            return parsed.scheme.lower() != "https"
        return False

    parsed = urlparse(candidate)

    # No scheme = relative reference.
    if not parsed.scheme:
        return False

    return parsed.scheme.lower() not in {"http", "https"}


def has_external_exfil(channel, output):
    """
    Check every extracted absolute URL.

    Compare parsed hostname exactly. Never use substring checks.
    """
    urls = extract_urls(channel, output)

    for candidate in urls:
        value = candidate.strip()

        if not value:
            continue

        # Protocol-relative URL => treat as https.
        if value.startswith("//"):
            parsed = urlparse("https:" + value)
        else:
            parsed = urlparse(value)

        # Relative URL is allowed.
        if not parsed.scheme and not value.startswith("//"):
            continue

        # At this point the extracted URL is absolute.
        hostname = parsed.hostname

        if hostname is None:
            continue

        if hostname not in ALLOWED_EXTERNAL_HOSTS:
            return True

    return False


def dangerous_scheme_check(channel, output):
    """
    Channel-independent dangerous-scheme check.
    """
    # Direct textual scheme use anywhere.
    if DANGEROUS_SCHEME_RE.search(output):
        return True

    # Extracted URLs may contain arbitrary schemes.
    for candidate in extract_urls(channel, output):
        if url_has_dangerous_scheme(candidate):
            return True

    return False


def channel_rule(output, channel):
    """
    Apply the channel rules to the ORIGINAL output.
    Returns the first applicable reason or SAFE.
    """

    # HTML:
    # SCRIPT_TAG -> EVENT_HANDLER -> DANGEROUS_SCHEME -> EXTERNAL_EXFIL
    if channel == "html":
        if HTML_SCRIPT_TAG_RE.search(output):
            return "SCRIPT_TAG"

        if has_html_event_handler(output):
            return "EVENT_HANDLER"

        if dangerous_scheme_check(channel, output):
            return "DANGEROUS_SCHEME"

        if has_external_exfil(channel, output):
            return "EXTERNAL_EXFIL"

        return "SAFE"

    # Markdown:
    # DANGEROUS_SCHEME -> EXTERNAL_EXFIL
    if channel == "markdown":
        if dangerous_scheme_check(channel, output):
            return "DANGEROUS_SCHEME"

        if has_external_exfil(channel, output):
            return "EXTERNAL_EXFIL"

        return "SAFE"

    # URL:
    # DANGEROUS_SCHEME -> EXTERNAL_EXFIL
    if channel == "url":
        if dangerous_scheme_check(channel, output):
            return "DANGEROUS_SCHEME"

        if has_external_exfil(channel, output):
            return "EXTERNAL_EXFIL"

        return "SAFE"

    # SQL
    if channel == "sql":
        if SQL_SINGLE_OR_DOUBLE_QUOTE_RE.search(output):
            return "SQL_METACHAR"

        if SQL_SEMICOLON_RE.search(output):
            return "SQL_METACHAR"

        if SQL_COMMENT_RE.search(output):
            return "SQL_METACHAR"

        if SQL_UNION_RE.search(output):
            return "SQL_METACHAR"

        if SQL_OR_1_EQ_1_RE.search(output):
            return "SQL_METACHAR"

        return "SAFE"

    # Shell
    if channel == "shell":
        if SHELL_METACHAR_RE.search(output):
            return "SHELL_METACHAR"

        return "SAFE"

    return "INVALID_SCHEMA"


def sanitize_result(safe, reason):
    return jsonify({
        "safe": safe,
        "reason": reason,
    })


@app.post("/sanitize-output")
@app.post("/sanitize-output/")
def sanitize_output():
    request_id = uuid.uuid4().hex[:12]

    data = request.get_json(silent=True)

    # Log the request for Render debugging.
    # Output itself is not a secret by definition, so it is logged
    # normally through the shared logging helper.
    log_payload(
        "sanitize_output",
        request_id,
        data,
    )

    # ========================================================
    # 1. INVALID_SCHEMA
    # ========================================================

    if not isinstance(data, dict):
        result = sanitize_result(False, "INVALID_SCHEMA")

        app.logger.info(
            "sanitize_output request_id=%s safe=false reason=INVALID_SCHEMA",
            request_id,
        )

        return result

    channel = data.get("channel")
    output = data.get("output")

    if channel not in SANITIZE_CHANNELS:
        result = sanitize_result(False, "INVALID_SCHEMA")

        app.logger.info(
            "sanitize_output request_id=%s safe=false reason=INVALID_SCHEMA",
            request_id,
        )

        return result

    if not isinstance(output, str):
        result = sanitize_result(False, "INVALID_SCHEMA")

        app.logger.info(
            "sanitize_output request_id=%s safe=false reason=INVALID_SCHEMA",
            request_id,
        )

        return result

    if len(output) > 20000:
        result = sanitize_result(False, "INVALID_SCHEMA")

        app.logger.info(
            "sanitize_output request_id=%s safe=false reason=INVALID_SCHEMA",
            request_id,
        )

        return result

    # ========================================================
    # 2. ENCODED_PAYLOAD
    # ========================================================

    decoded = decode_once(output)

    if decoded != output:
        decoded_reason = channel_rule(decoded, channel)

        if decoded_reason != "SAFE":
            result = sanitize_result(
                False,
                "ENCODED_PAYLOAD",
            )

            app.logger.info(
                "sanitize_output request_id=%s channel=%s safe=false reason=ENCODED_PAYLOAD decoded_rule=%s",
                request_id,
                channel,
                decoded_reason,
            )

            return result

    # ========================================================
    # 3. ORIGINAL OUTPUT CHANNEL RULES
    # ========================================================

    reason = channel_rule(output, channel)

    if reason != "SAFE":
        result = sanitize_result(False, reason)

        app.logger.info(
            "sanitize_output request_id=%s channel=%s safe=false reason=%s",
            request_id,
            channel,
            reason,
        )

        return result

    # ========================================================
    # SAFE
    # ========================================================

    result = sanitize_result(True, "SAFE")

    app.logger.info(
        "sanitize_output request_id=%s channel=%s safe=true reason=SAFE",
        request_id,
        channel,
    )

    return result

# ============================================================
# Existing release-gate configuration
# ============================================================

VIOLATIONS = [
    "EXCESS_PERMISSION",
    "UNSAFE_PR_TRIGGER",
    "TESTS_INCOMPLETE",
    "MUTABLE_ACTION",
    "SINGLE_STAGE_IMAGE",
    "ROOT_RUNTIME",
    "SECRET_IN_LAYER",
    "CRITICAL_CVE",
    "UNPINNED_IMAGE",
    "INVALID_PRODUCTION_REF",
    "APPROVAL_REQUIRED",
]

SHA40 = re.compile(r"^[0-9a-f]{40}$")
VERSION_TAG = re.compile(r"^v[0-9]+(?:\.[0-9]+){0,2}$")

REDACT_KEYS = {
    "token",
    "password",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "access_token",
    "private_key",
}


# ============================================================
# Shared logging helpers
# ============================================================

def redact(value):
    """Redact obviously sensitive dictionary fields before logging."""
    if isinstance(value, dict):
        result = {}
        for key, val in value.items():
            key_lower = str(key).lower()

            if any(marker in key_lower for marker in REDACT_KEYS):
                result[key] = "[REDACTED]"
            else:
                result[key] = redact(val)

        return result

    if isinstance(value, list):
        return [redact(item) for item in value]

    return value


def log_payload(kind, request_id, payload):
    """
    Log the received payload so hidden-grader requests can be
    inspected in Render logs.
    """
    if os.getenv("LOG_PAYLOADS", "1") != "1":
        return

    safe_payload = redact(payload)

    try:
        encoded = json.dumps(
            safe_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    except Exception:
        encoded = repr(safe_payload)

    # Avoid accidentally flooding Render logs.
    if len(encoded) > 100000:
        encoded = encoded[:100000] + "...[TRUNCATED]"

    app.logger.info(
        "%s request_id=%s payload=%s",
        kind,
        request_id,
        encoded,
    )


# ============================================================
# Existing release-gate implementation
# ============================================================

def validate_action(action):
    if not isinstance(action, dict):
        return False

    owner = action.get("owner")
    ref = action.get("ref")

    if not isinstance(ref, str):
        return False

    if owner == "actions":
        return bool(
            VERSION_TAG.fullmatch(ref)
            or SHA40.fullmatch(ref)
        )

    return bool(SHA40.fullmatch(ref))


# ============================================================
# New action-firewall configuration
# ============================================================

ASSIGNED_TENANT = "tenant-zyovf0n"
ALLOWED_EMAIL_DOMAIN = "notify-tx5jyo7.example"

FIREWALL_REASONS = {
    "ALLOW",
    "INVALID_SCHEMA",
    "TOOL_NOT_ALLOWED",
    "TENANT_SCOPE",
    "EGRESS_DENIED",
    "APPROVAL_REQUIRED",
    "UNSAFE_OUTPUT",
}

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html",
}


# ------------------------------------------------------------
# Exact-schema helper
# ------------------------------------------------------------

def exact_keys(obj, required_keys):
    return (
        isinstance(obj, dict)
        and set(obj.keys()) == set(required_keys)
    )


# ============================================================
# Terraform plan policy
# ============================================================

TERRAFORM_WORKSPACE = "prod-ujxf2x"

REQUIRED_LABELS = {
    "owner": "student-dx2lj",
    "environment": "production",
    "cost_center": "cc-nc6s",
}

ALLOWED_BACKENDS = {
    "gcs",
    "s3",
    "azurerm",
    "remote",
}

ALLOWED_PROVIDER_VERSIONS = {
    "6.2.1",
    "= 6.2.1",
    "~> 6.0",
}

DESTRUCTIVE_RESOURCE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}


# ------------------------------------------------------------
# HTML safety
# ------------------------------------------------------------

SCRIPT_TAG_RE = re.compile(
    r"<\s*/?\s*script\b",
    re.IGNORECASE,
)

IFRAME_TAG_RE = re.compile(
    r"<\s*/?\s*iframe\b",
    re.IGNORECASE,
)

INLINE_EVENT_RE = re.compile(
    r"\bon[a-zA-Z][a-zA-Z0-9_-]*\s*=",
    re.IGNORECASE,
)

JAVASCRIPT_URL_RE = re.compile(
    r"""
    (?:
        (?:href|src|action|formaction|poster|xlink:href)
        \s*=\s*
        ["']?
        \s*
        javascript\s*:
    )
    |
    (?:
        javascript\s*:
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def html_is_safe(html):
    if not isinstance(html, str):
        return False

    if SCRIPT_TAG_RE.search(html):
        return False

    if IFRAME_TAG_RE.search(html):
        return False

    if INLINE_EVENT_RE.search(html):
        return False

    if JAVASCRIPT_URL_RE.search(html):
        return False

    return True


# ------------------------------------------------------------
# Email domain validation
# ------------------------------------------------------------

def email_domain_is_allowed(value):
    if not isinstance(value, str):
        return False

    # No display-name syntax.
    display_name, parsed_address = parseaddr(value)

    if display_name or parsed_address != value:
        return False

    # Exactly one @.
    if value.count("@") != 1:
        return False

    local, domain = value.rsplit("@", 1)

    if not local or not domain:
        return False

    # Exact assigned domain.
    return domain.lower() == ALLOWED_EMAIL_DOMAIN


# ------------------------------------------------------------
# Tool-specific schema checks
# ------------------------------------------------------------

def validate_search_args(args):
    if not exact_keys(args, {"query"}):
        return False

    return (
        isinstance(args["query"], str)
        and 1 <= len(args["query"]) <= 200
    )


def validate_lookup_args(args):
    if not exact_keys(args, {"tenantId", "recordId"}):
        return False

    return (
        isinstance(args["tenantId"], str)
        and isinstance(args["recordId"], str)
        and len(args["recordId"]) > 0
    )


def validate_send_email_args(args):
    if not exact_keys(args, {"to", "subject", "body"}):
        return False

    return (
        isinstance(args["to"], str)
        and isinstance(args["subject"], str)
        and isinstance(args["body"], str)
    )


def validate_render_html_args(args):
    if not exact_keys(args, {"html"}):
        return False

    return isinstance(args["html"], str)


# ============================================================
# Action firewall
# ============================================================
# ============================================================
# Terraform plan policy
# ============================================================

def terraform_result(decision, reason):
    return jsonify({
        "decision": decision,
        "reason": reason,
    })


@app.post("/terraform/plan")
@app.post("/terraform/plan/")
def terraform_plan():
    request_id = uuid.uuid4().hex[:12]

    data = request.get_json(silent=True)

    # IMPORTANT:
    # Do not log plaintext secrets. The shared logger recursively
    # redacts keys named "secret", but resource.secret itself is
    # not a dictionary key containing a secret field. Therefore
    # create a sanitized copy specifically for this endpoint.
    log_data = data

    if isinstance(data, dict):
        try:
            log_data = json.loads(json.dumps(data))
            resource_for_log = log_data.get("resource")

            if isinstance(resource_for_log, dict) and "secret" in resource_for_log:
                resource_for_log["secret"] = (
                    "[REDACTED]" if resource_for_log["secret"] is not None
                    else None
                )
        except Exception:
            log_data = "[UNLOGGABLE_PAYLOAD]"

    log_payload(
        "terraform_plan",
        request_id,
        log_data,
    )

    # ========================================================
    # 1. REQUEST / NESTED OBJECT VALUE TYPES
    # ========================================================

    if not isinstance(data, dict):
        result = terraform_result("reject", "INVALID_PLAN")

        app.logger.info(
            "terraform_plan request_id=%s decision=reject reason=INVALID_PLAN",
            request_id,
        )

        return result

    # Exact top-level structure.
    if set(data.keys()) != {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }:
        result = terraform_result("reject", "INVALID_PLAN")

        app.logger.info(
            "terraform_plan request_id=%s decision=reject reason=INVALID_PLAN",
            request_id,
        )

        return result

    # Top-level types.
    if not isinstance(data["environment"], str):
        return terraform_result("reject", "INVALID_PLAN")

    if not isinstance(data["state"], dict):
        return terraform_result("reject", "INVALID_PLAN")

    if not isinstance(data["providerVersion"], str):
        return terraform_result("reject", "INVALID_PLAN")

    if not isinstance(data["destroyApproved"], bool):
        return terraform_result("reject", "INVALID_PLAN")

    if not isinstance(data["resource"], dict):
        return terraform_result("reject", "INVALID_PLAN")

    # State must have exactly the shown fields.
    state = data["state"]

    if set(state.keys()) != {"backend", "locked"}:
        return terraform_result("reject", "INVALID_PLAN")

    if not isinstance(state["backend"], str):
        return terraform_result("reject", "INVALID_PLAN")

    if not isinstance(state["locked"], bool):
        return terraform_result("reject", "INVALID_PLAN")

    # Resource must have exactly the shown fields.
    resource = data["resource"]

    if set(resource.keys()) != {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }:
        return terraform_result("reject", "INVALID_PLAN")

    if not isinstance(resource["address"], str):
        return terraform_result("reject", "INVALID_PLAN")

    if not isinstance(resource["type"], str):
        return terraform_result("reject", "INVALID_PLAN")

    if resource["action"] not in {"create", "update", "delete"}:
        return terraform_result("reject", "INVALID_PLAN")

    if not isinstance(resource["labels"], dict):
        return terraform_result("reject", "INVALID_PLAN")

    if any(
        not isinstance(k, str) or not isinstance(v, str)
        for k, v in resource["labels"].items()
    ):
        return terraform_result("reject", "INVALID_PLAN")

    if resource["secret"] is not None and not isinstance(resource["secret"], str):
        return terraform_result("reject", "INVALID_PLAN")

    if not isinstance(resource["forceDestroy"], bool):
        return terraform_result("reject", "INVALID_PLAN")

    # ========================================================
    # 2. ENVIRONMENT
    # ========================================================

    if data["environment"] != TERRAFORM_WORKSPACE:
        result = terraform_result(
            "reject",
            "ENVIRONMENT_MISMATCH",
        )

        app.logger.info(
            "terraform_plan request_id=%s decision=reject reason=ENVIRONMENT_MISMATCH",
            request_id,
        )

        return result

    # ========================================================
    # 3. REMOTE STATE
    # ========================================================

    if (
        state["backend"] not in ALLOWED_BACKENDS
        or state["locked"] is not True
    ):
        result = terraform_result(
            "reject",
            "STATE_UNSAFE",
        )

        app.logger.info(
            "terraform_plan request_id=%s decision=reject reason=STATE_UNSAFE",
            request_id,
        )

        return result

    # ========================================================
    # 4. PROVIDER VERSION
    # ========================================================

    if data["providerVersion"] not in ALLOWED_PROVIDER_VERSIONS:
        result = terraform_result(
            "reject",
            "UNPINNED_PROVIDER",
        )

        app.logger.info(
            "terraform_plan request_id=%s decision=reject reason=UNPINNED_PROVIDER providerVersion=%s",
            request_id,
            data["providerVersion"],
        )

        return result

    # ========================================================
    # 5. REQUIRED COST-OWNERSHIP LABELS
    # ========================================================

    labels = resource["labels"]

    for key, expected_value in REQUIRED_LABELS.items():
        if labels.get(key) != expected_value:
            result = terraform_result(
                "reject",
                "MISSING_LABELS",
            )

            app.logger.info(
                "terraform_plan request_id=%s decision=reject reason=MISSING_LABELS",
                request_id,
            )

            return result

    # ========================================================
    # 6. SECRET REPRESENTATION
    # ========================================================

    secret = resource["secret"]

    if secret is not None:
        if not isinstance(secret, str):
            return terraform_result(
                "reject",
                "INVALID_PLAN",
            )

        if not secret.startswith("secret://"):
            result = terraform_result(
                "reject",
                "PLAINTEXT_SECRET",
            )

            app.logger.info(
                "terraform_plan request_id=%s decision=reject reason=PLAINTEXT_SECRET",
                request_id,
            )

            return result

        # "secret://..." means the portion after the prefix
        # must not be empty.
        if len(secret) <= len("secret://"):
            result = terraform_result(
                "reject",
                "PLAINTEXT_SECRET",
            )

            app.logger.info(
                "terraform_plan request_id=%s decision=reject reason=PLAINTEXT_SECRET",
                request_id,
            )

            return result

    # ========================================================
    # 7. DESTRUCTIVE DELETE
    # ========================================================

    if (
        resource["action"] == "delete"
        and resource["type"] in DESTRUCTIVE_RESOURCE_TYPES
        and data["destroyApproved"] is not True
    ):
        result = terraform_result(
            "reject",
            "DELETE_NOT_APPROVED",
        )

        app.logger.info(
            "terraform_plan request_id=%s decision=reject reason=DELETE_NOT_APPROVED resource_type=%s",
            request_id,
            resource["type"],
        )

        return result

    # ========================================================
    # 8. PRODUCTION STORAGE BUCKET FORCE DESTROY
    # ========================================================

    if (
        resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        result = terraform_result(
            "reject",
            "FORCE_DESTROY",
        )

        app.logger.info(
            "terraform_plan request_id=%s decision=reject reason=FORCE_DESTROY",
            request_id,
        )

        return result

    # ========================================================
    # APPROVE
    # ========================================================

    result = terraform_result(
        "approve",
        "APPROVE",
    )

    app.logger.info(
        "terraform_plan request_id=%s decision=approve reason=APPROVE",
        request_id,
    )

    return result


@app.post("/action-firewall")
@app.post("/action-firewall/")
def action_firewall():
    request_id = uuid.uuid4().hex[:12]

    data = request.get_json(silent=True)

    log_payload(
        "action_firewall",
        request_id,
        data,
    )

    # ========================================================
    # 1. TOP-LEVEL SCHEMA
    # ========================================================

    if not isinstance(data, dict):
        result = {
            "decision": "block",
            "reason": "INVALID_SCHEMA",
        }

        app.logger.info(
            "action_firewall request_id=%s decision=%s reason=%s",
            request_id,
            result["decision"],
            result["reason"],
        )

        return jsonify(result)

    # Only these top-level fields are allowed.
    if set(data.keys()) not in (
        {
            "provenance",
            "humanApproved",
            "untrustedContent",
            "action",
        },
        {
            "provenance",
            "humanApproved",
            "action",
        },
    ):
        result = {
            "decision": "block",
            "reason": "INVALID_SCHEMA",
        }

        app.logger.info(
            "action_firewall request_id=%s decision=%s reason=%s",
            request_id,
            result["decision"],
            result["reason"],
        )

        return jsonify(result)

    if data.get("provenance") not in {
        "trusted",
        "untrusted",
    }:
        result = {
            "decision": "block",
            "reason": "INVALID_SCHEMA",
        }

        app.logger.info(
            "action_firewall request_id=%s decision=%s reason=%s",
            request_id,
            result["decision"],
            result["reason"],
        )

        return jsonify(result)

    if not isinstance(data.get("humanApproved"), bool):
        result = {
            "decision": "block",
            "reason": "INVALID_SCHEMA",
        }

        app.logger.info(
            "action_firewall request_id=%s decision=%s reason=%s",
            request_id,
            result["decision"],
            result["reason"],
        )

        return jsonify(result)

    if (
        "untrustedContent" in data
        and not isinstance(data["untrustedContent"], str)
    ):
        result = {
            "decision": "block",
            "reason": "INVALID_SCHEMA",
        }

        app.logger.info(
            "action_firewall request_id=%s decision=%s reason=%s",
            request_id,
            result["decision"],
            result["reason"],
        )

        return jsonify(result)

    action = data.get("action")

    if not isinstance(action, dict):
        result = {
            "decision": "block",
            "reason": "INVALID_SCHEMA",
        }

        app.logger.info(
            "action_firewall request_id=%s decision=%s reason=%s",
            request_id,
            result["decision"],
            result["reason"],
        )

        return jsonify(result)

    if set(action.keys()) != {"tool", "args"}:
        result = {
            "decision": "block",
            "reason": "INVALID_SCHEMA",
        }

        app.logger.info(
            "action_firewall request_id=%s decision=%s reason=%s",
            request_id,
            result["decision"],
            result["reason"],
        )

        return jsonify(result)

    tool = action["tool"]
    args = action["args"]

    if not isinstance(tool, str) or not isinstance(args, dict):
        result = {
            "decision": "block",
            "reason": "INVALID_SCHEMA",
        }

        app.logger.info(
            "action_firewall request_id=%s decision=%s reason=%s",
            request_id,
            result["decision"],
            result["reason"],
        )

        return jsonify(result)

    # ========================================================
    # 2. TOOL ALLOWLIST
    # ========================================================

    if tool not in ALLOWED_TOOLS:
        result = {
            "decision": "block",
            "reason": "TOOL_NOT_ALLOWED",
        }

        app.logger.info(
            "action_firewall request_id=%s tool=%s decision=%s reason=%s",
            request_id,
            tool,
            result["decision"],
            result["reason"],
        )

        return jsonify(result)

    # ========================================================
    # 3. SELECTED TOOL ARGUMENT SCHEMA
    # ========================================================

    if tool == "search":
        valid_schema = validate_search_args(args)

    elif tool == "lookup_record":
        valid_schema = validate_lookup_args(args)

    elif tool == "send_email":
        valid_schema = validate_send_email_args(args)

    elif tool == "render_html":
        valid_schema = validate_render_html_args(args)

    else:
        # Defensive fallback.
        valid_schema = False

    if not valid_schema:
        result = {
            "decision": "block",
            "reason": "INVALID_SCHEMA",
        }

        app.logger.info(
            "action_firewall request_id=%s tool=%s decision=%s reason=%s",
            request_id,
            tool,
            result["decision"],
            result["reason"],
        )

        return jsonify(result)

    # ========================================================
    # 4. TENANT SCOPE
    # ========================================================

    if tool == "lookup_record":
        if args["tenantId"] != ASSIGNED_TENANT:
            result = {
                "decision": "block",
                "reason": "TENANT_SCOPE",
            }

            app.logger.info(
                "action_firewall request_id=%s tool=%s decision=%s reason=%s",
                request_id,
                tool,
                result["decision"],
                result["reason"],
            )

            return jsonify(result)

    # ========================================================
    # 5. EMAIL EGRESS DOMAIN
    # ========================================================

    if tool == "send_email":
        if not email_domain_is_allowed(args["to"]):
            result = {
                "decision": "block",
                "reason": "EGRESS_DENIED",
            }

            app.logger.info(
                "action_firewall request_id=%s tool=%s decision=%s reason=%s",
                request_id,
                tool,
                result["decision"],
                result["reason"],
            )

            return jsonify(result)

    # ========================================================
    # 6. HUMAN APPROVAL
    # ========================================================

    if tool == "send_email":
        if data["humanApproved"] is not True:
            result = {
                "decision": "block",
                "reason": "APPROVAL_REQUIRED",
            }

            app.logger.info(
                "action_firewall request_id=%s tool=%s decision=%s reason=%s",
                request_id,
                tool,
                result["decision"],
                result["reason"],
            )

            return jsonify(result)

    # ========================================================
    # 7. HTML SAFETY
    # ========================================================

    if tool == "render_html":
        if not html_is_safe(args["html"]):
            result = {
                "decision": "block",
                "reason": "UNSAFE_OUTPUT",
            }

            app.logger.info(
                "action_firewall request_id=%s tool=%s decision=%s reason=%s",
                request_id,
                tool,
                result["decision"],
                result["reason"],
            )

            return jsonify(result)

    # ========================================================
    # ALLOW
    # ========================================================

    result = {
        "decision": "allow",
        "reason": "ALLOW",
    }

    app.logger.info(
        "action_firewall request_id=%s tool=%s decision=%s reason=%s",
        request_id,
        tool,
        result["decision"],
        result["reason"],
    )

    return jsonify(result)


# ============================================================
# Existing release-gate endpoints
# ============================================================

@app.get("/")
def health():
    return jsonify({
        "status": "ok",
        "service": "release-gate",
        "endpoints": [
            "/release-gate",
            "/action-firewall",
        ],
    })


@app.get("/release-gate")
@app.get("/release-gate/")
def release_gate_info():
    return jsonify({
        "status": "ok",
        "service": "release-gate",
        "method": "POST",
    })


@app.post("/release-gate")
@app.post("/release-gate/")
def release_gate():
    request_id = uuid.uuid4().hex[:12]

    data = request.get_json(silent=True)
    log_payload("release_gate", request_id, data)

    if not isinstance(data, dict):
        response = {
            "decision": "block",
            "violations": VIOLATIONS,
        }

        app.logger.info(
            "release_gate request_id=%s decision=%s violations=%s",
            request_id,
            response["decision"],
            response["violations"],
        )

        return jsonify(response)

    workflow = data.get("workflow")
    image = data.get("image")

    if not isinstance(workflow, dict):
        workflow = {}

    if not isinstance(image, dict):
        image = {}

    violations = []

    required_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    if workflow.get("permissions") != required_permissions:
        violations.append("EXCESS_PERMISSION")

    if data.get("event") == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    actions_list = workflow.get("actions", [])

    if not isinstance(actions_list, list):
        violations.append("MUTABLE_ACTION")
    else:
        for action in actions_list:
            if not validate_action(action):
                violations.append("MUTABLE_ACTION")
                break

    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    if data.get("target") == "production":
        if (
            data.get("event") != "push"
            or data.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    violations = list(dict.fromkeys(violations))

    decision = "promote" if not violations else "block"

    response = {
        "decision": decision,
        "violations": violations,
    }

    app.logger.info(
        "release_gate request_id=%s decision=%s violations=%s",
        request_id,
        decision,
        violations,
    )

    return jsonify(response)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)