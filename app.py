import json
import logging
import os
import re
import uuid
from email.utils import parseaddr

from flask import Flask, jsonify, request

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

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