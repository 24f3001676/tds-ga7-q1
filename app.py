import json
import logging
import os
import re
import uuid

from flask import Flask, jsonify, request

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

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


def redact(value):
    """Redact obviously sensitive fields before putting payloads in logs."""
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


def log_request(request_id, data):
    if os.getenv("LOG_PAYLOADS", "1") != "1":
        return

    safe_data = redact(data)

    app.logger.info(
        "release_gate request_id=%s payload=%s",
        request_id,
        json.dumps(safe_data, sort_keys=True, separators=(",", ":")),
    )


def validate_action(action):
    """
    actions/* may use a version tag or an immutable full SHA.
    Third-party actions MUST use a full lowercase 40-character SHA.
    """
    if not isinstance(action, dict):
        return False

    owner = action.get("owner")
    ref = action.get("ref")

    if not isinstance(ref, str):
        return False

    if owner == "actions":
        return bool(VERSION_TAG.fullmatch(ref) or SHA40.fullmatch(ref))

    return bool(SHA40.fullmatch(ref))


@app.get("/")
def health():
    return jsonify({
        "status": "ok",
        "service": "release-gate",
        "endpoint": "/release-gate",
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
    log_request(request_id, data)

    # Invalid JSON is never promotable.
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

    # ---------------------------------------------------------
    # 1. EXACT least-privilege permissions
    # ---------------------------------------------------------
    required_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    if workflow.get("permissions") != required_permissions:
        violations.append("EXCESS_PERMISSION")

    # ---------------------------------------------------------
    # 2. Pull requests must use pull_request, never
    #    pull_request_target
    # ---------------------------------------------------------
    if data.get("event") == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # ---------------------------------------------------------
    # 3. Tests must pass, matrix must be complete,
    #    failFast must be false
    # ---------------------------------------------------------
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # ---------------------------------------------------------
    # 4. Action pinning
    # ---------------------------------------------------------
    actions_list = workflow.get("actions", [])

    if not isinstance(actions_list, list):
        violations.append("MUTABLE_ACTION")
    else:
        for action in actions_list:
            if not validate_action(action):
                violations.append("MUTABLE_ACTION")
                break

    # ---------------------------------------------------------
    # 5. Multi-stage image
    # ---------------------------------------------------------
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # ---------------------------------------------------------
    # 6. Non-root runtime
    # ---------------------------------------------------------
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # ---------------------------------------------------------
    # 7. Safe secret handling
    # ---------------------------------------------------------
    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # ---------------------------------------------------------
    # 8. Zero critical CVEs
    # ---------------------------------------------------------
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # ---------------------------------------------------------
    # 9. Digest-pinned image
    # ---------------------------------------------------------
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # ---------------------------------------------------------
    # 10. Production-specific requirements
    # ---------------------------------------------------------
    if data.get("target") == "production":
        if (
            data.get("event") != "push"
            or data.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # Remove duplicates while keeping deterministic order.
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