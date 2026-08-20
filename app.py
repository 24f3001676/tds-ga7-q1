from flask import Flask, request, jsonify
import re

app = Flask(__name__)

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


@app.post("/release-gate")
def release_gate():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "decision": "block",
            "violations": VIOLATIONS
        })

    workflow = data.get("workflow") or {}
    image = data.get("image") or {}

    violations = []

    # ---------------------------------------------------------
    # 1. Permissions must be EXACTLY:
    # contents: read
    # packages: write
    # id-token: none
    # ---------------------------------------------------------
    permissions = workflow.get("permissions")

    required_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    if permissions != required_permissions:
        violations.append("EXCESS_PERMISSION")

    # ---------------------------------------------------------
    # 2. Pull requests must use pull_request
    # ---------------------------------------------------------
    if data.get("event") == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # ---------------------------------------------------------
    # 3. Tests + complete matrix + failFast false
    # ---------------------------------------------------------
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # ---------------------------------------------------------
    # 4. Action pinning
    #
    # actions/* can use tags.
    # Everyone else must use a 40-character lowercase SHA.
    # ---------------------------------------------------------
    actions_list = workflow.get("actions") or []

    for action in actions_list:
        if not isinstance(action, dict):
            violations.append("MUTABLE_ACTION")
            continue

        owner = action.get("owner")
        ref = action.get("ref")

        if owner == "actions":
            # Version tags are allowed.
            continue

        if not isinstance(ref, str) or not SHA40.fullmatch(ref):
            violations.append("MUTABLE_ACTION")

    # ---------------------------------------------------------
    # 5. Image must be multi-stage
    # ---------------------------------------------------------
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # ---------------------------------------------------------
    # 6. Image must run as non-root
    # ---------------------------------------------------------
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # ---------------------------------------------------------
    # 7. Secret handling:
    # only none or BuildKit are safe
    # ---------------------------------------------------------
    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # ---------------------------------------------------------
    # 8. Zero critical vulnerabilities
    # ---------------------------------------------------------
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # ---------------------------------------------------------
    # 9. Image must be digest pinned
    # ---------------------------------------------------------
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # ---------------------------------------------------------
    # 10. Production requirements
    # ---------------------------------------------------------
    if data.get("target") == "production":
        if (
            data.get("event") != "push"
            or data.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # Remove duplicates while preserving deterministic order.
    violations = list(dict.fromkeys(violations))

    decision = "promote" if not violations else "block"

    return jsonify({
        "decision": decision,
        "violations": violations
    })


@app.get("/")
def health():
    return "release-gate ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)