from fastapi import FastAPI
from typing import Any

app = FastAPI()


@app.get("/")
def root():
    return {"status": "ok"}


@app.post("/release-gate")
def release_gate(payload: dict[str, Any]):
    violations = []

    workflow = payload.get("workflow", {})
    image = payload.get("image", {})

    # ---------------------------------------------------------
    # 1. Permissions
    # ---------------------------------------------------------
    permissions = workflow.get("permissions", {})

    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    if permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # ---------------------------------------------------------
    # 2. Pull request trigger
    # ---------------------------------------------------------
    event = payload.get("event")
    trigger = workflow.get("trigger")

    if event == "pull_request" and trigger != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")

    # ---------------------------------------------------------
    # 3. Tests
    # ---------------------------------------------------------
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # ---------------------------------------------------------
    # 4. GitHub Actions pinning
    # ---------------------------------------------------------
    actions = workflow.get("actions", [])

    for action in actions:
        owner = action.get("owner")
        ref = action.get("ref", "")

        # Official actions owned by "actions" may use tags.
        if owner == "actions":
            continue

        # Every third-party action must use a
        # 40-character lowercase hexadecimal SHA.
        if not (
            isinstance(ref, str)
            and len(ref) == 40
            and all(c in "0123456789abcdef" for c in ref)
        ):
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
    # 7. Build secret
    # ---------------------------------------------------------
    secret_mode = image.get("secretMode")

    if secret_mode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # ---------------------------------------------------------
    # 8. Critical vulnerabilities
    # ---------------------------------------------------------
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # ---------------------------------------------------------
    # 9. Image digest
    # ---------------------------------------------------------
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # ---------------------------------------------------------
    # 10. Production requirements
    # ---------------------------------------------------------
    target = payload.get("target")
    
    if target == "production":
        if event != "push" or payload.get("ref") != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # ---------------------------------------------------------
    # Final decision
    # ---------------------------------------------------------
    decision = "promote" if not violations else "block"

    return {
        "decision": decision,
        "violations": violations
    }