"""
Fabric Variable Library – Update Variable Value via REST API
=============================================================
This script modifies a variable's value in a specific Value Set of a
Microsoft Fabric Variable Library, using only friendly names as input.

Parameters (passed via command-line arguments):
  1. Fabric Workspace Name
  2. Fabric Variable Library Name
  3. Variable Name
  4. Value Set Name            (use "Default" to update the default value in variables.json)
  5. New Value

Prerequisites:
  pip install azure-identity requests

Authentication:
  Uses a Service Principal (client_id, tenant_id, client_secret) via
  ClientSecretCredential from azure-identity.
"""

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

import requests
import yaml
from azure.identity import ClientSecretCredential

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
FABRIC_API_BASE = "https://api.fabric.microsoft.com/v1"
FABRIC_SCOPE = "https://api.fabric.microsoft.com/.default"
LRO_POLL_INTERVAL_SECONDS = 2
LRO_MAX_WAIT_SECONDS = 300


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
def get_access_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Obtain a bearer token for the Fabric API using a Service Principal."""
    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )
    token = credential.get_token(FABRIC_SCOPE)
    return token.token


def build_headers(token: str) -> dict:
    """Return standard request headers."""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


# ---------------------------------------------------------------------------
# Helpers – pagination & LRO
# ---------------------------------------------------------------------------
def get_paginated(url: str, headers: dict, key: str = "value") -> list:
    """GET a paginated Fabric API endpoint and return the full list."""
    results: list = []
    while url:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        body = resp.json()
        results.extend(body.get(key, []))
        url = body.get("continuationUri")
    return results


def wait_for_lro(response: requests.Response, headers: dict) -> None:
    """If the response is 202 Accepted, poll the operation until it completes."""
    if response.status_code != 202:
        return

    operation_url = response.headers.get("Location")
    if not operation_url:
        raise RuntimeError("202 Accepted but no Location header for LRO polling.")

    retry_after = int(response.headers.get("Retry-After", LRO_POLL_INTERVAL_SECONDS))
    elapsed = 0

    while elapsed < LRO_MAX_WAIT_SECONDS:
        time.sleep(retry_after)
        elapsed += retry_after

        print(f"  Polling LRO ... ({elapsed}s elapsed)")
        poll = requests.get(operation_url, headers=headers)
        poll.raise_for_status()
        body = poll.json()
        status = body.get("status", "").lower()

        if status in ("succeeded", "completed"):
            print(f"  Long-running operation completed (status={status}).")
            return
        elif status in ("failed", "cancelled"):
            raise RuntimeError(
                f"Long-running operation {status}: {json.dumps(body, indent=2)}"
            )
        # still running – keep polling
        retry_after = int(
            poll.headers.get("Retry-After", LRO_POLL_INTERVAL_SECONDS)
        )

    raise TimeoutError(
        f"Long-running operation did not complete within {LRO_MAX_WAIT_SECONDS}s."
    )


# ---------------------------------------------------------------------------
# Step 1 – Resolve Workspace ID
# ---------------------------------------------------------------------------
def get_workspace_id(workspace_name: str, headers: dict) -> str:
    """Return the Workspace ID for the given display name."""
    print(f"\n[1/5] Resolving Workspace ID for '{workspace_name}' ...")
    workspaces = get_paginated(f"{FABRIC_API_BASE}/workspaces", headers)

    for ws in workspaces:
        if ws["displayName"].lower() == workspace_name.lower():
            ws_id = ws["id"]
            print(f"  Found Workspace ID: {ws_id}")
            return ws_id

    raise ValueError(
        f"Workspace '{workspace_name}' not found. "
        f"Available workspaces: {[w['displayName'] for w in workspaces]}"
    )


# ---------------------------------------------------------------------------
# Step 2 – Resolve Variable Library ID
# ---------------------------------------------------------------------------
def get_variable_library_id(
    workspace_id: str, library_name: str, headers: dict
) -> str:
    """Return the Variable Library ID for the given display name."""
    print(f"\n[2/5] Resolving Variable Library ID for '{library_name}' ...")
    url = f"{FABRIC_API_BASE}/workspaces/{workspace_id}/VariableLibraries"
    libraries = get_paginated(url, headers)

    for lib in libraries:
        if lib["displayName"].lower() == library_name.lower():
            lib_id = lib["id"]
            print(f"  Found Variable Library ID: {lib_id}")
            return lib_id

    raise ValueError(
        f"Variable Library '{library_name}' not found in workspace. "
        f"Available libraries: {[l['displayName'] for l in libraries]}"
    )


# ---------------------------------------------------------------------------
# Step 3 – Get Variable Library Definition
# ---------------------------------------------------------------------------
def get_variable_library_definition(
    workspace_id: str, library_id: str, headers: dict
) -> dict:
    """Retrieve the full definition (parts list) of the Variable Library."""
    print(f"\n[3/5] Fetching Variable Library definition ...")
    url = (
        f"{FABRIC_API_BASE}/workspaces/{workspace_id}"
        f"/VariableLibraries/{library_id}/getDefinition"
    )
    resp = requests.post(url, headers=headers)

    if resp.status_code == 202:
        print("  Definition retrieval is a long-running operation – polling ...")
        wait_for_lro(resp, headers)
        # After LRO completes, the result may be at a result URL.
        # Re-fetch the definition with a fresh call (now it should be 200).
        result_url = resp.headers.get("Location")
        if result_url:
            result_resp = requests.get(f"{result_url}/result", headers=headers)
            result_resp.raise_for_status()
            definition = result_resp.json().get("definition", result_resp.json())
        else:
            resp2 = requests.post(url, headers=headers)
            resp2.raise_for_status()
            definition = resp2.json().get("definition", resp2.json())
    else:
        resp.raise_for_status()
        definition = resp.json().get("definition", resp.json())

    parts = definition.get("parts", [])
    print(f"  Retrieved {len(parts)} definition part(s): {[p['path'] for p in parts]}")
    return definition


# ---------------------------------------------------------------------------
# Step 4 – Modify the variable value
# ---------------------------------------------------------------------------
def decode_payload(payload_b64: str) -> dict:
    """Decode a Base64 payload to a Python dict."""
    return json.loads(base64.b64decode(payload_b64).decode("utf-8"))


def encode_payload(data: dict) -> str:
    """Encode a Python dict to a Base64 payload string."""
    return base64.b64encode(json.dumps(data, indent=2).encode("utf-8")).decode("utf-8")


def coerce_value(new_value_str: str, variable_type: str) -> Any:
    """Convert the CLI string value to the appropriate Python type."""
    vtype = variable_type.lower()
    if vtype in ("boolean", "booleanvariable"):
        return new_value_str.lower() in ("true", "1", "yes")
    elif vtype in ("integer", "integervariable"):
        return int(new_value_str)
    elif vtype in ("number", "numbervariable"):
        return float(new_value_str)
    elif vtype in ("itemreference", "itemreferencevariable"):
        return json.loads(new_value_str)
    else:
        # String, DateTime, or unknown → keep as string
        return new_value_str


def modify_definition(
    definition: dict,
    variable_name: str,
    value_set_name: str,
    new_value: str,
) -> dict:
    """
    Modify the variable value inside the definition parts.

    - If value_set_name is "Default" (case-insensitive), the variable's
      default value in variables.json is updated.
    - Otherwise, the matching valueSets/<valueSetName>.json is updated
      (or the override is added if it does not exist yet).
    """
    print(
        f"\n[4/5] Modifying variable '{variable_name}' "
        f"in value set '{value_set_name}' ..."
    )

    parts = definition["parts"]
    is_default = value_set_name.lower() == "default"

    if is_default:
        # ----- Update the default value in variables.json -----
        variables_part = _find_part(parts, "variables.json")
        if not variables_part:
            raise ValueError("variables.json part not found in the definition.")

        variables_json = decode_payload(variables_part["payload"])
        variable_found = False
        for var in variables_json.get("variables", []):
            if var["name"].lower() == variable_name.lower():
                var_type = var.get("type", "String")
                old_value = var.get("value")
                var["value"] = coerce_value(new_value, var_type)
                variable_found = True
                print(
                    f"  Updated default value: '{old_value}' -> '{var['value']}' "
                    f"(type={var_type})"
                )
                break

        if not variable_found:
            available = [v["name"] for v in variables_json.get("variables", [])]
            raise ValueError(
                f"Variable '{variable_name}' not found in variables.json. "
                f"Available variables: {available}"
            )

        variables_part["payload"] = encode_payload(variables_json)

    else:
        # ----- Update the override in the matching value-set file -----
        # First, look up the variable type from variables.json so we can coerce
        variables_part = _find_part(parts, "variables.json")
        var_type = "String"
        if variables_part:
            variables_json = decode_payload(variables_part["payload"])
            for var in variables_json.get("variables", []):
                if var["name"].lower() == variable_name.lower():
                    var_type = var.get("type", "String")
                    break

        # Find the value-set part (handle both "valueSets/" and "valueSet/" paths)
        vs_part = _find_value_set_part(parts, value_set_name)
        if not vs_part:
            available_vs = [
                p["path"]
                for p in parts
                if p["path"].lower().startswith("valueset")
                and p["path"].lower().endswith(".json")
            ]
            raise ValueError(
                f"Value Set '{value_set_name}' not found in the definition. "
                f"Available value-set files: {available_vs}"
            )

        vs_json = decode_payload(vs_part["payload"])

        # Find or create the override entry
        overrides = vs_json.setdefault("variableOverrides", [])
        override_found = False
        for ovr in overrides:
            if ovr["name"].lower() == variable_name.lower():
                old_value = ovr.get("value")
                ovr["value"] = coerce_value(new_value, var_type)
                override_found = True
                print(
                    f"  Updated override value: '{old_value}' -> '{ovr['value']}' "
                    f"(type={var_type})"
                )
                break

        if not override_found:
            new_override = {
                "name": variable_name,
                "value": coerce_value(new_value, var_type),
            }
            overrides.append(new_override)
            print(
                f"  Added new override for '{variable_name}' = "
                f"'{new_override['value']}' (type={var_type})"
            )

        vs_part["payload"] = encode_payload(vs_json)

    return definition


def _find_part(parts: list, filename: str) -> Optional[dict]:
    """Find a definition part by its path (case-insensitive)."""
    for part in parts:
        if part["path"].lower() == filename.lower():
            return part
    return None


def _find_value_set_part(parts: list, value_set_name: str) -> Optional[dict]:
    """
    Find the definition part for a given value set name.
    The API may return paths like 'valueSets/name.json' or 'valueSet/name.json'.
    We also match by the 'name' field inside the decoded JSON as a fallback.
    """
    vs_name_lower = value_set_name.lower()

    # Try direct path match first
    for prefix in ("valueSets/", "valueSet/"):
        candidate_path = f"{prefix}{value_set_name}.json"
        part = _find_part(parts, candidate_path)
        if part:
            return part

    # Fallback: decode each value-set part and match by 'name' field
    for part in parts:
        path_lower = part["path"].lower()
        if (
            path_lower.startswith("valueset")
            and path_lower.endswith(".json")
            and path_lower != "variables.json"
        ):
            try:
                vs_json = decode_payload(part["payload"])
                if vs_json.get("name", "").lower() == vs_name_lower:
                    return part
            except Exception:
                continue

    return None


# ---------------------------------------------------------------------------
# Step 5 – Update Variable Library Definition
# ---------------------------------------------------------------------------
def update_variable_library_definition(
    workspace_id: str, library_id: str, definition: dict, headers: dict
) -> None:
    """Push the modified definition back to the Fabric API."""
    print(f"\n[5/5] Updating Variable Library definition ...")
    url = (
        f"{FABRIC_API_BASE}/workspaces/{workspace_id}"
        f"/VariableLibraries/{library_id}/updateDefinition"
    )
    body = {"definition": definition}
    resp = requests.post(url, headers=headers, json=body)

    if resp.status_code == 202:
        print("  Update is a long-running operation – polling ...")
        wait_for_lro(resp, headers)
    elif resp.status_code == 200:
        print("  Definition updated successfully (200 OK).")
    else:
        resp.raise_for_status()


# ---------------------------------------------------------------------------
# Single update workflow
# ---------------------------------------------------------------------------
def run_single_update(
    workspace_name: str,
    library_name: str,
    variable_name: str,
    value_set_name: str,
    new_value: str,
    headers: dict,
    dry_run: bool = False,
) -> bool:
    """Execute the 5-step workflow for one variable update. Returns True on success."""
    try:
        workspace_id = get_workspace_id(workspace_name, headers)
        library_id = get_variable_library_id(workspace_id, library_name, headers)
        definition = get_variable_library_definition(workspace_id, library_id, headers)
        modified_definition = modify_definition(
            definition, variable_name, value_set_name, new_value
        )

        if dry_run:
            print("\n  [DRY-RUN] Skipping update – no changes pushed to Fabric.")
        else:
            update_variable_library_definition(
                workspace_id, library_id, modified_definition, headers
            )

        print("\n  ✅ Update completed successfully.")
        return True

    except Exception as exc:
        print(f"\n  ❌ Update FAILED: {exc}")
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Update variable values in Fabric Variable Libraries via the REST API.\n"
            "Supports single-update mode (CLI flags) or batch mode (--config YAML file)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # --- Authentication (can also come from environment variables) ---
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("FABRIC_TENANT_ID"),
        help="Azure AD / Entra Tenant ID (or set FABRIC_TENANT_ID env var).",
    )
    parser.add_argument(
        "--client-id",
        default=os.environ.get("FABRIC_CLIENT_ID"),
        help="Application (client) ID (or set FABRIC_CLIENT_ID env var).",
    )
    parser.add_argument(
        "--client-secret",
        default=os.environ.get("FABRIC_CLIENT_SECRET"),
        help="Client secret value (or set FABRIC_CLIENT_SECRET env var).",
    )

    # --- Batch mode ---
    parser.add_argument(
        "--config",
        help="Path to a YAML config file with a list of variable updates.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without pushing updates to Fabric.",
    )

    # --- Single-update mode ---
    parser.add_argument("--workspace_name", help="Fabric Workspace display name.")
    parser.add_argument("--library_name", help="Variable Library display name.")
    parser.add_argument("--variable_name", help="Name of the variable to update.")
    parser.add_argument(
        "--value_set_name",
        help='Value Set name (use "Default" for the default value in variables.json).',
    )
    parser.add_argument(
        "--new_value",
        help="New value for the variable (string; coerced to the correct type).",
    )

    args = parser.parse_args()

    # --- Validate authentication ---
    if not all([args.tenant_id, args.client_id, args.client_secret]):
        parser.error(
            "Service Principal credentials are required. Provide --tenant-id, "
            "--client-id, --client-secret or set FABRIC_TENANT_ID, "
            "FABRIC_CLIENT_ID, FABRIC_CLIENT_SECRET environment variables."
        )

    # Authenticate
    print("Authenticating with Azure / Fabric via Service Principal ...")
    token = get_access_token(args.tenant_id, args.client_id, args.client_secret)
    headers = build_headers(token)

    # ---- Batch mode (YAML config) ----
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            parser.error(f"Config file not found: {config_path}")

        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        updates = config.get("updates", [])
        if not updates:
            print("No updates found in the config file.")
            sys.exit(0)

        total = len(updates)
        passed = 0
        failed = 0

        print(f"\n{'='*60}")
        print(f"  Batch mode: {total} update(s) to process")
        if args.dry_run:
            print("  Mode: DRY-RUN (no changes will be pushed)")
        print(f"{'='*60}")

        for idx, update in enumerate(updates, start=1):
            print(f"\n{'─'*60}")
            print(
                f"  Update {idx}/{total}: "
                f"{update['workspace_name']} / {update['library_name']} / "
                f"{update['variable_name']} @ {update['value_set_name']}"
            )
            print(f"{'─'*60}")

            ok = run_single_update(
                workspace_name=update["workspace_name"],
                library_name=update["library_name"],
                variable_name=update["variable_name"],
                value_set_name=update["value_set_name"],
                new_value=str(update["new_value"]),
                headers=headers,
                dry_run=args.dry_run,
            )
            if ok:
                passed += 1
            else:
                failed += 1

        # Summary
        print(f"\n{'='*60}")
        print(f"  SUMMARY: {passed} succeeded, {failed} failed out of {total}")
        print(f"{'='*60}")

        if failed > 0:
            sys.exit(1)

    # ---- Single-update mode (CLI flags) ----
    else:
        required = ["workspace_name", "library_name", "variable_name",
                     "value_set_name", "new_value"]
        missing = [f for f in required if not getattr(args, f)]
        if missing:
            parser.error(
                f"In single-update mode these flags are required: "
                f"{', '.join('--' + f for f in missing)}"
            )

        ok = run_single_update(
            workspace_name=args.workspace_name,
            library_name=args.library_name,
            variable_name=args.variable_name,
            value_set_name=args.value_set_name,
            new_value=args.new_value,
            headers=headers,
            dry_run=args.dry_run,
        )
        if not ok:
            sys.exit(1)


if __name__ == "__main__":
    main()
