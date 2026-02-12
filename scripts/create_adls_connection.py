"""
Create Fabric ADLS Gen2 Connection via REST API
================================================
Creates a cloud connection to Azure Data Lake Storage Gen2
using Service Principal authentication.

Authentication:
  Uses environment variables:
    - AZURE_TENANT_ID
    - AZURE_CLIENT_ID
    - AZURE_CLIENT_SECRET

Connection details:
  Uses environment variables:
    - CONNECTION_NAME
    - ADLS_ACCOUNT_NAME
    - ADLS_FILESYSTEM  (optional, defaults to "/")
"""

import json
import os
import sys

import requests
from azure.identity import ClientSecretCredential

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
FABRIC_API_BASE = "https://api.fabric.microsoft.com/v1"
FABRIC_SCOPE = "https://api.fabric.microsoft.com/.default"


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


# ---------------------------------------------------------------------------
# Create Connection
# ---------------------------------------------------------------------------
def create_adls_connection(
    token: str,
    connection_name: str,
    storage_account: str,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    path: str = "/",
) -> dict:
    """Create an ADLS Gen2 connection in Microsoft Fabric."""

    url = f"{FABRIC_API_BASE}/connections"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    body = {
        "displayName": connection_name,
        "connectivityType": "ShareableCloud",
        "privacyLevel": "Organizational",
        "connectionDetails": {
            "type": "AzureDataLakeStorage",
            "creationMethod": "AzureDataLakeStorage",
            "parameters": [
                {
                    "dataType": "Text",
                    "name": "server",
                    "value": f"{storage_account}.dfs.core.windows.net",
                },
                {
                    "dataType": "Text",
                    "name": "path",
                    "value": path,
                },
            ],
        },
        "credentialDetails": {
            "singleSignOnType": "None",
            "connectionEncryption": "NotEncrypted",
            "credentials": {
                "credentialType": "ServicePrincipal",
                "tenantId": tenant_id,
                "servicePrincipalClientId": client_id,
                "servicePrincipalSecret": client_secret,
            },
        },
    }

    print(f"Creating connection '{connection_name}'...")
    print(f"  Server: {storage_account}.dfs.core.windows.net")
    print(f"  Path: {path}")

    response = requests.post(url, headers=headers, json=body)

    if response.status_code in (200, 201):
        result = response.json()
        print(f"Connection created successfully! ID: {result.get('id', 'N/A')}")
        return result
    else:
        print(f"Failed to create connection. Status: {response.status_code}")
        print(f"Response: {response.text}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Share Connection
# ---------------------------------------------------------------------------
def share_connection(token: str, connection_id: str, principal_id: str, principal_type: str = "User", role: str = "User"):
    """Add a role assignment to a Fabric connection."""

    url = f"{FABRIC_API_BASE}/connections/{connection_id}/roleAssignments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    body = {
        "principal": {
            "id": principal_id,
            "type": principal_type,
        },
        "role": role,
    }

    print(f"Sharing connection {connection_id} with {principal_type} {principal_id} (role: {role})...")
    response = requests.post(url, headers=headers, json=body)

    if response.status_code in (200, 201):
        print("Connection shared successfully!")
    else:
        print(f"Failed to share connection. Status: {response.status_code}")
        print(f"Response: {response.text}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    # Auth env vars
    tenant_id = os.environ.get("AZURE_TENANT_ID")
    client_id = os.environ.get("AZURE_CLIENT_ID")
    client_secret = os.environ.get("AZURE_CLIENT_SECRET")

    # Connection env vars
    connection_name = os.environ.get("CONNECTION_NAME")
    storage_account = os.environ.get("ADLS_ACCOUNT_NAME")
    path = os.environ.get("ADLS_PATH", "/")

    # Validate
    missing = []
    for var in ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
                "CONNECTION_NAME", "ADLS_ACCOUNT_NAME"]:
        if not os.environ.get(var):
            missing.append(var)

    if missing:
        print(f"ERROR: Missing required environment variables: {', '.join(missing)}")
        sys.exit(1)

    # Get token
    print("Authenticating with Service Principal...")
    token = get_access_token(tenant_id, client_id, client_secret)
    print("Authentication successful.")

    # Create connection
    result = create_adls_connection(
        token=token,
        connection_name=connection_name,
        storage_account=storage_account,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        path=path,
    )

    # Share connection with admin user
    connection_id = result.get("id")
    if connection_id:
        share_connection(
            token=token,
            connection_id=connection_id,
            principal_id="1034d73d-275e-43c1-a639-2bf0b06cfb69",
            principal_type="User",
            role="User",
        )


if __name__ == "__main__":
    main()
