"""Microsoft Entra ID, Microsoft 365 and Azure: credentials and connection tests."""
from __future__ import annotations

import requests

GRAPH = "https://graph.microsoft.com/v1.0"
ARM = "https://management.azure.com"
# Graph permission -> probe request. Each is tested separately so the result says exactly what is missing.
GRAPH_PROBES = (
    ("User.Read.All", "/users?$top=1&$select=id"),
    ("AuditLog.Read.All", "/reports/authenticationMethods/userRegistrationDetails?$top=1"),
    ("RoleManagement.Read.Directory", "/roleManagement/directory/roleAssignments?$top=1"),
    ("Application.Read.All", "/applications?$top=1&$select=id"),
    ("Policy.Read.All", "/identity/conditionalAccess/policies?$top=1"),
    ("DeviceManagementManagedDevices.Read.All", "/deviceManagement/managedDevices?$top=1&$select=id"),
)


def credential(settings):
    """Explicit credential object, so collector identities never leak into the portal's own storage identity."""
    from azure import identity

    auth = settings.get("GRCPAL_MS_AUTH")
    tenant = settings.get("GRCPAL_MS_TENANT_ID") or None
    client = settings.get("GRCPAL_MS_CLIENT_ID") or None
    if auth == "client_secret":
        if not (tenant and client and settings.secret("GRCPAL_MS_CLIENT_SECRET")):
            raise ValueError("Client secret sign-in needs the tenant ID, client ID and client secret")
        return identity.ClientSecretCredential(tenant, client, settings.secret("GRCPAL_MS_CLIENT_SECRET"))
    if auth == "managed_identity":
        return identity.ManagedIdentityCredential(client_id=client) if client else identity.ManagedIdentityCredential()
    return identity.DefaultAzureCredential(exclude_interactive_browser_credential=True)


def token(settings, scope: str) -> str:
    return credential(settings).get_token(scope).token


def _get(url: str, bearer: str) -> requests.Response:
    return requests.get(url, headers={"Authorization": f"Bearer {bearer}"}, timeout=20)


def validate(settings, ctx, result) -> None:
    if not settings.flag("GRCPAL_MS_ENABLED"):
        result.add("Microsoft collection is turned off", True)
        return
    tok = result.run("Sign in to Microsoft Entra ID", lambda: token(settings, "https://graph.microsoft.com/.default"),
                     hint="Check the tenant ID, client ID and secret, or that the managed identity exists.")
    if not tok:
        return
    for permission, path in GRAPH_PROBES:
        r = _get(GRAPH + path, tok)
        hint = (f"Grant the application permission {permission} to the identity and grant admin consent. "
                "Licensing can also block some reports (Entra ID P1 for sign-in data, Intune for devices).")
        result.add(f"Graph permission {permission}", r.status_code == 200,
                   "ok" if r.status_code == 200 else f"HTTP {r.status_code}: {r.text[:160]}", hint)


def validate_azure(settings, ctx, result) -> None:
    if not settings.flag("GRCPAL_AZURE_ENABLED"):
        result.add("Azure collection is turned off", True)
        return
    tok = result.run("Sign in to Azure Resource Manager", lambda: token(settings, f"{ARM}/.default"),
                     hint="Uses the Microsoft identity above. Check that section first.")
    if not tok:
        return
    r = _get(f"{ARM}/subscriptions?api-version=2022-12-01", tok)
    if not result.add("List subscriptions", r.status_code == 200, f"HTTP {r.status_code}"):
        return
    visible = {s["subscriptionId"]: s.get("displayName", "") for s in r.json().get("value", [])}
    result.add("Subscriptions visible", bool(visible), f"{len(visible)} visible: " + ", ".join(list(visible.values())[:8]),
               "Assign the Reader role on the subscriptions or management group in scope.")
    for sub in settings.list("GRCPAL_SUBSCRIPTIONS"):
        result.add(f"Subscription {sub}", sub in visible, "readable" if sub in visible else "not visible to the identity",
                   "Assign Reader on this subscription, or remove it from the list.")
