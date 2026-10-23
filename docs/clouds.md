# Connecting Azure, AWS and Google Cloud

GRC-pal reads cloud configuration with read-only identities. Enter the values on **Configuration**
(or step by step in the **Setup guide**), press **Test without saving**, then **Save and apply**.
Each test checks sign-in and every permission separately and says what to grant when one fails.

Where collectors run decides the best sign-in method:

| Collectors run in | Microsoft / Azure | AWS | Google Cloud |
| --- | --- | --- | --- |
| The portal and its daily job (Azure Container Apps) | Managed identity (no secret) | Azure managed identity to an AWS role (no secret) | Service account key (encrypted) |
| GitHub Actions in your program repository | GitHub OIDC (no secret) | GitHub OIDC with `aws-actions/configure-aws-credentials` | GitHub OIDC with `google-github-actions/auth` |
| Your computer | `az login` | AWS profile (default chain) | `gcloud auth application-default login` |

## Microsoft Entra ID, Microsoft 365 and Azure

- **Permissions (Microsoft Graph, application):** User.Read.All, AuditLog.Read.All,
  RoleManagement.Read.Directory, Application.Read.All, Policy.Read.All,
  DeviceManagementManagedDevices.Read.All, and GroupMember.Read.All for access reviews that include groups
  (Entra enterprise applications and Azure). `deploy/azure/grant-permissions.ps1` grants them to an identity.
- **Azure:** Reader at the management group or on each subscription in scope. Optionally assign the
  built-in Azure Policy initiative *SOC 2 Type 2* in audit mode and enter its assignment name.

## Amazon Web Services

Collectors: `aws_iam` (users, MFA, access key age, root account), `aws_cloudtrail` (multi-region
trail, log validation), `aws_s3` (public access block, encryption), `aws_security_services`
(GuardDuty, AWS Config, Security Hub, EBS default encryption per region).

1. Create a role `grc-pal-reader` with the AWS managed policies **SecurityAudit** and **ViewOnlyAccess**.
2. Choose how GRC-pal assumes it.

**Azure managed identity (no secret, recommended when GRC-pal runs in Azure):**

1. In Entra ID, create an app registration (for example *GRC-pal AWS federation*) and set its
   Application ID URI, for example `api://grc-pal-aws`.
2. In AWS IAM, add an OpenID Connect identity provider with URL
   `https://sts.windows.net/<your-tenant-id>/` and audience `api://grc-pal-aws`.
3. Use this trust policy on the role (replace the values):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::<account-id>:oidc-provider/sts.windows.net/<tenant-id>/"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {"StringEquals": {
      "sts.windows.net/<tenant-id>/:aud": "api://grc-pal-aws",
      "sts.windows.net/<tenant-id>/:sub": "<object ID of the GRC-pal managed identity>"
    }}
  }]
}
```

4. On the AWS page in GRC-pal choose *Azure managed identity to an AWS role*, enter the role ARN and
   the audience. The test calls `sts:GetCallerIdentity`, then reads IAM, CloudTrail, S3 and GuardDuty.

**Access key:** create an IAM user with the same two policies, enter the key pair (stored encrypted),
and rotate it at least every 90 days. Use only when no federation option is possible.

**Several accounts:** create the role in each account, or use an organization-wide delegated
administrator account for Security Hub and Config. Multi-account role chaining is on the roadmap.

## Google Cloud

Collectors: `gcp_iam` (basic owner/editor roles granted to people, user-managed service account keys and their age),
`gcp_logging` (Data Access audit logs, log sinks), `gcp_storage` (public access prevention,
uniform bucket-level access), `gcp_firewall` (rules open to the internet).

1. Create a service account `grc-pal-reader` and grant **Security Reviewer**
   (`roles/iam.securityReviewer`), **Logs Viewer** (`roles/logging.viewer`) and **Browser** on the organization or on each project.
2. Choose how GRC-pal signs in:
   - **GitHub Actions:** Workload Identity Federation with `google-github-actions/auth`; no key exists anywhere.
   - **Portal on Azure Container Apps:** a service account key JSON, pasted on the configuration page
     (stored encrypted). Container Apps does not expose the Azure instance metadata endpoint that
     Google's Azure federation expects, so keyless federation from the portal is not available yet.
     Rotate the key every 90 days and alert on its use.
   - **Elsewhere:** paste a Workload Identity Federation credential configuration JSON
     (`gcloud iam workload-identity-pools create-cred-config ...`).
3. List the project IDs in scope. The test reads each project, its IAM policy and its buckets.

## Adding another cloud or SaaS

1. Add a section with fields and help text to `grcpal/settings.py` (`SCHEMA`).
2. Add `grcpal/integrations/<name>.py` with a session helper and `validate(settings, ctx, result)`.
3. Write collectors in `grcpal/collectors/` with `PLATFORM = "<name>"`, register them in `NAMES` and
   `PLATFORMS`, and add tests with canned API responses.
4. Map the collectors to controls in `catalog/controls.yaml` (`via: "collector:<name>"`).
