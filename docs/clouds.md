# Connecting Azure, AWS and Google Cloud

GRC-pal reads cloud configuration with read-only identities. Enter the values on **Configuration**
(or step by step in the **Setup guide**), press **Test without saving**, then **Save and apply**.
Each test checks sign-in and every permission separately and says what to grant when one fails.

Where collectors run decides the best sign-in method:

| Collectors run in | Microsoft / Azure | AWS | Google Cloud |
| --- | --- | --- | --- |
| A VM (deploy/vm/install.sh) | App registration with a certificate (`grcpal ms-cert`) | Access key or assume role | Service account key (encrypted) |
| The portal and its daily job (Azure Container Apps) | Managed identity (no secret) | Azure managed identity to an AWS role (no secret) | Service account key (encrypted) |
| GitHub Actions in your program repository | GitHub OIDC (no secret) | GitHub OIDC with `aws-actions/configure-aws-credentials` | GitHub OIDC with `google-github-actions/auth` |
| Your computer | `az login` | AWS profile (default chain) | `gcloud auth application-default login` |

## Checking and running collectors: the Automation page

**Compliance > Automation** (admins only) lists every platform and collector with its status and the controls it
feeds. After you connect a platform:

1. Press **Verify** on one of its collectors. It runs the collector without saving anything and shows the record
   counts and field names it would collect (for example the number of users in Entra), the API calls it made and
   any findings. If it fails, the error usually names the missing permission; fix it in the platform's settings
   and use **Test without saving** there.
2. Press **Run once** to save a real run now (stored write-once, marked as manual in the manifest). Use it when you
   need evidence immediately or a scheduled run was missed.
3. Leave the daily schedule on. A collector with no run in 36 hours shows **Overdue**; **Run them once now** fills
   the gap, but also check why the schedule missed it (Jobs, Logs), because an auditor tests the schedule itself.

## Microsoft Entra ID, Microsoft 365 and Azure

- **Permissions (Microsoft Graph, application):** User.Read.All, AuditLog.Read.All,
  RoleManagement.Read.Directory, Application.Read.All, Policy.Read.All,
  DeviceManagementManagedDevices.Read.All, and GroupMember.Read.All for access reviews that include groups
  (Entra enterprise applications and Azure). `deploy/azure/grant-permissions.ps1` grants them to an identity.
- **Sign-in from a VM: use a certificate, not a client secret.** A certificate's private key is created on
  the server and never shown on a screen, in a log or in a ticket, so it cannot be copied the way a secret can.
  1. On the server: `grcpal ms-cert --out grcpal-microsoft` (with Docker:
     `docker compose exec grcpal grcpal ms-cert --out /tmp/grcpal-microsoft`). It writes
     `grcpal-microsoft.pem` (private key and certificate, readable by you only) and `grcpal-microsoft.cer`
     (public), valid for 2 years, and prints the thumbprint.
  2. Entra admin center > App registrations > your GRC-pal app > **Certificates & secrets > Certificates >
     Upload certificate**: choose the `.cer` file and check the thumbprint matches.
  3. **Configuration > Microsoft**: *How GRC-pal signs in* = certificate; paste the whole `.pem` file (line
     breaks do not matter); **Save and test**. Then delete the `.pem` file from the server.
  4. Put the expiry date in the security calendar; create and upload a new certificate before it expires.
- **Email through Microsoft Graph** needs Mail.Send restricted to one mailbox; the **Email** step's test sends
  a real message, which proves it.
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
