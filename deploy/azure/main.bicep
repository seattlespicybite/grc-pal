// GRC-pal on Azure: one instance (one organization) per resource group.
//
//   Storage account   evidence and backups (write-once containers), inbox, portal tables. Entra auth only.
//                     Delete lock on by default; a lifecycle rule removes backups after their retention.
//   Container App     the portal, consumption plan, scales to zero, Entra sign-in in front.
//   Log Analytics     structured app logs, 30-day retention, daily cap.
//   Identities        portal (managed), collectors (GitHub OIDC, optional). No stored keys.
//
// Easiest path: ./deploy.sh (creates the sign-in app registration and runs this template).
// Manual:       az deployment group create -g <rg> -f main.bicep -p instanceName=acme entraClientId=... ...
//
// Cost: Container Apps consumption (usually inside the monthly free grant when scaled to zero),
// Storage (cents per GB-month) and Log Analytics ingestion (capped below). No licenses.

targetScope = 'resourceGroup'

@description('Short name for this instance, also its tenant ID inside GRC-pal (lowercase letters, digits, hyphens).')
@minLength(2)
@maxLength(20)
param instanceName string

param location string = resourceGroup().location

@description('Container image. The public image needs no registry credentials.')
param image string = 'ghcr.io/seattlespicybite/grc-pal:latest'

@description('Optional private registry login (leave empty for a public image).')
param registryServer string = ''
param registryUsername string = ''
@secure()
param registryPassword string = ''

@description('Entra app registration used for sign-in (deploy.sh creates it).')
param entraClientId string
@secure()
param entraClientSecret string

@description('Random value that signs form tokens. deploy.sh generates it (openssl rand -hex 32).')
@secure()
param grcpalSecret string

@description('Key that encrypts credentials saved on the Configuration page. Keep it stable: deploy.sh reuses the existing one. Losing it means re-entering saved secrets.')
@secure()
param encryptionKey string

@description('Comma-separated emails that become admins at first sign-in.')
param bootstrapAdmins string

@description('Directory (tenant) IDs allowed to sign in. Defaults to this subscription\'s directory.')
param allowedTenantIds string = subscription().tenantId

@description('GitHub repository (owner/repo) whose main-branch workflows run collectors. Empty to skip.')
param githubRepo string = ''

@allowed(['off', 'graph', 'smtp'])
param mailBackend string = 'off'
@description('Sender mailbox for notifications, e.g. grc@contoso.com.')
param mailFrom string = ''
param smtpHost string = ''
param smtpPort string = '587'
param smtpUser string = ''
@secure()
param smtpPassword string = ''

@description('Days each evidence file is write-protected. Cover the audit window plus at least one year.')
@minValue(1)
param retentionDays int = 730

@allowed(['Standard_LRS', 'Standard_ZRS', 'Standard_GRS'])
param storageSku string = 'Standard_GRS'

@description('Key that encrypts backup files (base64 of 32 random bytes). deploy.sh creates it once and reuses it; keep a copy in the recovery kit.')
@secure()
param backupKey string

@description('Days each backup file is write-protected in the backups container (protects against deletion and ransomware).')
@minValue(1)
param backupRetentionDays int = 35

@description('How often the backup job checks for due work (cron, UTC). It makes at most one scheduled backup per day (or week) per the Backups page; the checks also start "Back up now" requests.')
param backupCheckCron string = '*/15 * * * *'

@description('Put a delete lock on the storage account (protects evidence and backups from deletion of the whole account). Remove the lock first to retire an instance.')
param lockStorage bool = true

@description('Hours a sign-in lasts before the user goes back to Entra ID, where Conditional Access (MFA, compliant device) is checked again.')
@minValue(1)
@maxValue(24)
param sessionHours int = 8

@description('Email (or distribution list) for alerts: no successful backup, and changes to locks, role assignments, write-once policies or sign-in settings. Empty = no alerts.')
param alertEmail string = ''

@description('Alert when no successful scheduled backup was logged for this long (ISO 8601). Use P8D for a weekly schedule.')
param backupAlertWindow string = 'P2D'

@description('Optional allow-list of source IP ranges (CIDR). Empty = reachable from anywhere, still behind sign-in.')
param allowedIpRanges array = []

var suffix = uniqueString(resourceGroup().id, instanceName)
var storageName = take('stgrc${replace(instanceName, '-', '')}${suffix}', 24)
var appName = take('grcpal-${instanceName}', 32)
var tenantId = subscription().tenantId
var roleIds = {
  contributor: 'b24988ac-6180-42a0-ab88-20f7382dd24c'
  blobContributor: 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
  tableContributor: '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
}

// ------------------------------------------------------------------ storage
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: { name: storageSku }
  kind: 'StorageV2'
  tags: { app: 'grc-pal', instance: instanceName }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false // Entra ID authentication only
    accessTier: 'Cool'
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    deleteRetentionPolicy: { enabled: true, days: 30 }
    containerDeleteRetentionPolicy: { enabled: true, days: 30 }
  }
}

// Write-once evidence. Lock the policy after the first good week (docs/deploy-azure.md, step 6).
resource evidence 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'evidence'
  properties: { publicAccess: 'None' }
}

resource evidenceImmutability 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  parent: evidence
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: retentionDays
    allowProtectedAppendWrites: false
  }
}

resource inbox 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'inbox'
  properties: { publicAccess: 'None' }
}

// Your catalog, registers and policies (grcpal publish-config); the portal loads it at start-up.
resource config 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'config'
  properties: { publicAccess: 'None' }
}

// Backup files (grcpal backup): write-once for backupRetentionDays, so they cannot be changed or deleted early.
resource backups 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'backups'
  properties: { publicAccess: 'None' }
}

resource backupsImmutability 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  parent: backups
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: backupRetentionDays
    allowProtectedAppendWrites: false
  }
}

// Old backups are removed by storage, not by the app (the app cannot delete write-once files). Without this
// rule every daily backup would be kept, and paid for, forever.
resource lifecycle 'Microsoft.Storage/storageAccounts/managementPolicies@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          name: 'expire-backups'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: { blobTypes: ['blockBlob'], prefixMatch: ['backups/'] }
            actions: { baseBlob: { delete: { daysAfterCreationGreaterThan: backupRetentionDays + 1 } } }
          }
        }
      ]
    }
  }
  dependsOn: [backups]
}

// Blocks deleting the account (and the resource group) until the lock is removed. Data access is unchanged.
resource storageLock 'Microsoft.Authorization/locks@2020-05-01' = if (lockStorage) {
  scope: storage
  name: 'grcpal-no-delete'
  properties: {
    level: 'CanNotDelete'
    notes: 'GRC-pal evidence and backups. Remove this lock only to retire the instance.'
  }
}

// ------------------------------------------------------------------ identities
resource portalIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-${appName}'
  location: location
}

resource collectorIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (!empty(githubRepo)) {
  name: 'id-${appName}-collector'
  location: location
}

// Keyless login from GitHub Actions (OIDC); only workflows on the main branch can use it.
resource githubFederation 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = if (!empty(githubRepo)) {
  parent: collectorIdentity
  name: 'github-main'
  properties: {
    issuer: 'https://token.actions.githubusercontent.com'
    subject: 'repo:${githubRepo}:ref:refs/heads/main'
    audiences: ['api://AzureADTokenExchange']
  }
}

// Updates (deploy/azure/update.sh) run from the program repository's monthly workflow with this identity. Only
// workflow runs in the repository's `grcpal-update` environment can use it (add required reviewers there to
// approve every update). It may change this container app and its jobs, nothing else.
resource updaterIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (!empty(githubRepo)) {
  name: 'id-${appName}-updater'
  location: location
}

resource updaterFederation 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = if (!empty(githubRepo)) {
  parent: updaterIdentity
  name: 'github-grcpal-update'
  properties: {
    issuer: 'https://token.actions.githubusercontent.com'
    subject: 'repo:${githubRepo}:environment:grcpal-update'
    audiences: ['api://AzureADTokenExchange']
  }
}

resource portalBlob 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: storage
  name: guid(storage.id, portalIdentity.id, roleIds.blobContributor)
  properties: {
    principalId: portalIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.blobContributor)
  }
}

resource portalTables 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: storage
  name: guid(storage.id, portalIdentity.id, roleIds.tableContributor)
  properties: {
    principalId: portalIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.tableContributor)
  }
}

resource collectorBlob 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(githubRepo)) {
  scope: storage
  name: guid(storage.id, 'collector', roleIds.blobContributor)
  properties: {
    principalId: collectorIdentity!.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.blobContributor)
  }
}

resource collectorTables 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(githubRepo)) {
  scope: storage
  name: guid(storage.id, 'collector', roleIds.tableContributor)
  properties: {
    principalId: collectorIdentity!.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.tableContributor)
  }
}

// ------------------------------------------------------------------ logs
resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'log-${appName}'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
    workspaceCapping: { dailyQuotaGb: json('0.5') }
  }
}

// ------------------------------------------------------------------ portal
resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: 'cae-${appName}'
  location: location
  properties: {
    workloadProfiles: [{ name: 'Consumption', workloadProfileType: 'Consumption' }]
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
  }
}

var usePrivateRegistry = !empty(registryServer) && !empty(registryUsername)
var publicUrl = 'https://${appName}.${env.properties.defaultDomain}'
var baseSecrets = [
  { name: 'microsoft-provider-authentication-secret', value: entraClientSecret }
  { name: 'grcpal-secret', value: grcpalSecret }
  { name: 'encryption-key', value: encryptionKey }
  { name: 'smtp-password', value: empty(smtpPassword) ? 'unused' : smtpPassword }
  { name: 'backup-key', value: backupKey }
]

var appEnv = [
  { name: 'AZURE_CLIENT_ID', value: portalIdentity.properties.clientId }
  { name: 'GRCPAL_ENV', value: 'production' }
  { name: 'GRCPAL_AUTH_MODE', value: 'easyauth' }
  { name: 'GRCPAL_TENANT', value: instanceName }
  { name: 'GRCPAL_SECRET', secretRef: 'grcpal-secret' }
  { name: 'GRCPAL_ENCRYPTION_KEY', secretRef: 'encryption-key' }
  { name: 'GRCPAL_PUBLIC_URL', value: publicUrl }
  { name: 'GRCPAL_TABLES_URL', value: storage.properties.primaryEndpoints.table }
  { name: 'GRCPAL_EVIDENCE_ACCOUNT_URL', value: storage.properties.primaryEndpoints.blob }
  { name: 'GRCPAL_BOOTSTRAP_ADMINS', value: bootstrapAdmins }
  { name: 'GRCPAL_ALLOWED_TENANT_IDS', value: allowedTenantIds }
  { name: 'GRCPAL_MAIL_BACKEND', value: mailBackend }
  { name: 'GRCPAL_MAIL_FROM', value: mailFrom }
  { name: 'GRCPAL_SMTP_HOST', value: smtpHost }
  { name: 'GRCPAL_SMTP_PORT', value: smtpPort }
  { name: 'GRCPAL_SMTP_USER', value: smtpUser }
  { name: 'GRCPAL_SMTP_PASSWORD', secretRef: 'smtp-password' }
  { name: 'GRCPAL_BACKUP_KEY', secretRef: 'backup-key' }
  { name: 'GRCPAL_BACKUP_CONTAINER', value: 'backups' }
]

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: appName
  location: location
  tags: { app: 'grc-pal', instance: instanceName }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${portalIdentity.id}': {} }
  }
  properties: {
    environmentId: env.id
    workloadProfileName: 'Consumption'
    configuration: {
      // Multiple: an update starts a new revision with no traffic, checks it, then moves traffic (update.sh).
      activeRevisionsMode: 'Multiple'
      ingress: {
        external: true
        targetPort: 8000
        traffic: [{ latestRevision: true, weight: 100 }]
        transport: 'auto'
        allowInsecure: false
        ipSecurityRestrictions: [for (cidr, i) in allowedIpRanges: {
          name: 'allow-${i}'
          action: 'Allow'
          ipAddressRange: cidr
        }]
      }
      secrets: usePrivateRegistry ? concat(baseSecrets, [{ name: 'registry-password', value: registryPassword }]) : baseSecrets
      registries: usePrivateRegistry ? [{ server: registryServer, username: registryUsername, passwordSecretRef: 'registry-password' }] : []
    }
    template: {
      containers: [
        {
          name: 'portal'
          image: image
          resources: { cpu: json('0.25'), memory: '0.5Gi' }
          env: appEnv
          probes: [
            { type: 'Liveness', httpGet: { path: '/healthz', port: 8000 }, periodSeconds: 30 }
            { type: 'Readiness', httpGet: { path: '/healthz', port: 8000 }, periodSeconds: 10 }
          ]
        }
      ]
      scale: { minReplicas: 0, maxReplicas: 2 }
    }
  }
  dependsOn: [portalBlob, portalTables]
}


// Scheduled jobs on the same image and identity: daily collection and checks (with the settings saved on the
// Configuration page), weekly overdue reminders, monthly recurring tasks, and the backup runner every 15 minutes
// (the schedule and "Back up now" from the Backups page; a check with nothing due exits in seconds; also used by
// update.sh for the pre-update backup and checks).
// The backup job is larger: a backup is written to the job's local disk before it is uploaded.
var jobs = [
  { name: 'collect', cron: '17 6 * * *', args: ['collect', '--all', '--checks'], cpu: '0.25', memory: '0.5Gi' }
  { name: 'remind', cron: '0 13 * * 1', args: ['remind', '--overdue'], cpu: '0.25', memory: '0.5Gi' }
  { name: 'tasks', cron: '0 12 1 * *', args: ['tasks'], cpu: '0.25', memory: '0.5Gi' }
  { name: 'backup', cron: backupCheckCron, args: ['backup', 'run-due'], cpu: '1.0', memory: '2Gi' }
]

resource scheduled 'Microsoft.App/jobs@2024-03-01' = [for j in jobs: {
  name: take('job-${replace(instanceName, '_', '-')}-${j.name}', 32)
  location: location
  tags: { app: 'grc-pal', instance: instanceName }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${portalIdentity.id}': {} }
  }
  properties: {
    environmentId: env.id
    workloadProfileName: 'Consumption'
    configuration: {
      triggerType: 'Schedule'
      replicaTimeout: 3600
      replicaRetryLimit: 1
      scheduleTriggerConfig: { cronExpression: j.cron, parallelism: 1, replicaCompletionCount: 1 }
      secrets: usePrivateRegistry ? concat(baseSecrets, [{ name: 'registry-password', value: registryPassword }]) : baseSecrets
      registries: usePrivateRegistry ? [{ server: registryServer, username: registryUsername, passwordSecretRef: 'registry-password' }] : []
    }
    template: {
      containers: [
        {
          name: j.name
          image: image
          command: ['grcpal']
          args: j.args
          resources: { cpu: json(j.cpu), memory: j.memory }
          env: appEnv
        }
      ]
    }
  }
  dependsOn: [portalBlob, portalTables]
}]

resource updaterOnApp 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(githubRepo)) {
  scope: app
  name: guid(app.id, 'updater', roleIds.contributor)
  properties: {
    principalId: updaterIdentity!.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.contributor)
  }
}

resource updaterOnJobs 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (j, i) in jobs: if (!empty(githubRepo)) {
  scope: scheduled[i]
  name: guid(scheduled[i].id, 'updater', roleIds.contributor)
  properties: {
    principalId: updaterIdentity!.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.contributor)
  }
}]

// Creating a revision also needs permission to use the environment; this role grants that one action only.
resource envJoinRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = if (!empty(githubRepo)) {
  name: guid(resourceGroup().id, 'grcpal-updater-env-join')
  properties: {
    roleName: 'GRC-pal updater environment use (${resourceGroup().name})'
    description: 'Lets the GRC-pal updater create container app revisions in this environment, nothing else.'
    type: 'CustomRole'
    permissions: [{ actions: ['Microsoft.App/managedEnvironments/read', 'Microsoft.App/managedEnvironments/join/action'] }]
    assignableScopes: [resourceGroup().id]
  }
}

resource updaterOnEnv 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(githubRepo)) {
  scope: env
  name: guid(env.id, 'updater', 'env-join')
  properties: {
    principalId: updaterIdentity!.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: envJoinRole.id
  }
}

resource auth 'Microsoft.App/containerApps/authConfigs@2024-03-01' = {
  parent: app
  name: 'current'
  properties: {
    platform: { enabled: true }
    globalValidation: {
      unauthenticatedClientAction: 'RedirectToLoginPage'
      redirectToProvider: 'azureactivedirectory'
      excludedPaths: ['/healthz']
    }
    httpSettings: { requireHttps: true }
    login: {
      cookieExpiration: { convention: 'FixedTime', timeToExpiration: '${padLeft(string(sessionHours), 2, '0')}:00:00' }
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          clientId: entraClientId
          clientSecretSettingName: 'microsoft-provider-authentication-secret'
          openIdIssuer: '${environment().authentication.loginEndpoint}${tenantId}/v2.0'
        }
        validation: {
          allowedAudiences: [entraClientId, 'api://${entraClientId}']
        }
      }
    }
  }
}

// ------------------------------------------------------------------ alerts (optional: alertEmail)
resource alertGroup 'Microsoft.Insights/actionGroups@2023-01-01' = if (!empty(alertEmail)) {
  name: take('ag-${appName}', 64)
  location: 'global'
  properties: {
    groupShortName: 'grcpal'
    enabled: true
    emailReceivers: [{ name: 'grcpal-admins', emailAddress: alertEmail, useCommonAlertSchema: true }]
  }
}

// No successful scheduled backup logged by the backup job (grcpal backup run-due prints one JSON line).
resource backupAlert 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = if (!empty(alertEmail)) {
  name: 'grcpal-${instanceName}-no-backup'
  location: location
  properties: {
    displayName: 'GRC-pal ${instanceName}: no successful backup'
    description: 'No verified scheduled backup in the window. Check Administration > Backups and the backup job runs.'
    severity: 2
    enabled: true
    scopes: [logs.id]
    evaluationFrequency: 'PT1H'
    windowSize: backupAlertWindow
    criteria: {
      allOf: [
        {
          query: 'ContainerAppConsoleLogs_CL | where Log_s has "backup.run_due" and Log_s contains \'"kind": "scheduled"\' and Log_s contains \'"ok": true\''
          timeAggregation: 'Count'
          operator: 'Equal'
          threshold: 0
          failingPeriods: { numberOfEvaluationPeriods: 1, minFailingPeriodsToAlert: 1 }
        }
      ]
    }
    actions: { actionGroups: [alertGroup.id] }
  }
}

// Changes an attacker (or a mistake) would make to weaken protections. Deployments and updates also trigger
// it, which doubles as a change record.
var watchedOperations = [
  'Microsoft.Authorization/locks/delete'
  'Microsoft.Authorization/roleAssignments/write'
  'Microsoft.Authorization/roleAssignments/delete'
  'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/write'
  'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/delete'
  'Microsoft.App/containerApps/authConfigs/write'
  'Microsoft.App/containerApps/write'
]

resource changeAlert 'Microsoft.Insights/activityLogAlerts@2020-10-01' = if (!empty(alertEmail)) {
  name: 'grcpal-${instanceName}-security-change'
  location: 'global'
  properties: {
    description: 'A lock, role assignment, write-once policy or sign-in setting changed in this resource group.'
    enabled: true
    scopes: [resourceGroup().id]
    condition: {
      allOf: [
        { field: 'category', equals: 'Administrative' }
        { anyOf: [for op in watchedOperations: { field: 'operationName', equals: op }] }
      ]
    }
    actions: { actionGroups: [{ actionGroupId: alertGroup.id }] }
  }
}

output portalUrl string = publicUrl
output redirectUri string = '${publicUrl}/.auth/login/aad/callback'
output storageAccount string = storage.name
output evidenceAccountUrl string = storage.properties.primaryEndpoints.blob
output tablesUrl string = storage.properties.primaryEndpoints.table
output portalIdentityClientId string = portalIdentity.properties.clientId
output portalIdentityPrincipalId string = portalIdentity.properties.principalId
output collectorClientId string = empty(githubRepo) ? '' : collectorIdentity!.properties.clientId
output updaterClientId string = empty(githubRepo) ? '' : updaterIdentity!.properties.clientId
output collectorPrincipalId string = empty(githubRepo) ? '' : collectorIdentity!.properties.principalId
