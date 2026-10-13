// GRC-pal on Azure: one instance (one organization) per resource group.
//
//   Storage account   evidence (write-once container), inbox, portal tables. Entra auth only.
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

@description('Optional allow-list of source IP ranges (CIDR). Empty = reachable from anywhere, still behind sign-in.')
param allowedIpRanges array = []

var suffix = uniqueString(resourceGroup().id, instanceName)
var storageName = take('stgrc${replace(instanceName, '-', '')}${suffix}', 24)
var appName = take('grcpal-${instanceName}', 32)
var tenantId = subscription().tenantId
var roleIds = {
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
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 8000
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
// Configuration page), weekly overdue reminders, monthly recurring tasks.
var jobs = [
  { name: 'collect', cron: '17 6 * * *', args: ['collect', '--all', '--checks'] }
  { name: 'remind', cron: '0 13 * * 1', args: ['remind', '--overdue'] }
  { name: 'tasks', cron: '0 12 1 * *', args: ['tasks'] }
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
          resources: { cpu: json('0.25'), memory: '0.5Gi' }
          env: appEnv
        }
      ]
    }
  }
  dependsOn: [portalBlob, portalTables]
}]

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

output portalUrl string = publicUrl
output redirectUri string = '${publicUrl}/.auth/login/aad/callback'
output storageAccount string = storage.name
output evidenceAccountUrl string = storage.properties.primaryEndpoints.blob
output tablesUrl string = storage.properties.primaryEndpoints.table
output portalIdentityClientId string = portalIdentity.properties.clientId
output portalIdentityPrincipalId string = portalIdentity.properties.principalId
output collectorClientId string = empty(githubRepo) ? '' : collectorIdentity!.properties.clientId
output collectorPrincipalId string = empty(githubRepo) ? '' : collectorIdentity!.properties.principalId
