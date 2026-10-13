<#
Grants the collector identity read-only access to Microsoft Graph and Azure.
Run once as a Global Administrator (Graph app roles) and Owner/User Access Administrator
(Azure role assignments). Requires: Microsoft.Graph PowerShell module, Az CLI.

  ./deploy/azure/grant-permissions.ps1 -PrincipalId <principalId output> -Scope /providers/Microsoft.Management/managementGroups/<mg>
#>
param(
  [Parameter(Mandatory)] [string] $PrincipalId,
  [Parameter(Mandatory)] [string] $Scope   # subscription or management group resource ID
)

$GraphAppRoles = @(
  'User.Read.All',                          # users, guests (entra_users, leaver_reconcile)
  'AuditLog.Read.All',                      # sign-in activity, MFA registration report
  'RoleManagement.Read.Directory',          # directory role assignments
  'Application.Read.All',                   # enterprise apps and app credentials
  'Policy.Read.All',                        # Conditional Access policies
  'DeviceManagementManagedDevices.Read.All' # Intune devices
)

Connect-MgGraph -Scopes 'AppRoleAssignment.ReadWrite.All','Application.Read.All' -NoWelcome
$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalId -All

foreach ($perm in $GraphAppRoles) {
  $role = $graph.AppRoles | Where-Object { $_.Value -eq $perm -and $_.AllowedMemberTypes -contains 'Application' }
  if ($existing.AppRoleId -contains $role.Id) { Write-Host "already granted $perm"; continue }
  New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalId `
    -PrincipalId $PrincipalId -ResourceId $graph.Id -AppRoleId $role.Id | Out-Null
  Write-Host "granted $perm"
}

# Azure: Reader for inventory, RBAC, backup and Azure Policy state (Resource Graph).
az role assignment create --assignee-object-id $PrincipalId --assignee-principal-type ServicePrincipal `
  --role Reader --scope $Scope | Out-Null
Write-Host "granted Reader on $Scope"

Write-Host "Maester needs additional read permissions for some tests; see its documentation and add them here."
