<#
.SYNOPSIS
  Creates a custom Entra ID role definition for assigning Temporary Access Pass (TAP).

.DESCRIPTION
  This script connects to Microsoft Graph with directory role management privileges 
  and creates a custom role definition called "Temporary Access Pass Assigner".  
  The role allows limited actions on user authentication methods required for TAP.  
  After creation, the script verifies the role exists.

.EXAMPLE
  .\New-EntraCustomRole-TAPAssigner.ps1

.NOTES
  Requirements:
    - Microsoft.Graph PowerShell SDK
    - Admin consent for the following delegated scopes:
      RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All
    - Global Administrator or Privileged Role Administrator permissions
#>

# --- Ensure Graph module is installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Force -AllowClobber
}
Import-Module Microsoft.Graph

# --- Connect to Graph with required scopes
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory","Directory.ReadWrite.All"

# --- Custom role definition
$roleDefinition = @{
    description   = "Allows only the assignment of Temporary Access Pass (TAP) in Microsoft Entra ID"
    displayName   = "Temporary Access Pass Assigner"
    isEnabled     = $true
    rolePermissions = @(
        @{
            allowedResourceActions = @(
                "microsoft.directory/users/authenticationMethods/create",
                "microsoft.directory/users/authenticationMethods/delete",
                "microsoft.directory/users/authenticationMethods/standard/restrictedRead",
                "microsoft.directory/users/authenticationMethods/basic/update"
            )
        }
    )
}

# --- Convert to JSON
$roleDefinitionJson = $roleDefinition | ConvertTo-Json -Compress

# --- Create role via Graph API
Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions" `
    -Body $roleDefinitionJson `
    -ContentType "application/json"

# --- Verify creation
Get-MgRoleManagementDirectoryRoleDefinition |
    Where-Object { $_.DisplayName -eq "Temporary Access Pass Assigner" }
