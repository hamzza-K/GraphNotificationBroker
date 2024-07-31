#Requires -Module Microsoft.Graph.Applications
#Requires -Module Microsoft.Graph.Authentication
#Requires -Module Microsoft.Graph.Users

param (
    [Parameter(Mandatory=$true)]
    [string] $ApplicationName,
    [string] $AccessToken,
    [string[]] $SpaRedirectUris,
    [string[]] $WebRedirectUris,
    [string[]] $CorsUrls
)
try {
    $FuncAppRedirectUri = "https://$($ApplicationName)func.azurewebsites.net"
    $SpaRedirectUris += $FuncAppRedirectUri
    $CorsUrls += $FuncAppRedirectUri

    Write-Host "Connecting to Graph"
    if ($AccessToken) {
        $secureToken = ConvertTo-SecureString -String $AccessToken -AsPlainText -Force
        Connect-MgGraph -AccessToken $secureToken
    } else {
        Connect-MgGraph -Scopes "Application.ReadWrite.All", "User.ReadBasic.All"
    }

    $frontendApplication = Get-MgApplication -Filter "DisplayName eq '$($ApplicationName) Frontend'"
    if (!$frontendApplication) {
        Write-Warning -Message "Creating Frontend Application: $($ApplicationName) Frontend"
        $frontendApplicationParams = @{
            DisplayName = $ApplicationName + " Frontend"
            Spa = @{
                RedirectUris = $SpaRedirectUris
            }
            Web = @{
                RedirectUris = $WebRedirectUris
            }
            SignInAudience = "AzureADMultipleOrgs"
        }
        $frontendApplication = New-MgApplication @frontendApplicationParams
    } else {
        Write-Host "Frontend Application already exists: $($frontendApplication.DisplayName)"
    }

    $backendApplication = Get-MgApplication -Filter "DisplayName eq '$($ApplicationName) Backend'"
    if (!$backendApplication) {
        Write-Warning -Message "Creating Backend Application: $($ApplicationName) Backend"
        $backendApplicationParams = @{
            DisplayName = $ApplicationName + " Backend"
            SignInAudience = "AzureADMultipleOrgs"
            RequiredResourceAccess = @(
                @{
                    ResourceAppId = "00000003-0000-0000-c000-000000000000" # MS Graph
                    ResourceAccess = @(
                        @{
                            Id = "f501c180-9344-439a-bca0-6cbf209fd270" # Chat.Read
                            Type = "Scope"
                        }
                    )
                }
            )
        }
        $backendApplication = New-MgApplication @backendApplicationParams

        Write-Warning -Message "Adding Microsoft Graph Permissions to: $($ApplicationName) Backend"
        $scopeId = [Guid]::NewGuid()
        $backendScopeParams = @{
            IdentifierUris = @("api://" + $backendApplication.AppId)
            Api = @{
                KnownClientApplications = @($frontendApplication.AppId)
                Oauth2PermissionScopes = @(
                    @{ 
                        Id = $scopeId
                        AdminConsentDescription = "Allows the app to read all 1-to-1 or group chat messages in Microsoft Teams."
                        AdminConsentDisplayName = "Read all chat messages"
                        UserConsentDescription = "Allows an app to read 1 on 1 or group chats threads, on behalf of the signed-in user."
                        UserConsentDisplayName = "Read user chat messages"
                        Value = "Chat.Read"
                        IsEnabled = $true
                        Type = "User"
                    }
                )
            }
        }
        Update-MgApplication -ApplicationId $backendApplication.Id @backendScopeParams
    } else {
        Write-Host "Backend Application already exists: $($backendApplication.DisplayName)"
        # Generate scopeId if not generating new
        $scopeId = [Guid]::NewGuid()
    }

    if ($null -eq $frontendApplication.RequiredResourceAccess -or $frontendApplication.RequiredResourceAccess.ResourceAppId -ne $backendApplication.AppId) {
        Write-Warning -Message "Adding $($ApplicationName) Backend API scope to $($ApplicationName) Frontend"
        $frontendScopesParams = @{
            RequiredResourceAccess = @(
                @{
                    ResourceAppId = $backendApplication.AppId
                    ResourceAccess = @(
                        @{
                            Id = $scopeId
                            Type = "Scope"
                        }
                    )
                }
            )
        }
        Update-MgApplication -ApplicationId $frontendApplication.Id @frontendScopesParams
    }

    Write-Warning -Message "Creating new client secret for: $($ApplicationName) Backend"
    $backendSecretParams = @{
        PasswordCredential = @{
            DisplayName = [Guid]::NewGuid().ToString()
        }
    }
    $backendSecret = Add-MgApplicationPassword -ApplicationId $backendApplication.Id @backendSecretParams

    $graphChangeTrackingSp = Get-MgServicePrincipal -Filter "AppId eq '0bf30f3b-4a52-48df-9a82-234910c4a086'"
    # $context = Get-MgContext

    # Extracting current user UPN from context and getting user object
    # $userUpn = $context.Account
    $user = Get-MgUser

    $paramsOutput = @{
        '$schema' = 'https=//schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        'contentVersion' = '1.0.0.0'
        'parameters' = @{
            'appName' = @{
                'value' = $ApplicationName
            }
            'graphChangeTrackingSpId' = @{
                'value' = $graphChangeTrackingSp.Id
            }
            'userId' = @{
                'value' = $user.Id
                # 'value' = '00f28cbd-f80d-4395-982c-7edd8d2e06e7'
            }
            'apiClientId' = @{
                'value' = $backendApplication.AppId
            }
            'apiClientSecret' = @{
                'value' = $backendSecret.SecretText
            }
            'corsUrls' = @{
                'value' = $CorsUrls
            }
        }
    }

    $paramsOutput | ConvertTo-Json -Depth 5 | Set-Content './bicep/main.parameters.json'

    Write-Host "Frontend ClientId: " $frontendApplication.AppId
    Write-Host "Backend ClientId: " $backendApplication.AppId
    Write-Host "Microsoft Graph Change Tracking Service Principal Id: " $graphChangeTrackingSp.Id
    Write-Host "User Account Id: " $user.Id

    return [PSCustomObject]@{
        FrontendClientId = $frontendApplication.AppId
        BackendClientId = $backendApplication.AppId
        RedirectUri = $FuncAppRedirectUri
    }
}
catch {
    Write-Warning $_
    Write-Warning $_.exception
}

