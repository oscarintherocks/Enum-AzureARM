# Azure App Configuration PowerShell Script
# Retrieves configuration settings from Azure App Configuration using REST API

param(
    [Parameter(Mandatory=$false)]
    [string]$ConnectionString = "Endpoint=https://example.azconfig.io;Id=xxx:xxx;Secret=xxx==",
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigKey = "ExampleApp:Password"
)

function ConvertFrom-ConnectionString {
    param([string]$ConnectionString)
    
    $parts = @{}
    $ConnectionString -split ';' | ForEach-Object {
        if ($_ -match '^(.+?)=(.+)$') {
            $parts[$matches[1]] = $matches[2]
        }
    }
    
    return @{
        Endpoint = $parts['Endpoint']
        Id = $parts['Id']
        Secret = $parts['Secret']
    }
}

function Get-HmacSha256Signature {
    param(
        [string]$StringToSign,
        [string]$Key
    )
    
    # Decode the base64 secret key (this was the missing piece!)
    $keyBytes = [System.Convert]::FromBase64String($Key)
    $stringBytes = [System.Text.Encoding]::UTF8.GetBytes($StringToSign)
    
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $keyBytes
    $hashBytes = $hmac.ComputeHash($stringBytes)
    
    return [System.Convert]::ToBase64String($hashBytes)
}

function Get-AuthorizationHeader {
    param(
        [string]$Method,
        [string]$Uri,
        [string]$ContentHash,
        [string]$Id,
        [string]$Secret
    )
    
    $timestamp = [DateTimeOffset]::UtcNow.ToString("R")
    $uriObj = [System.Uri]$Uri
    $pathAndQuery = $uriObj.PathAndQuery
    
    # Azure App Configuration requires specific string-to-sign format
    # Format: HTTP_METHOD + "\n" + path_and_query + "\n" + signed_headers_values
    $stringToSign = "$Method`n$pathAndQuery`n$timestamp;$($uriObj.Host);$ContentHash"
    
    Write-Debug "String to sign: $stringToSign"
    
    $signature = Get-HmacSha256Signature -StringToSign $stringToSign -Key $Secret
    
    return @{
        Authorization = "HMAC-SHA256 Credential=$Id&SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=$signature"
        'x-ms-date' = $timestamp
        'x-ms-content-sha256' = $ContentHash
        Host = $uriObj.Host
    }
}

try {
    Write-Host "Starting Azure App Configuration retrieval..." -ForegroundColor Green
    
    # Parse connection string
    $config = ConvertFrom-ConnectionString -ConnectionString $ConnectionString
    
    if (-not $config.Endpoint -or -not $config.Id -or -not $config.Secret) {
        Write-Error "Invalid connection string format. Missing required components (Endpoint, Id, Secret)."
        exit 1
    }
    
    Write-Host "Parsed connection string successfully" -ForegroundColor Yellow
    Write-Host "Endpoint: $($config.Endpoint)" -ForegroundColor Gray
    Write-Host "Credential ID: $($config.Id)" -ForegroundColor Gray
    
    # Construct the request URL
    $endpoint = $config.Endpoint.TrimEnd('/')
    # URL encode the key using PowerShell native method
    $encodedKey = [System.Uri]::EscapeDataString($ConfigKey)
    $requestUri = "$endpoint/kv/$encodedKey" + "?api-version=1.0"
    
    Write-Host "Request URI: $requestUri" -ForegroundColor Gray
    
    # Create empty content hash for GET request
    $contentHash = [System.Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("")))
    
    # Generate authorization header
    $authHeaders = Get-AuthorizationHeader -Method "GET" -Uri $requestUri -ContentHash $contentHash -Id $config.Id -Secret $config.Secret
    
    # Create headers (order matters for signed headers)
    $headers = @{
        'Authorization' = $authHeaders.Authorization
        'x-ms-date' = $authHeaders.'x-ms-date'
        'Host' = $authHeaders.Host
        'x-ms-content-sha256' = $authHeaders.'x-ms-content-sha256'
        'Accept' = 'application/vnd.microsoft.appconfig.kv+json'
        'Content-Type' = 'application/json'
    }
    
    Write-Host "`nSending request to Azure App Configuration..." -ForegroundColor Cyan
    
    # Debug: Show authentication details (without sensitive data)
    Write-Host "Authentication Debug Info:" -ForegroundColor Yellow
    Write-Host "  Method: GET" -ForegroundColor Gray
    Write-Host "  Path: $($([System.Uri]$requestUri).PathAndQuery)" -ForegroundColor Gray
    Write-Host "  Host: $($([System.Uri]$requestUri).Host)" -ForegroundColor Gray
    Write-Host "  Timestamp: $($authHeaders.'x-ms-date')" -ForegroundColor Gray
    Write-Host "  Content Hash: $($authHeaders.'x-ms-content-sha256')" -ForegroundColor Gray
    
    # Make the REST API call
    $response = Invoke-RestMethod -Uri $requestUri -Method GET -Headers $headers -ErrorAction Stop
    
    Write-Host "`nConfiguration retrieved successfully!" -ForegroundColor Green
    Write-Host "Key: $ConfigKey" -ForegroundColor Yellow
    Write-Host "Value: $($response.value)" -ForegroundColor White
    
    # Display additional metadata if available
    if ($response.label) {
        Write-Host "Label: $($response.label)" -ForegroundColor Gray
    }
    
    if ($response.content_type) {
        Write-Host "Content Type: $($response.content_type)" -ForegroundColor Gray
    }
    
    if ($response.last_modified) {
        Write-Host "Last Modified: $($response.last_modified)" -ForegroundColor Gray
    }
    
    if ($response.tags) {
        Write-Host "Tags:" -ForegroundColor Gray
        $response.tags.PSObject.Properties | ForEach-Object {
            Write-Host "  $($_.Name): $($_.Value)" -ForegroundColor Gray
        }
    }
    
    # Return the value for potential script usage
    return $response.value
    
} catch [System.Net.WebException] {
    $statusCode = $_.Exception.Response.StatusCode
    $statusDescription = $_.Exception.Response.StatusDescription
    
    Write-Host "`nHTTP Response Details:" -ForegroundColor Red
    Write-Host "Status Code: $statusCode" -ForegroundColor Gray
    Write-Host "Status Description: $statusDescription" -ForegroundColor Gray
    
    # Try to read response content for more details
    try {
        $responseStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($responseStream)
        $responseContent = $reader.ReadToEnd()
        if ($responseContent) {
            Write-Host "Response Content: $responseContent" -ForegroundColor Gray
        }
        $reader.Close()
    } catch {
        # Ignore if we can't read response content
    }
    
    switch ($statusCode) {
        'NotFound' { 
            Write-Error "Configuration key '$ConfigKey' not found in App Configuration store."
        }
        'Unauthorized' { 
            Write-Error "Authentication failed. HMAC-SHA256 signature verification failed."
            Write-Host "`nAuthentication Troubleshooting:" -ForegroundColor Yellow
            Write-Host "1. Verify the connection string components are correct:" -ForegroundColor Gray
            Write-Host "   - Endpoint: $($config.Endpoint)" -ForegroundColor Gray
            Write-Host "   - Id: $($config.Id)" -ForegroundColor Gray
            Write-Host "   - Secret: [LENGTH: $($config.Secret.Length) chars]" -ForegroundColor Gray
            Write-Host "2. Check if the credential is active and not expired" -ForegroundColor Gray
            Write-Host "3. Verify the timestamp is correct (check system clock)" -ForegroundColor Gray
        }
        'Forbidden' { 
            Write-Error "Access denied. The credential may not have sufficient permissions."
        }
        default { 
            Write-Error "HTTP Error $statusCode : $statusDescription"
        }
    }
    
    Write-Host "`nGeneral troubleshooting tips:" -ForegroundColor Yellow
    Write-Host "1. Verify the connection string is correct" -ForegroundColor Gray
    Write-Host "2. Check that the configuration key exists in the App Configuration store" -ForegroundColor Gray
    Write-Host "3. Ensure the credential has read permissions" -ForegroundColor Gray
    Write-Host "4. Verify the endpoint URL is accessible" -ForegroundColor Gray
    
} catch {
    Write-Error "An unexpected error occurred: $($_.Exception.Message)"
    Write-Host "Full error details:" -ForegroundColor Red
    Write-Host $_.Exception.ToString() -ForegroundColor Red
}