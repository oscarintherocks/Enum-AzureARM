<#
.SYNOPSIS
    Azure ARM/Graph enumeration with selective token support and multiple authentication methods
.DESCRIPTION
    Comprehensive Azure enumeration tool that supports multiple authentication methods including current user context, 
    access tokens, and service principal credentials. When OutputFile is not specified, generates dynamic filename: 
    accountid_YYYYMMDDHHMMSS_AzureResources.json
    
    Supports multiple authentication methods:
    1. Current user context (-UseCurrentUser)
       - Uses existing Azure PowerShell or Azure CLI authentication
       - Requires prior login with Connect-AzAccount or az login
    
    2. Access tokens (-AccessTokenARM and/or -AccessTokenGraph with -AccountId)
       - Direct token-based authentication for ARM and/or Graph APIs
       - Useful for CTF scenarios or when tokens are obtained through other means
    
    3. Azure CLI service principal authentication (recommended for automation)
       - Method A: -UseAzureCLI with -ServicePrincipalId, -ServicePrincipalSecret, -TenantId
       - Method B: Direct parameters: -ServicePrincipalId, -ServicePrincipalSecret, -TenantId
       - Uses Azure CLI backend for authentication and token management
    
    4. Azure PowerShell service principal authentication (enhanced capabilities)
       - Parameters: -UseServicePrincipal with -ApplicationId, -ClientSecret, -TenantId
       - Automatically extracts ARM, Graph, Storage, and Key Vault tokens for comprehensive access
       - Provides enhanced blob download capabilities with multiple authentication methods
       - Ideal for comprehensive enumeration when service principal credentials are available
    
    Service Principal Authentication Benefits:
    - Automatic resource-specific token acquisition (Storage: https://storage.azure.com/, Key Vault: https://vault.azure.net/)
    - Enhanced blob download with 5-tier authentication system
    - Cross-resource enumeration capabilities
    - No interactive authentication required (perfect for automation/CTF scenarios)
    
.PARAMETER UseServicePrincipal
    Enables Azure PowerShell service principal authentication mode with enhanced token capabilities
.PARAMETER ApplicationId
    Service principal application (client) ID for Azure PowerShell authentication
.PARAMETER ClientSecret
    Service principal client secret for Azure PowerShell authentication
.PARAMETER UseAzureCLI
    Enables Azure CLI service principal authentication mode
.PARAMETER ServicePrincipalId
    Service principal application ID for Azure CLI authentication
.PARAMETER ServicePrincipalSecret
    Service principal secret for Azure CLI authentication
.PARAMETER TenantId
    Azure Active Directory tenant ID (required for service principal authentication)
.NOTES
    Version: 2.0 | Outputs to Results\ folder | Dynamic filenames based on account identity
    Enhanced service principal support with automatic resource-specific token management
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$AccessTokenARM,

    [Parameter(Mandatory=$false)]
    [string]$AccessTokenGraph,

    [Parameter(Mandatory=$false)]
    [string]$AccountId,

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "Results\AzureResourcesOutput.json",

    [Parameter(Mandatory=$false)]
    [ValidateSet("json","csv")]
    [string]$OutputFormat = "json",

    [Parameter(Mandatory=$false)]
    [Alias("h")]
    [switch]$Help,

    [Parameter(Mandatory=$false)]
    [switch]$UseCurrentUser,

    # Azure CLI Service Principal Authentication
    [Parameter(Mandatory=$false)]
    [string]$ServicePrincipalId,

    [Parameter(Mandatory=$false)]
    [string]$ServicePrincipalSecret,

    [Parameter(Mandatory=$false)]
    [string]$TenantId,

    [Parameter(Mandatory=$false)]
    [switch]$UseAzureCLI,

    # Azure PowerShell Service Principal Authentication
    [Parameter(Mandatory=$false)]
    [switch]$UseServicePrincipal,

    [Parameter(Mandatory=$false)]
    [string]$ApplicationId,

    [Parameter(Mandatory=$false)]
    [string]$ClientSecret,

    [Parameter(Mandatory=$false)]
    [switch]$GraphOnly,

    # Interactive authentication helper
    [Parameter(Mandatory=$false)]
    [switch]$NoInteractiveAuth,

    # Allow running without subscription access
    [Parameter(Mandatory=$false)]
    [switch]$AllowNoSubscription
)

# Error action preference for better error handling
$ErrorActionPreference = 'Stop'

# Global variables for tracking authentication status
$Script:AuthenticationStatus = @{
    AzContext = $false
    GraphContext = $false
    ARMToken = $false
    GraphToken = $false
    AzureCLI = $false
}

# Global variable for Service Principal authentication state
$Script:ServicePrincipalMode = $false

# Global variables for resource-specific tokens
$Script:KeyVaultToken = $null
$Script:StorageToken = $null

# Global variables for token tenant tracking
$Script:ARMTokenTenant = $null
$Script:GraphTokenTenant = $null
$Script:SubscriptionTenant = $null

# Global timeout for user interaction prompts (in seconds)
$Script:UserPromptTimeout = 10

# Display help if requested or if no authentication method is provided
if ($Help -or (-not $UseCurrentUser -and -not $AccessTokenARM -and -not $AccessTokenGraph -and -not $UseAzureCLI -and -not ($ServicePrincipalId -and $ServicePrincipalSecret -and $TenantId) -and -not ($UseServicePrincipal -and $ApplicationId -and $ClientSecret -and $TenantId))) {
    Write-Host "`nAzure ARM/Graph Enumeration Script v2.0`n" -ForegroundColor Cyan
    Write-Host "Authentication Methods:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1. Current User (requires prior authentication):" -ForegroundColor Cyan
    Write-Host "     .\Enum-AzureARM.ps1 -UseCurrentUser"
    Write-Host ""
    Write-Host "  2. Access Tokens (direct token usage):" -ForegroundColor Cyan
    Write-Host "     .\Enum-AzureARM.ps1 -AccessTokenARM <token> -AccountId <id>"
    Write-Host "     .\Enum-AzureARM.ps1 -AccessTokenGraph <token>"
    Write-Host "     .\Enum-AzureARM.ps1 -AccessTokenARM <arm> -AccessTokenGraph <graph> -AccountId <id>"
    Write-Host ""
    Write-Host "  3. Azure CLI Service Principal (standard automation):" -ForegroundColor Cyan
    Write-Host "     .\Enum-AzureARM.ps1 -UseAzureCLI -ServicePrincipalId <appid> -ServicePrincipalSecret <secret> -TenantId <tenantid>"
    Write-Host "     .\Enum-AzureARM.ps1 -ServicePrincipalId <appid> -ServicePrincipalSecret <secret> -TenantId <tenantid>"
    Write-Host ""
    Write-Host "  4. Azure PowerShell Service Principal (enhanced capabilities) " -NoNewline -ForegroundColor Cyan
    Write-Host "[RECOMMENDED FOR CTF]:" -ForegroundColor Green
    Write-Host "     .\Enum-AzureARM.ps1 -UseServicePrincipal -ApplicationId <appid> -ClientSecret <secret> -TenantId <tenantid>"
    Write-Host "     • Automatic resource-specific token acquisition (Storage + Key Vault)" -ForegroundColor Gray
    Write-Host "     • Enhanced blob download with 5-tier authentication system" -ForegroundColor Gray
    Write-Host "     • Comprehensive cross-resource enumeration capabilities" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Yellow
    Write-Host "  -OutputFormat json|csv     (Output format selection)"
    Write-Host "  -OutputFile <path>         (Custom output file path)"
    Write-Host "  -GraphOnly                 (Skip ARM enumeration, use Graph token only)"
    Write-Host "  -NoInteractiveAuth         (Disable interactive authentication helpers)"
    Write-Host "  -AllowNoSubscription       (Allow Graph-only enumeration when no subscription access)"
    Write-Host "  -Verbose                   (Show detailed operation progress)"
    Write-Host "  -Help                      (Show this message)`n"
    
    Write-Host "Usage Examples:" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Basic enumeration with current user:" -ForegroundColor White
    Write-Host "  .\Enum-AzureARM.ps1 -UseCurrentUser -Verbose" -ForegroundColor Green
    Write-Host ""
    Write-Host "  CTF/Red Team: Enhanced service principal enumeration (recommended):" -ForegroundColor White
    Write-Host "  .\Enum-AzureARM.ps1 -UseServicePrincipal \" -ForegroundColor Green
    Write-Host "                       -ApplicationId '12345678-1234-1234-1234-123456789abc' \" -ForegroundColor Green
    Write-Host "                       -ClientSecret 'ABC123XyZ456DefGhi789JklMno012PqrStu' \" -ForegroundColor Green
    Write-Host "                       -TenantId '87654321-4321-4321-4321-cba987654321'" -ForegroundColor Green
    Write-Host "  # Automatically gets Storage + Key Vault tokens for blob downloads" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Standard service principal with Azure CLI:" -ForegroundColor White
    Write-Host "  .\Enum-AzureARM.ps1 -ServicePrincipalId '12345678-1234-1234-1234-123456789abc' \" -ForegroundColor Green
    Write-Host "                       -ServicePrincipalSecret 'ABC123XyZ456DefGhi789JklMno012PqrStu' \" -ForegroundColor Green
    Write-Host "                       -TenantId '87654321-4321-4321-4321-cba987654321'" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Graph-only enumeration with existing token:" -ForegroundColor White
    Write-Host "  .\Enum-AzureARM.ps1 -AccessTokenGraph '<graph_token>' -GraphOnly" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Custom output and format:" -ForegroundColor White
    Write-Host "  .\Enum-AzureARM.ps1 -UseCurrentUser -OutputFormat csv -OutputFile 'MyReport.csv'" -ForegroundColor Green
    Write-Host "`n"
    
    if (-not $Help -and -not $UseCurrentUser -and -not $AccessTokenARM -and -not $AccessTokenGraph -and -not $UseAzureCLI -and -not ($ServicePrincipalId -and $ServicePrincipalSecret -and $TenantId) -and -not ($UseServicePrincipal -and $ApplicationId -and $ClientSecret -and $TenantId)) {
        Write-Host "Error: No authentication method provided." -ForegroundColor Red
    }
    exit 0
}

#region Validation and Initialization

# Validate authentication parameters
function Test-AuthenticationParameters {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Validating authentication parameters..."
    
    # Determine authentication mode based on provided parameters
    $authMode = "Unknown"
    if ($UseCurrentUser) {
        $authMode = "CurrentUser"
    } elseif ($AccessTokenARM -and $AccessTokenGraph) {
        $authMode = "TokenBoth"
    } elseif ($AccessTokenARM) {
        $authMode = "TokenARM"
    } elseif ($AccessTokenGraph) {
        $authMode = "TokenGraph"
    }
    
    Write-Verbose "Authentication mode: $authMode"
    
    # Check if using current user, token-based authentication, or service principal authentication
    if (-not $UseCurrentUser -and [string]::IsNullOrWhiteSpace($AccessTokenARM) -and [string]::IsNullOrWhiteSpace($AccessTokenGraph) -and -not $UseAzureCLI -and -not ($ServicePrincipalId -and $ServicePrincipalSecret -and $TenantId) -and -not ($UseServicePrincipal -and $ApplicationId -and $ClientSecret -and $TenantId)) {
        throw "No authentication method provided. Use -UseCurrentUser, provide access tokens (-AccessTokenARM and/or -AccessTokenGraph), or use service principal authentication.`n`nExamples:`n  .\Enum-AzureARM.ps1 -UseCurrentUser`n  .\Enum-AzureARM.ps1 -AccessTokenARM `"your-arm-token`" -AccountId `"user@example.com`"`n  .\Enum-AzureARM.ps1 -UseServicePrincipal -ApplicationId `"app-id`" -ClientSecret `"secret`" -TenantId `"tenant-id`""
    }
    
    # Validate Azure PowerShell Service Principal parameters
    if ($UseServicePrincipal) {
        if ([string]::IsNullOrWhiteSpace($ApplicationId)) {
            throw "ApplicationId parameter is required when using -UseServicePrincipal. Please provide a valid Application/Client ID."
        }
        if ([string]::IsNullOrWhiteSpace($ClientSecret)) {
            throw "ClientSecret parameter is required when using -UseServicePrincipal. Please provide a valid client secret."
        }
        if ([string]::IsNullOrWhiteSpace($TenantId)) {
            throw "TenantId parameter is required when using -UseServicePrincipal. Please provide a valid tenant ID."
        }
    }
    
    # Validate required parameters for different scenarios
    if (-not [string]::IsNullOrWhiteSpace($AccessTokenARM)) {
        if ([string]::IsNullOrWhiteSpace($AccountId)) {
            throw "AccountId parameter is required when using AccessTokenARM. Please provide a valid Account ID (UPN or Object ID).`n`nExample:`n  .\Enum-AzureARM.ps1 -AccessTokenARM `"your-token`" -AccountId `"user@example.com`""
        }
    }
    
    # Validate tokens are not just whitespace if provided
    if ($PSBoundParameters.ContainsKey('AccessTokenARM') -and [string]::IsNullOrWhiteSpace($AccessTokenARM)) {
        throw "AccessTokenARM parameter cannot be empty or whitespace. Please provide a valid ARM access token or remove the parameter."
    }
    
    if ($PSBoundParameters.ContainsKey('AccessTokenGraph') -and [string]::IsNullOrWhiteSpace($AccessTokenGraph)) {
        throw "AccessTokenGraph parameter cannot be empty or whitespace. Please provide a valid Graph access token or remove the parameter."
    }
    
    # Validate OutputFile is not null or empty
    if ([string]::IsNullOrWhiteSpace($OutputFile)) {
        throw "OutputFile parameter cannot be null or empty."
    }
    
    # Determine what checks will be performed
    $Script:PerformARMChecks = $false
    $Script:PerformGraphChecks = $false
    
    if ($UseCurrentUser) {
        # CurrentUser mode attempts both ARM and Graph
        $Script:PerformARMChecks = $true
        $Script:PerformGraphChecks = $true
        Write-Verbose "CurrentUser mode: Both ARM and Graph checks will be attempted"
    } elseif ($UseAzureCLI -or ($ServicePrincipalId -and $ServicePrincipalSecret -and $TenantId)) {
        # Azure CLI mode with service principal authentication
        $Script:PerformARMChecks = $true
        $Script:PerformGraphChecks = $true
        $Script:UseAzureCLI = $true
        Write-Verbose "Azure CLI mode: Service principal authentication will be attempted"
    } elseif ($UseServicePrincipal -and $ApplicationId -and $ClientSecret -and $TenantId) {
        # Azure PowerShell Service Principal mode
        $Script:PerformARMChecks = $true
        $Script:PerformGraphChecks = $true
        $Script:ServicePrincipalMode = $true
        Write-Verbose "Azure PowerShell Service Principal mode: Connect-AzAccount with service principal will be used"
    } else {
        if ($AccessTokenARM) {
            $Script:PerformARMChecks = $true
            Write-Verbose "ARM token provided: ARM resource checks will be performed"
        }
        if ($AccessTokenGraph) {
            $Script:PerformGraphChecks = $true
            Write-Verbose "Graph token provided: Graph user checks will be performed"
        }
    }
    
    # Validate output file extension matches format
    if ($OutputFile -notmatch "\.(?:json|csv)$") {
        Write-Warning "Output file extension does not match format. Adjusting..."
        if ($OutputFormat -eq "json") {
            $Script:OutputFile = [System.IO.Path]::ChangeExtension($OutputFile, "json")
        } else {
            $Script:OutputFile = [System.IO.Path]::ChangeExtension($OutputFile, "csv")
        }
    }
    
    Write-Verbose "Authentication parameters validated successfully."
    Write-Verbose "Will perform ARM checks: $Script:PerformARMChecks"
    Write-Verbose "Will perform Graph checks: $Script:PerformGraphChecks"
}

try {
    Test-AuthenticationParameters
} catch {
    Write-Error "Validation Error: $($_.Exception.Message)"
    Write-Host "`nUse 'Get-Help .\Enum-AzureARM.ps1' for detailed usage information." -ForegroundColor Yellow
    exit 1
}

# Global SSL certificate error handling
$Script:SSLBypassEnabled = $false
$Script:OriginalCertificateCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
$Script:OriginalAzureCLIVerification = $env:AZURE_CLI_DISABLE_CONNECTION_VERIFICATION

function Enable-SSLBypass {
    <#
    .SYNOPSIS
        Globally disables SSL certificate verification for all operations.
    #>
    param(
        [string]$Reason = "SSL certificate error detected"
    )
    
    if (-not $Script:SSLBypassEnabled) {
        Write-Warning "SSL Certificate Bypass Activated"
        Write-Warning "Reason: $Reason"
        Write-Warning "This is common in CTF/lab environments with self-signed certificates"
        Write-Warning "All SSL certificate verification will be disabled for this session"
        
        # Disable .NET certificate validation
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        
        # Disable Azure CLI certificate verification
        $env:AZURE_CLI_DISABLE_CONNECTION_VERIFICATION = "1"
        
        # Set PowerShell session preference for Invoke-RestMethod/Invoke-WebRequest
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
            $PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
        }
        
        $Script:SSLBypassEnabled = $true
        Write-Host "SSL certificate verification disabled globally" -ForegroundColor Yellow
    }
}

function Disable-SSLBypass {
    <#
    .SYNOPSIS
        Restores original SSL certificate verification settings.
    #>
    if ($Script:SSLBypassEnabled) {
        Write-Verbose "Restoring SSL certificate verification settings"
        
        # Restore .NET certificate validation
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $Script:OriginalCertificateCallback
        
        # Restore Azure CLI certificate verification
        if ($Script:OriginalAzureCLIVerification) {
            $env:AZURE_CLI_DISABLE_CONNECTION_VERIFICATION = $Script:OriginalAzureCLIVerification
        } else {
            Remove-Item Env:AZURE_CLI_DISABLE_CONNECTION_VERIFICATION -ErrorAction SilentlyContinue
        }
        
        # Remove PowerShell session preferences
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $PSDefaultParameterValues.Remove('Invoke-RestMethod:SkipCertificateCheck')
            $PSDefaultParameterValues.Remove('Invoke-WebRequest:SkipCertificateCheck')
        }
        
        $Script:SSLBypassEnabled = $false
        Write-Verbose "SSL certificate verification restored"
    }
}

function Test-SSLConnectivity {
    <#
    .SYNOPSIS
        Tests basic SSL connectivity and enables bypass if certificate errors are detected.
    #>
    param(
        [string]$TestUri = "https://management.azure.com/"
    )
    
    if ($Script:SSLBypassEnabled) {
        return # Already bypassed
    }
    
    try {
        Write-Debug "Testing SSL connectivity to: $TestUri"
        $null = Invoke-RestMethod -Uri $TestUri -Method HEAD -TimeoutSec 10 -ErrorAction Stop
        Write-Debug "SSL connectivity test successful"
    } catch {
        if ($_.Exception.Message -like "*SSL*" -or 
            $_.Exception.Message -like "*certificate*" -or 
            $_.Exception.Message -like "*CERTIFICATE_VERIFY_FAILED*" -or
            $_.Exception.Message -like "*self-signed*") {
            
            Enable-SSLBypass -Reason "SSL connectivity test failed: $($_.Exception.Message)"
        } else {
            Write-Debug "SSL connectivity test failed for non-certificate reason: $($_.Exception.Message)"
        }
    }
}

# Test SSL connectivity early in the process
Test-SSLConnectivity

# Cleanup function to restore SSL settings on exit
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    if ($Script:SSLBypassEnabled) {
        Disable-SSLBypass
    }
}

# Generate dynamic filename if using default
if ($OutputFile -eq "Results\AzureResourcesOutput.json") {
    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
    $accountIdentifier = "unknown"
    
    # Try to get account identifier from different sources
    if ($AccountId) {
        $accountIdentifier = $AccountId -replace '[\\/:*?"<>|]', '_'  # Sanitize filename
    } else {
        try {
            # Try to get from current Azure context
            $context = Get-AzContext -ErrorAction SilentlyContinue
            if ($context -and $context.Account.Id) {
                $accountIdentifier = $context.Account.Id -replace '[\\/:*?"<>|]', '_'
            } elseif ($Script:PerformGraphChecks) {
                # Will be updated later when Graph user details are retrieved
                $accountIdentifier = "pending"
            }
        } catch {
            Write-Verbose "Could not determine account identifier: $($_.Exception.Message)"
        }
    }
    
    $filename = "${accountIdentifier}_${timestamp}_AzureResources.json"
    $OutputFile = Join-Path "Results" $filename
    Write-Verbose "Generated dynamic filename: $OutputFile"
}

# Ensure Results directory exists
$ResultsDir = "Results"
if (-not (Test-Path $ResultsDir)) {
    New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
    Write-Verbose "Created Results directory: $ResultsDir"
}

# Ensure output file path includes Results directory
if ($OutputFile -notmatch "^Results\\") {
    $OutputFile = Join-Path $ResultsDir (Split-Path $OutputFile -Leaf)
    Write-Verbose "Updated output file path: $OutputFile"
}

#endregion


#region Helper Functions

function Request-UserConfirmation {
    <#
    .SYNOPSIS
        Prompts the user for confirmation with a timeout. Default is NO.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [int]$TimeoutSeconds = $Script:UserPromptTimeout,
        
        [Parameter(Mandatory=$false)]
        [switch]$DefaultYes
    )
    
    $defaultChoice = if ($DefaultYes) { "Yes" } else { "No" }
    $choices = if ($DefaultYes) { "[Y/n]" } else { "[y/N]" }
    
    Write-Host ""
    Write-Host $Message -ForegroundColor Yellow
    Write-Host "Default: $defaultChoice (timeout: ${TimeoutSeconds}s) $choices" -ForegroundColor Gray
    Write-Host -NoNewline "Your choice: " -ForegroundColor Cyan
    
    # Start a job to handle the timeout
    $job = Start-Job -ScriptBlock {
        param($timeout)
        Start-Sleep -Seconds $timeout
        return "TIMEOUT"
    } -ArgumentList $TimeoutSeconds
    
    $response = $null
    $startTime = Get-Date
    
    while ((Get-Date) - $startTime -lt [TimeSpan]::FromSeconds($TimeoutSeconds)) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq 'Enter') {
                $response = ""
                break
            } elseif ($key.KeyChar -match '^[YyNn]$') {
                $response = $key.KeyChar.ToString().ToUpper()
                Write-Host $response
                break
            }
        }
        Start-Sleep -Milliseconds 100
    }
    
    Stop-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -ErrorAction SilentlyContinue
    
    if ($null -eq $response) {
        Write-Host ""
        Write-Host "Timeout reached. Using default: $defaultChoice" -ForegroundColor Yellow
        $response = ""
    }
    
    # Determine the result
    if ([string]::IsNullOrEmpty($response)) {
        return $DefaultYes.IsPresent
    } elseif ($response -eq "Y") {
        return $true
    } else {
        return $false
    }
}

function Invoke-AuthenticationFix {
    <#
    .SYNOPSIS
        Attempts to fix authentication issues automatically.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("ARM", "Graph", "Both")]
        [string]$FixType,
        
        [Parameter(Mandatory=$false)]
        [switch]$Interactive
    )
    
    $result = @{
        Success = $false
        ARMFixed = $false
        GraphFixed = $false
        Message = ""
    }
    
    try {
        Write-Host ""
        Write-Host "🔧 AUTHENTICATION HELPER" -ForegroundColor Cyan
        Write-Host "=========================" -ForegroundColor Cyan
        
        if ($FixType -eq "ARM" -or $FixType -eq "Both") {
            Write-Host "Issue: ARM access token could not be retrieved from current context" -ForegroundColor Yellow
            Write-Host "This usually means you're not authenticated to Azure PowerShell or Azure CLI" -ForegroundColor Gray
            Write-Host ""
            
            if ($Interactive.IsPresent) {
                $tryFix = Request-UserConfirmation -Message "Would you like me to attempt automatic authentication to Azure?"
                
                if ($tryFix) {
                    Write-Host "🔄 Attempting to fix Azure authentication..." -ForegroundColor Green
                    
                    # Try Connect-AzAccount first
                    try {
                        Write-Host "Trying Azure PowerShell authentication (Connect-AzAccount)..." -ForegroundColor Cyan
                        $azContext = Connect-AzAccount -ErrorAction Stop
                        if ($azContext) {
                            Write-Host "✅ Azure PowerShell authentication successful!" -ForegroundColor Green
                            $result.ARMFixed = $true
                            $result.Success = $true
                        }
                    } catch {
                        Write-Host "❌ Azure PowerShell authentication failed: $($_.Exception.Message)" -ForegroundColor Red
                        
                        # Try Azure CLI as fallback
                        try {
                            Write-Host "Trying Azure CLI authentication (az login)..." -ForegroundColor Cyan
                            $azLogin = az login --output json 2>&1
                            if ($LASTEXITCODE -eq 0) {
                                Write-Host "✅ Azure CLI authentication successful!" -ForegroundColor Green
                                $result.ARMFixed = $true
                                $result.Success = $true
                            }
                        } catch {
                            Write-Host "❌ Azure CLI authentication also failed: $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                } else {
                    Write-Host "Authentication fix skipped by user." -ForegroundColor Gray
                }
            }
        }
        
        if ($FixType -eq "Graph" -or $FixType -eq "Both") {
            Write-Host "Issue: Microsoft Graph access is not available" -ForegroundColor Yellow
            Write-Host "This usually means you're not connected to Microsoft Graph" -ForegroundColor Gray
            Write-Host ""
            
            if ($Interactive.IsPresent) {
                $tryGraphFix = Request-UserConfirmation -Message "Would you like me to attempt Microsoft Graph authentication?"
                
                if ($tryGraphFix) {
                    Write-Host "🔄 Attempting to fix Microsoft Graph authentication..." -ForegroundColor Green
                    
                    try {
                        Write-Host "Connecting to Microsoft Graph with basic permissions..." -ForegroundColor Cyan
                        Connect-MgGraph -Scopes "User.Read", "Directory.Read.All" -NoWelcome -ErrorAction Stop
                        Write-Host "✅ Microsoft Graph authentication successful!" -ForegroundColor Green
                        $result.GraphFixed = $true
                        $result.Success = $true
                    } catch {
                        Write-Host "❌ Microsoft Graph authentication failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Graph authentication fix skipped by user." -ForegroundColor Gray
                }
            }
        }
        
        if ($result.Success) {
            Write-Host ""
            Write-Host "🎉 Authentication fix completed! Please run the script again." -ForegroundColor Green
            $result.Message = "Authentication successfully fixed. Re-run the script to use new authentication."
        } else {
            Write-Host ""
            Write-Host "⚠️ Automatic fix was not successful or was skipped." -ForegroundColor Yellow
            Write-Host "Manual authentication options:" -ForegroundColor Cyan
            Write-Host "  1. Azure PowerShell: Connect-AzAccount" -ForegroundColor White
            Write-Host "  2. Azure CLI: az login" -ForegroundColor White
            Write-Host "  3. Microsoft Graph: Connect-MgGraph -Scopes 'User.Read','Directory.Read.All'" -ForegroundColor White
            Write-Host "  4. Use token-based authentication with -AccessTokenARM and -AccessTokenGraph parameters" -ForegroundColor White
            $result.Message = "Automatic fix not applied. Manual authentication required."
        }
        
    } catch {
        $result.Message = "Error during authentication fix: $($_.Exception.Message)"
        Write-Host "❌ Error during authentication fix: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $result
}

function Select-AzureSubscription {
    <#
    .SYNOPSIS
        Interactive subscription selection when multiple subscriptions are available.
    .DESCRIPTION
        Lists available Azure subscriptions and prompts user to select one, with fallback to first accessible subscription.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$false)]
        [switch]$AllowNoSubscription,
        
        [Parameter(Mandatory=$false)]
        [switch]$NonInteractive
    )
    
    $result = @{
        SubscriptionId = $null
        SubscriptionName = $null
        TenantId = $null
        Success = $false
        UserCancelled = $false
    }
    
    try {
        Write-Host "🔍 Discovering available Azure subscriptions..." -ForegroundColor Cyan
        
        # Get available subscriptions
        $subscriptions = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions?api-version=2022-12-01" -Headers @{
            'Authorization' = "Bearer $AccessToken"
            'Content-Type' = 'application/json'
        } -Method GET
        
        if (-not $subscriptions -or -not $subscriptions.value -or $subscriptions.value.Count -eq 0) {
            if ($AllowNoSubscription) {
                Write-Host "⚠️ No accessible subscriptions found, but continuing with Graph-only enumeration..." -ForegroundColor Yellow
                $result.Success = $true
                return $result
            } else {
                Write-Host "❌ No accessible Azure subscriptions found." -ForegroundColor Red
                Write-Host "Use -AllowNoSubscription to continue with Graph-only enumeration." -ForegroundColor Gray
                return $result
            }
        }
        
        $subList = $subscriptions.value | Sort-Object displayName
        
        if ($subList.Count -eq 1) {
            # Only one subscription available - use it automatically
            $selectedSub = $subList[0]
            Write-Host "✅ Found single accessible subscription: " -NoNewline -ForegroundColor Green
            Write-Host "$($selectedSub.displayName) ($($selectedSub.subscriptionId))" -ForegroundColor White
            
            $result.SubscriptionId = $selectedSub.subscriptionId
            $result.SubscriptionName = $selectedSub.displayName
            $result.TenantId = $selectedSub.tenantId
            $result.Success = $true
            return $result
        }
        
        if ($NonInteractive) {
            # Non-interactive mode - use first subscription
            $selectedSub = $subList[0]
            Write-Host "⚠️ Non-interactive mode: Using first available subscription: " -NoNewline -ForegroundColor Yellow
            Write-Host "$($selectedSub.displayName) ($($selectedSub.subscriptionId))" -ForegroundColor White
            
            $result.SubscriptionId = $selectedSub.subscriptionId
            $result.SubscriptionName = $selectedSub.displayName
            $result.TenantId = $selectedSub.tenantId
            $result.Success = $true
            return $result
        }
        
        # Multiple subscriptions - show selection menu
        Write-Host ""
        Write-Host "📋 Multiple Azure subscriptions found:" -ForegroundColor Cyan
        Write-Host "=" * 50 -ForegroundColor Gray
        
        for ($i = 0; $i -lt $subList.Count; $i++) {
            $sub = $subList[$i]
            Write-Host "$($i + 1). " -NoNewline -ForegroundColor Yellow
            Write-Host "$($sub.displayName)" -NoNewline -ForegroundColor White
            Write-Host " ($($sub.subscriptionId))" -ForegroundColor Gray
        }
        
        if ($AllowNoSubscription) {
            Write-Host "$($subList.Count + 1). " -NoNewline -ForegroundColor Yellow
            Write-Host "Continue without subscription (Graph-only)" -ForegroundColor Cyan
        }
        
        Write-Host "0. " -NoNewline -ForegroundColor Red
        Write-Host "Exit" -ForegroundColor Red
        Write-Host ""
        
        # Get user selection
        do {
            $maxChoice = if ($AllowNoSubscription) { $subList.Count + 1 } else { $subList.Count }
            Write-Host "Select subscription (1-$maxChoice, or 0 to exit): " -NoNewline -ForegroundColor Cyan
            
            $selection = $null
            if ([Console]::IsInputRedirected) {
                # Fallback for non-interactive environments
                $selection = "1"
                Write-Host $selection
            } else {
                $selection = Read-Host
            }
            
            if ($selection -eq "0") {
                Write-Host "❌ Operation cancelled by user." -ForegroundColor Red
                $result.UserCancelled = $true
                return $result
            }
            
            if ($AllowNoSubscription -and $selection -eq ($subList.Count + 1).ToString()) {
                Write-Host "✅ Continuing with Graph-only enumeration..." -ForegroundColor Green
                $result.Success = $true
                return $result
            }
            
            $selectionNum = 0
            if ([int]::TryParse($selection, [ref]$selectionNum) -and $selectionNum -ge 1 -and $selectionNum -le $subList.Count) {
                $selectedSub = $subList[$selectionNum - 1]
                
                Write-Host "✅ Selected: " -NoNewline -ForegroundColor Green
                Write-Host "$($selectedSub.displayName) ($($selectedSub.subscriptionId))" -ForegroundColor White
                
                $result.SubscriptionId = $selectedSub.subscriptionId
                $result.SubscriptionName = $selectedSub.displayName
                $result.TenantId = $selectedSub.tenantId
                $result.Success = $true
                return $result
            } else {
                Write-Host "❌ Invalid selection. Please enter a number between 1 and $maxChoice (or 0 to exit)." -ForegroundColor Red
            }
        } while ($true)
        
    } catch {
        Write-Host "❌ Error discovering subscriptions: $($_.Exception.Message)" -ForegroundColor Red
        if ($AllowNoSubscription) {
            Write-Host "⚠️ Continuing with Graph-only enumeration..." -ForegroundColor Yellow
            $result.Success = $true
        }
        return $result
    }
}

function Invoke-ARMRequest {
    <#
    .SYNOPSIS
        Invoke Azure ARM REST API calls with proper error handling.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        
        [Parameter(Mandatory=$false)]
        [string]$Method = "GET",
        
        [Parameter(Mandatory=$false)]
        $Body = $null,
        
        [Parameter(Mandatory=$false)]
        [int]$RetryCount = 3,
        
        [Parameter(Mandatory=$false)]
        [int]$RetryDelaySeconds = 2,
        
        [Parameter(Mandatory=$false)]
        [switch]$SuppressWarnings
    )
    
    if (-not $AccessTokenARM) {
        Write-Warning "No ARM access token available for request to: $Uri"
        return $null
    }
    
    $headers = @{ 
        "Authorization" = "Bearer $AccessTokenARM"
        "Content-Type" = "application/json"
        "User-Agent" = "AzureEnumerationScript/2.0"
    }
    
    $bodyJson = if ($Body) { $Body | ConvertTo-Json -Depth 10 } else { $null }
    
    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        try {
            Write-Debug "ARM REST call (attempt $attempt): $Uri"
            
            $response = Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method -Body $bodyJson -ErrorAction Stop
            
            if ($response -and $response.value) {
                Write-Debug "ARM response received; items count: $($response.value.Count)"
            } elseif ($response) {
                Write-Debug "ARM response received; single item or metadata"
            } else {
                Write-Debug "ARM response received; empty or null"
            }
            
            return $response
            
        } catch [System.Net.WebException] {
            $statusCode = $_.Exception.Response.StatusCode
            
            # Check for SSL certificate errors and enable global bypass
            if ($_.Exception.Message -like "*SSL*" -or 
                $_.Exception.Message -like "*certificate*" -or 
                $_.Exception.Message -like "*CERTIFICATE_VERIFY_FAILED*" -or
                $_.Exception.Message -like "*self-signed*") {
                
                if (-not $Script:SSLBypassEnabled) {
                    Enable-SSLBypass -Reason "ARM API SSL error: $($_.Exception.Message)"
                    
                    # Retry this request immediately with SSL bypass enabled
                    Write-Debug "Retrying ARM request with SSL bypass: $Uri"
                    try {
                        $response = Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method -Body $bodyJson -ErrorAction Stop
                        return $response
                    } catch {
                        Write-Debug "ARM request still failed after SSL bypass: $($_.Exception.Message)"
                        # Continue with normal error handling below
                    }
                }
            }
            
            if (-not $SuppressWarnings) {
                Write-Warning "ARM call failed (attempt $attempt/$RetryCount) - Status: $statusCode, URI: $Uri"
            }
            
            if ($statusCode -eq 'Unauthorized' -or $statusCode -eq 'Forbidden') {
                # Provide enhanced error guidance for auth failures
                if ($statusCode -eq 'Unauthorized' -and $Script:ARMTokenTenant -and $Script:SubscriptionTenant -and $Script:ARMTokenTenant -ne $Script:SubscriptionTenant) {
                    Write-Error "Authentication failed: Token tenant mismatch detected. ARM token is for tenant '$Script:ARMTokenTenant' but subscription is in tenant '$Script:SubscriptionTenant'. Please get a token for the correct tenant."
                } elseif ($statusCode -eq 'Unauthorized') {
                    Write-Error "Authentication failed: ARM token may be expired, invalid, or lacks permissions for: $Uri"
                } else {
                    Write-Error "Authorization failed: Insufficient permissions for: $Uri"
                }
                return $null
            }
            
            if ($attempt -eq $RetryCount) {
                Write-Error "ARM call permanently failed after $RetryCount attempts: $Uri - Error: $($_.Exception.Message)"
                return $null
            }
            
            Start-Sleep -Seconds ($RetryDelaySeconds * $attempt)
            
        } catch {
            # Check for SSL certificate errors in general exceptions too
            if ($_.Exception.Message -like "*SSL*" -or 
                $_.Exception.Message -like "*certificate*" -or 
                $_.Exception.Message -like "*CERTIFICATE_VERIFY_FAILED*" -or
                $_.Exception.Message -like "*self-signed*") {
                
                if (-not $Script:SSLBypassEnabled) {
                    Enable-SSLBypass -Reason "ARM API SSL error: $($_.Exception.Message)"
                    
                    # Retry this request immediately with SSL bypass enabled
                    Write-Debug "Retrying ARM request with SSL bypass: $Uri"
                    try {
                        $response = Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method -Body $bodyJson -ErrorAction Stop
                        return $response
                    } catch {
                        Write-Debug "ARM request still failed after SSL bypass: $($_.Exception.Message)"
                        # Continue with normal error handling below
                    }
                }
            }
            if (-not $SuppressWarnings) {
                Write-Warning "ARM call failed (attempt $attempt/$RetryCount) on $Uri with error: $($_.Exception.Message)"
            }
            
            if ($attempt -eq $RetryCount) {
                Write-Warning "ARM call permanently failed after $RetryCount attempts: $Uri"
                return $null
            }
            
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
    
    return $null
}

function Invoke-GraphRequest {
    <#
    .SYNOPSIS
        Invoke Microsoft Graph API calls with proper error handling.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        
        [Parameter(Mandatory=$false)]
        [string]$Method = "GET",
        
        [Parameter(Mandatory=$false)]
        $Body = $null,
        
        [Parameter(Mandatory=$false)]
        [int]$RetryCount = 3,
        
        [Parameter(Mandatory=$false)]
        [int]$RetryDelaySeconds = 2
    )
    
    if (-not $AccessTokenGraph) {
        Write-Warning "No Graph access token available for request to: $Uri"
        return $null
    }
    
    $headers = @{ 
        "Authorization" = "Bearer $AccessTokenGraph"
        "Content-Type" = "application/json"
        "User-Agent" = "AzureEnumerationScript/2.0"
    }
    
    $bodyJson = if ($Body) { $Body | ConvertTo-Json -Depth 10 } else { $null }
    
    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        try {
            Write-Debug "Graph REST call (attempt $attempt): $Uri"
            
            $response = Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method -Body $bodyJson -ErrorAction Stop
            
            if ($response -and $response.value) {
                Write-Debug "Graph response received; items count: $($response.value.Count)"
            } elseif ($response) {
                Write-Debug "Graph response received; single item or metadata"
            } else {
                Write-Debug "Graph response received; empty or null"
            }
            
            return $response
            
        } catch [System.Net.WebException] {
            $statusCode = $_.Exception.Response.StatusCode
            
            # Check for SSL certificate errors and enable global bypass
            if ($_.Exception.Message -like "*SSL*" -or 
                $_.Exception.Message -like "*certificate*" -or 
                $_.Exception.Message -like "*CERTIFICATE_VERIFY_FAILED*" -or
                $_.Exception.Message -like "*self-signed*") {
                
                if (-not $Script:SSLBypassEnabled) {
                    Enable-SSLBypass -Reason "Graph API SSL error: $($_.Exception.Message)"
                    
                    # Retry this request immediately with SSL bypass enabled
                    Write-Debug "Retrying Graph request with SSL bypass: $Uri"
                    try {
                        $response = Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method -Body $bodyJson -ErrorAction Stop
                        return $response
                    } catch {
                        Write-Debug "Graph request still failed after SSL bypass: $($_.Exception.Message)"
                        # Continue with normal error handling below
                    }
                }
            }
            
            Write-Warning "Graph call failed (attempt $attempt/$RetryCount) - Status: $statusCode, URI: $Uri"
            
            if ($statusCode -eq 'Unauthorized' -or $statusCode -eq 'Forbidden') {
                Write-Error "Authentication/Authorization failed for: $Uri"
                return $null
            }
            
            if ($attempt -eq $RetryCount) {
                Write-Error "Graph call permanently failed after $RetryCount attempts: $Uri - Error: $($_.Exception.Message)"
                return $null
            }
            
            Start-Sleep -Seconds ($RetryDelaySeconds * $attempt)
            
        } catch {
            # Check for SSL certificate errors in general exceptions too
            if ($_.Exception.Message -like "*SSL*" -or 
                $_.Exception.Message -like "*certificate*" -or 
                $_.Exception.Message -like "*CERTIFICATE_VERIFY_FAILED*" -or
                $_.Exception.Message -like "*self-signed*") {
                
                if (-not $Script:SSLBypassEnabled) {
                    Enable-SSLBypass -Reason "Graph API SSL error: $($_.Exception.Message)"
                    
                    # Retry this request immediately with SSL bypass enabled
                    Write-Debug "Retrying Graph request with SSL bypass: $Uri"
                    try {
                        $response = Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method -Body $bodyJson -ErrorAction Stop
                        return $response
                    } catch {
                        Write-Debug "Graph request still failed after SSL bypass: $($_.Exception.Message)"
                        # Continue with normal error handling below
                    }
                }
            }
            
            Write-Warning "Graph call failed (attempt $attempt/$RetryCount) on $Uri with error: $($_.Exception.Message)"
            
            if ($attempt -eq $RetryCount) {
                Write-Error "Graph call permanently failed after $RetryCount attempts: $Uri"
                return $null
            }
            
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
    
    return $null
}


function Get-AzAccessTokenFromContext {
    <#
    .SYNOPSIS
        Retrieves Azure ARM access token from current Az context.
    #>
    [CmdletBinding()]
    param()
    
    try {
        $context = Get-AzContext -ErrorAction Stop
        if (-not $context) {
            Write-Warning "No Azure context found. Please run Connect-AzAccount first."
            return $null
        }
        
        Write-Verbose "Retrieving access token for ARM endpoint..."
        $tokenResult = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop
        
        if ($tokenResult -and $tokenResult.Token) {
            # Handle both SecureString and plain string tokens
            if ($tokenResult.Token -is [System.Security.SecureString]) {
                $plainToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenResult.Token)
                )
                return $plainToken
            } else {
                return $tokenResult.Token
            }
        }
        
        Write-Warning "Could not retrieve access token from context."
        return $null
        
    } catch {
        Write-Warning "Failed to get access token from Az context: $($_.Exception.Message)"
        return $null
    }
}

function Get-ResourceSpecificTokens {
    <#
    .SYNOPSIS
        Retrieves resource-specific access tokens for Storage and Key Vault operations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("Storage", "KeyVault", "Both")]
        [string]$TokenType = "Both",
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowGuidance
    )
    
    $result = @{
        StorageToken = $null
        KeyVaultToken = $null
        Success = $false
        Error = $null
        Guidance = @()
    }
    
    try {
        # Check if Azure CLI is available and authenticated
        $azCli = Get-Command az -ErrorAction SilentlyContinue
        if (-not $azCli) {
            $result.Error = "Azure CLI (az) is not installed or not available in PATH"
            return $result
        }
        
        # Check if we're logged in
        $accountCheck = az account show --output json 2>&1
        if ($LASTEXITCODE -ne 0) {
            $result.Error = "Not authenticated with Azure CLI. Please run 'az login' first."
            return $result
        }
        
        # Get Storage token
        if ($TokenType -eq "Storage" -or $TokenType -eq "Both") {
            try {
                Write-Verbose "Acquiring Storage access token from Azure CLI..."
                $storageTokenJson = az account get-access-token --resource=https://storage.azure.com/ --output json 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $storageTokenObj = $storageTokenJson | ConvertFrom-Json
                    $result.StorageToken = $storageTokenObj.accessToken
                    $Script:StorageToken = $result.StorageToken
                    Write-Verbose "Storage token acquired successfully"
                } else {
                    Write-Warning "Failed to get Storage token from Azure CLI: $storageTokenJson"
                    $result.Guidance += @{
                        Resource = "Storage"
                        ManualCommand = "az account get-access-token --resource=https://storage.azure.com/"
                        Usage = "Use for direct blob/file operations when RBAC permissions are insufficient"
                    }
                }
            } catch {
                Write-Warning "Error getting Storage token: $($_.Exception.Message)"
                $result.Guidance += @{
                    Resource = "Storage"
                    Error = $_.Exception.Message
                    ManualCommand = "az account get-access-token --resource=https://storage.azure.com/"
                }
            }
        }
        
        # Get Key Vault token
        if ($TokenType -eq "KeyVault" -or $TokenType -eq "Both") {
            try {
                Write-Verbose "Acquiring Key Vault access token from Azure CLI..."
                $kvTokenJson = az account get-access-token --resource=https://vault.azure.net/ --output json 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $kvTokenObj = $kvTokenJson | ConvertFrom-Json
                    $result.KeyVaultToken = $kvTokenObj.accessToken
                    $Script:KeyVaultToken = $result.KeyVaultToken
                    Write-Verbose "Key Vault token acquired successfully"
                } else {
                    Write-Warning "Failed to get Key Vault token from Azure CLI: $kvTokenJson"
                    $result.Guidance += @{
                        Resource = "KeyVault"
                        ManualCommand = "az account get-access-token --resource=https://vault.azure.net/"
                        Usage = "Use for direct Key Vault secret operations"
                    }
                }
            } catch {
                Write-Warning "Error getting Key Vault token: $($_.Exception.Message)"
                $result.Guidance += @{
                    Resource = "KeyVault"
                    Error = $_.Exception.Message
                    ManualCommand = "az account get-access-token --resource=https://vault.azure.net/"
                }
            }
        }
        
        $result.Success = ($result.StorageToken -or $result.KeyVaultToken)
        
        # Show guidance if requested or if tokens failed
        if ($ShowGuidance -or $result.Guidance.Count -gt 0) {
            Show-ResourceTokenGuidance -TokenResults $result
        }
        
        return $result
        
    } catch {
        $result.Error = "Failed to get resource-specific tokens: $($_.Exception.Message)"
        return $result
    }
}

function Show-ResourceTokenGuidance {
    <#
    .SYNOPSIS
        Shows guidance for manually obtaining resource-specific tokens.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$TokenResults
    )
    
    if ($TokenResults.Guidance.Count -eq 0) {
        return
    }
    
    Write-Host "`n" -NoNewline
    Write-Host "RESOURCE TOKEN GUIDANCE" -ForegroundColor Yellow
    Write-Host "========================" -ForegroundColor Yellow
    Write-Host "Some operations require resource-specific tokens instead of ARM management tokens.`n" -ForegroundColor Gray
    
    foreach ($guidance in $TokenResults.Guidance) {
        Write-Host "Resource: $($guidance.Resource)" -ForegroundColor Cyan
        Write-Host "Manual Token Command:" -ForegroundColor White
        Write-Host "  $($guidance.ManualCommand)" -ForegroundColor Green
        
        if ($guidance.Usage) {
            Write-Host "Usage: $($guidance.Usage)" -ForegroundColor Gray
        }
        
        if ($guidance.Error) {
            Write-Host "Error: $($guidance.Error)" -ForegroundColor Red
        }
        
        # Show specific usage examples
        if ($guidance.Resource -eq "Storage") {
            Write-Host "`nStorage Token Usage Examples:" -ForegroundColor Yellow
            Write-Host "  # Get token" -ForegroundColor Gray
            Write-Host "  `$storageToken = (az account get-access-token --resource=https://storage.azure.com/ | ConvertFrom-Json).accessToken" -ForegroundColor White
            Write-Host "  # Use with direct REST API calls" -ForegroundColor Gray
            Write-Host "  `$headers = @{ 'Authorization' = \"Bearer `$storageToken\"; 'x-ms-version' = '2020-10-02' }" -ForegroundColor White
            Write-Host "  Invoke-WebRequest -Uri \"https://storageaccount.blob.core.windows.net/container/blob\" -Headers `$headers" -ForegroundColor White
        }
        
        if ($guidance.Resource -eq "KeyVault") {
            Write-Host "`nKey Vault Token Usage Examples:" -ForegroundColor Yellow
            Write-Host "  # Get token" -ForegroundColor Gray
            Write-Host "  `$kvToken = (az account get-access-token --resource=https://vault.azure.net/ | ConvertFrom-Json).accessToken" -ForegroundColor White
            Write-Host "  # Use with direct REST API calls" -ForegroundColor Gray
            Write-Host "  `$headers = @{ 'Authorization' = \"Bearer `$kvToken\" }" -ForegroundColor White
            Write-Host "  Invoke-RestMethod -Uri \"https://keyvault.vault.azure.net/secrets/secretname?api-version=7.3\" -Headers `$headers" -ForegroundColor White
        }
        
        Write-Host ""
    }
    
    Write-Host "Alternative: PowerShell Module Methods" -ForegroundColor Yellow
    Write-Host "  # For Storage (requires Az.Storage module)" -ForegroundColor Gray
    Write-Host "  Connect-AzAccount" -ForegroundColor White
    Write-Host "  `$ctx = New-AzStorageContext -StorageAccountName 'account' -UseConnectedAccount" -ForegroundColor White
    Write-Host "  Get-AzStorageBlobContent -Container 'container' -Blob 'file' -Context `$ctx" -ForegroundColor White
    Write-Host ""
    Write-Host "  # For Key Vault (requires Az.KeyVault module)" -ForegroundColor Gray
    Write-Host "  Connect-AzAccount" -ForegroundColor White
    Write-Host "  Get-AzKeyVaultSecret -VaultName 'keyvault' -Name 'secretname'" -ForegroundColor White
    Write-Host ""
}

function Get-AccessTokenFromAzureCLI {
    <#
    .SYNOPSIS
        Retrieves access tokens from Azure CLI for ARM and Graph resources.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("ARM", "Graph", "Both")]
        [string]$TokenType = "Both"
    )
    
    $result = @{
        ARMToken = $null
        GraphToken = $null
        Success = $false
        Error = $null
    }
    
    try {
        # Check if Azure CLI is available and authenticated
        $azCli = Get-Command az -ErrorAction SilentlyContinue
        if (-not $azCli) {
            $result.Error = "Azure CLI (az) is not installed or not available in PATH"
            return $result
        }
        
        # Check if we're logged in
        $accountCheck = az account show --output json 2>&1
        if ($LASTEXITCODE -ne 0) {
            $result.Error = "Not authenticated with Azure CLI. Please run 'az login' first."
            Write-Verbose $accountCheck
            return $result
        }
        
        if ($TokenType -eq "ARM" -or $TokenType -eq "Both") {
            try {
                Write-Verbose "Acquiring ARM access token from Azure CLI..."
                $armTokenJson = az account get-access-token --resource=https://management.azure.com/ --output json 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $armTokenObj = $armTokenJson | ConvertFrom-Json
                    $result.ARMToken = $armTokenObj.accessToken
                    Write-Verbose "ARM token acquired successfully"
                } else {
                    Write-Warning "Failed to get ARM token from Azure CLI: $armTokenJson"
                }
            } catch {
                Write-Warning "Error getting ARM token: $($_.Exception.Message)"
            }
        }
        
        if ($TokenType -eq "Graph" -or $TokenType -eq "Both") {
            try {
                Write-Verbose "Acquiring Graph access token from Azure CLI..."
                $graphTokenJson = az account get-access-token --resource=https://graph.microsoft.com --output json 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $graphTokenObj = $graphTokenJson | ConvertFrom-Json
                    $result.GraphToken = $graphTokenObj.accessToken
                    Write-Verbose "Graph token acquired successfully"
                } else {
                    Write-Warning "Failed to get Graph token from Azure CLI: $graphTokenJson"
                }
            } catch {
                Write-Warning "Error getting Graph token: $($_.Exception.Message)"
            }
        }
        
        $result.Success = ($result.ARMToken -or $result.GraphToken)
        return $result
        
    } catch {
        $result.Error = "Failed to get access tokens from Azure CLI: $($_.Exception.Message)"
        return $result
    }
}

function Test-TenantMismatch {
    <#
    .SYNOPSIS
        Detects tenant mismatches between tokens and subscriptions and provides guidance.
    #>
    [CmdletBinding()]
    param()
    
    # Only run if we have ARM token tenant info
    if (-not $Script:ARMTokenTenant) {
        return
    }
    
    Write-Verbose "Checking for tenant mismatches..."
    
    try {
        # Try to get subscription information to determine the subscription's tenant
        if ($AccessTokenARM) {
            Write-Verbose "Discovering accessible subscriptions to check tenant alignment..."
            
            $subscriptionsUri = "https://management.azure.com/subscriptions?api-version=2022-12-01"
            $subscriptions = Invoke-ARMRequest -Uri $subscriptionsUri -SuppressWarnings
            
            if ($subscriptions -and $subscriptions.value -and $subscriptions.value.Count -gt 0) {
                $foundMismatch = $false
                
                foreach ($sub in $subscriptions.value) {
                    if ($sub.tenantId -and $sub.tenantId -ne $Script:ARMTokenTenant) {
                        $foundMismatch = $true
                        $Script:SubscriptionTenant = $sub.tenantId
                        
                        Write-Host "`n" -NoNewline
                        Write-Host "TENANT MISMATCH DETECTED" -ForegroundColor Red -BackgroundColor Yellow
                        Write-Host "=========================" -ForegroundColor Red
                        Write-Host "Token Tenant:        $Script:ARMTokenTenant" -ForegroundColor Yellow
                        Write-Host "Subscription Tenant: $($sub.tenantId)" -ForegroundColor Yellow
                        Write-Host "Subscription:        $($sub.displayName) ($($sub.subscriptionId))" -ForegroundColor Gray
                        Write-Host ""
                        
                        Write-Host "ISSUE EXPLANATION:" -ForegroundColor Cyan
                        Write-Host "Your ARM token was issued for tenant '$Script:ARMTokenTenant'" -ForegroundColor White
                        Write-Host "But you're trying to access subscription '$($sub.displayName)' in tenant '$($sub.tenantId)'" -ForegroundColor White
                        Write-Host "This will result in '401 Unauthorized' errors for ARM API calls." -ForegroundColor Red
                        Write-Host ""
                        
                        Write-Host "SOLUTIONS:" -ForegroundColor Green
                        Write-Host ""
                        Write-Host "Option 1: Get ARM token for correct tenant" -ForegroundColor Cyan
                        Write-Host "  # Azure CLI:" -ForegroundColor Gray
                        Write-Host "  az login --tenant $($sub.tenantId)" -ForegroundColor White
                        Write-Host "  az account get-access-token --resource=https://management.azure.com/" -ForegroundColor White
                        Write-Host ""
                        Write-Host "  # PowerShell:" -ForegroundColor Gray
                        Write-Host "  Connect-AzAccount -Tenant '$($sub.tenantId)'" -ForegroundColor White
                        Write-Host "  `$armToken = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com/').Token" -ForegroundColor White
                        Write-Host ""
                        
                        Write-Host "Option 2: Use Service Principal (if you have SP credentials)" -ForegroundColor Cyan
                        Write-Host "  .\Enum-AzureARM.ps1 -UseServicePrincipal \" -ForegroundColor White
                        Write-Host "                       -ApplicationId '<app-id>' \" -ForegroundColor White
                        Write-Host "                       -ClientSecret '<secret>' \" -ForegroundColor White
                        Write-Host "                       -TenantId '$($sub.tenantId)'" -ForegroundColor White
                        Write-Host ""
                        
                        Write-Host "Option 3: Continue with Graph-only enumeration (if Graph token is valid)" -ForegroundColor Cyan
                        if ($Script:GraphTokenTenant -eq $Script:ARMTokenTenant) {
                            Write-Host "  Your Graph token is for the same tenant as ARM token, but may still work" -ForegroundColor Gray
                            Write-Host "  for Azure AD enumeration across tenant boundaries." -ForegroundColor Gray
                        }
                        Write-Host "  .\Enum-AzureARM.ps1 -AccessTokenGraph '<graph-token>' -GraphOnly" -ForegroundColor White
                        Write-Host ""
                        
                        Write-Host "COMMON SCENARIOS:" -ForegroundColor Yellow
                        Write-Host "• Guest user accessing resources in another tenant" -ForegroundColor Gray
                        Write-Host "• Multi-tenant application with wrong tenant-specific token" -ForegroundColor Gray
                        Write-Host "• Token obtained for home tenant but accessing resource tenant" -ForegroundColor Gray
                        Write-Host "• B2B collaboration scenario with cross-tenant access" -ForegroundColor Gray
                        Write-Host ""
                        
                        break
                    }
                }
                
                if (-not $foundMismatch) {
                    Write-Verbose "No tenant mismatches detected - tokens and subscriptions are aligned"
                }
            } else {
                Write-Verbose "Could not retrieve subscription information to check tenant alignment"
            }
        }
        
    } catch {
        Write-Verbose "Could not perform tenant mismatch check: $($_.Exception.Message)"
        # Don't throw errors here as this is just a diagnostic check
    }
}

function Get-RoleDefinitionName {
    <#
    .SYNOPSIS
        Retrieves the role definition name from role definition ID.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RoleDefinitionId
    )
    
    if ([string]::IsNullOrWhiteSpace($RoleDefinitionId)) {
        Write-Debug "Empty or null role definition ID provided"
        return $null
    }
    
    # Ensure proper URI format
    $baseUri = "https://management.azure.com"
    if (-not $RoleDefinitionId.StartsWith("/")) {
        $RoleDefinitionId = "/$RoleDefinitionId"
    }
    
    $fullUri = "$baseUri$($RoleDefinitionId)?api-version=2022-04-01"
    
    try {
        Write-Debug "Retrieving role definition: $RoleDefinitionId"
        $roleDef = Invoke-ARMRequest -Uri $fullUri
        
        if ($roleDef -and $roleDef.properties -and $roleDef.properties.roleName) {
            Write-Debug "Role definition found: $($roleDef.properties.roleName)"
            return $roleDef.properties.roleName
        } else {
            Write-Debug "No role name found in response for: $RoleDefinitionId"
            return "Unknown Role"
        }
    } catch {
        Write-Warning "Failed to retrieve role definition for $RoleDefinitionId : $($_.Exception.Message)"
        return "Error Retrieving Role"
    }
}



function Test-GraphAccess {
    <#
    .SYNOPSIS
        Tests available Graph access methods for debugging.
    #>
    
    Write-Host "=== Graph Access Diagnostic ===" -ForegroundColor Cyan
    Write-Host "AccessTokenGraph provided: $($null -ne $AccessTokenGraph)" -ForegroundColor Yellow
    Write-Host "AuthenticationStatus.GraphContext: $($Script:AuthenticationStatus.GraphContext)" -ForegroundColor Yellow
    Write-Host "AuthenticationStatus.GraphToken: $($Script:AuthenticationStatus.GraphToken)" -ForegroundColor Yellow
    
    # Test Graph module availability
    $mgModule = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication
    Write-Host "Microsoft.Graph.Authentication module available: $($null -ne $mgModule)" -ForegroundColor Yellow
    
    # Test Graph context
    try {
        $mgContext = Get-MgContext -ErrorAction SilentlyContinue
        Write-Host "Current MgContext available: $($null -ne $mgContext)" -ForegroundColor Yellow
        if ($mgContext) {
            Write-Host "  Scopes: $($mgContext.Scopes -join ', ')" -ForegroundColor Gray
        }
    } catch {
        Write-Host "Get-MgContext failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Test cmdlet availability
    $mgUserCmd = Get-Command Get-MgUser -ErrorAction SilentlyContinue
    Write-Host "Get-MgUser cmdlet available: $($null -ne $mgUserCmd)" -ForegroundColor Yellow
    
    # Test Graph token with a simple REST API call
    if ($AccessTokenGraph) {
        Write-Host "Testing Graph token with REST API call..." -ForegroundColor Yellow
        try {
            $testResponse = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/me" -ErrorAction Stop
            if ($testResponse -and $testResponse.displayName) {
                Write-Host "[SUCCESS] Graph REST API test successful: $($testResponse.displayName)" -ForegroundColor Green
            } else {
                Write-Host "[FAILED] Graph REST API test returned empty response" -ForegroundColor Red
            }
        } catch {
            Write-Host "[FAILED] Graph REST API test failed: $($_.Exception.Message)" -ForegroundColor Red
            
            # Check if it's a permission-related error
            if ($_.Exception.Message -match "Forbidden|Unauthorized|Insufficient|Permission" -or
                ($_.Exception -is [System.Net.WebException] -and $_.Exception.Response.StatusCode -in @(401, 403))) {
                Show-GraphPermissionGuidance -MissingPermission "User.Read" -ErrorContext "Basic user profile access (/me endpoint)"
            }
        }
        
        # Test Directory.Read.All permission by trying to read a user
        try {
            $testUser = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/users?`$top=1" -ErrorAction Stop
            if ($testUser -and $testUser.value) {
                Write-Host "[SUCCESS] Directory.Read.All permission test successful" -ForegroundColor Green
            } else {
                Write-Host "[WARNING] Directory.Read.All permission test returned empty response" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[FAILED] Directory.Read.All permission test failed: $($_.Exception.Message)" -ForegroundColor Red
            
            # Check if it's a permission-related error
            if ($_.Exception.Message -match "Forbidden|Unauthorized|Insufficient|Permission" -or
                ($_.Exception -is [System.Net.WebException] -and $_.Exception.Response.StatusCode -in @(401, 403))) {
                Show-GraphPermissionGuidance -MissingPermission "Directory.Read.All" -ErrorContext "Directory enumeration (/users endpoint)"
            } else {
                Write-Host "  This indicates insufficient Graph permissions for principal lookups" -ForegroundColor Gray
            }
        }
    }
    
    Write-Host "================================" -ForegroundColor Cyan
}

function Show-GraphPermissionGuidance {
    param (
        [string]$MissingPermission,
        [string]$ErrorContext = "Graph API call"
    )
    
    Write-Host ""
    Write-Host "Graph Permission Issue Detected" -ForegroundColor Red
    Write-Host "================================" -ForegroundColor Red
    Write-Host "Context: $ErrorContext" -ForegroundColor Yellow
    Write-Host ""
    
    if ($Script:GraphTokenPermissions) {
        Write-Host "Current Token Analysis:" -ForegroundColor Cyan
        Write-Host "  Delegated Scopes: $($Script:GraphTokenPermissions.Scopes -join ', ')" -ForegroundColor Gray
        Write-Host "  Application Roles: $($Script:GraphTokenPermissions.Roles -join ', ')" -ForegroundColor Gray
        Write-Host "  Issues Found: $($Script:GraphTokenPermissions.Issues.Count)" -ForegroundColor Gray
        
        if ($Script:GraphTokenPermissions.Issues.Count -gt 0) {
            foreach ($issue in $Script:GraphTokenPermissions.Issues) {
                Write-Host "    - $issue" -ForegroundColor Red
            }
        }
        Write-Host ""
    }
    
    Write-Host "Recommended Solutions:" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "Option 1: Azure CLI (Interactive Login)" -ForegroundColor Cyan
    Write-Host "  # For basic enumeration (User.Read + Directory.Read.All):" -ForegroundColor Gray
    Write-Host "  az login --scope https://graph.microsoft.com/User.Read https://graph.microsoft.com/Directory.Read.All" -ForegroundColor White
    Write-Host "  az account get-access-token --resource=https://graph.microsoft.com" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Option 2: Azure PowerShell (Connect-AzAccount)" -ForegroundColor Cyan
    Write-Host "  # Basic enumeration permissions:" -ForegroundColor Gray
    Write-Host "  Connect-AzAccount -Scope 'https://graph.microsoft.com/User.Read', 'https://graph.microsoft.com/Directory.Read.All'" -ForegroundColor White
    Write-Host "  `$token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(`$context.Account, `$context.Environment, `$context.Tenant.Id, `$null, 'https://graph.microsoft.com/').AccessToken" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Option 2b: Azure PowerShell Service Principal (Recommended for CTF)" -ForegroundColor Cyan
    Write-Host "  # Use discovered service principal credentials directly:" -ForegroundColor Gray
    Write-Host "  .\Enum-AzureARM.ps1 -UseServicePrincipal -ApplicationId '<APP_ID>' -ClientSecret '<SECRET>' -TenantId '<TENANT_ID>'" -ForegroundColor White
    Write-Host "  # Automatically extracts ARM, Graph, and Key Vault tokens" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Option 3: Azure CLI (Service Principal with App Permissions)" -ForegroundColor Cyan
    Write-Host "  # First, register app and grant admin consent for:" -ForegroundColor Gray
    Write-Host "  # - Directory.Read.All (Application permission)" -ForegroundColor Gray
    Write-Host "  # - User.Read.All (Application permission)" -ForegroundColor Gray
    Write-Host "  az login --service-principal -u <APP_ID> -p <SECRET> --tenant <TENANT_ID>" -ForegroundColor White
    Write-Host "  az account get-access-token --resource=https://graph.microsoft.com" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Option 4: Manual Token Request (PowerShell)" -ForegroundColor Cyan
    Write-Host "  # For client credentials flow (app-only) - REQUIRES APPLICATION PERMISSIONS:" -ForegroundColor Gray
    Write-Host @'
  $clientId = "YOUR_APP_ID"
  $clientSecret = "YOUR_SECRET"  
  $tenantId = "YOUR_TENANT_ID"
  $body = @{
      grant_type = "client_credentials"
      client_id = $clientId
      client_secret = $clientSecret
      scope = "https://graph.microsoft.com/.default"
  }
  $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method Post -Body $body
  $token = $response.access_token
'@ -ForegroundColor White
    Write-Host ""
    
    if ($MissingPermission -like "*client credentials*" -or $ErrorContext -like "*delegated-only*") {
        Write-Host "CRITICAL: Your App Registration Issue" -ForegroundColor Red
        Write-Host "Your application has DELEGATED permissions but you're using CLIENT CREDENTIALS flow." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Fix in Azure Portal:" -ForegroundColor Cyan
        Write-Host "1. Go to portal.azure.com > Azure Active Directory > App registrations" -ForegroundColor White
        Write-Host "2. Find your application and click on it" -ForegroundColor White
        Write-Host "3. Navigate to 'API permissions'" -ForegroundColor White
        Write-Host "4. Click 'Add a permission' > Microsoft Graph > Application permissions" -ForegroundColor White
        Write-Host "5. Add these APPLICATION permissions:" -ForegroundColor White
        Write-Host "   - User.Read.All" -ForegroundColor Cyan
        Write-Host "   - Directory.Read.All" -ForegroundColor Cyan
        Write-Host "   - Group.Read.All" -ForegroundColor Cyan
        Write-Host "   - Application.Read.All" -ForegroundColor Cyan
        Write-Host "6. Click 'Grant admin consent for [tenant]'" -ForegroundColor White
        Write-Host ""
        Write-Host "Alternative: Use a different app with existing application permissions" -ForegroundColor Yellow
        Write-Host ""
    }
    
    Write-Host "Required Permissions by Operation:" -ForegroundColor Yellow
    Write-Host "  Basic User Info: User.Read or User.ReadBasic.All" -ForegroundColor Gray
    Write-Host "  All Users: User.Read.All or Directory.Read.All" -ForegroundColor Gray
    Write-Host "  Groups: Group.Read.All or Directory.Read.All" -ForegroundColor Gray
    Write-Host "  Applications: Application.Read.All or Directory.Read.All" -ForegroundColor Gray
    Write-Host "  Directory Roles: RoleManagement.Read.Directory or Directory.Read.All" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Pro Tip: Use 'Directory.Read.All' for comprehensive read access to most resources" -ForegroundColor Green
    Write-Host ""
}

function Get-PrincipalName {
    <#
    .SYNOPSIS
        Retrieves the display name for a principal (user, group, or service principal) from Microsoft Graph.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PrincipalId
    )
    
    # Return null if no access token and no Graph context
    if (-not $AccessTokenGraph -and -not $Script:AuthenticationStatus.GraphContext) {
        Write-Debug "No Graph access token or Graph context available for principal lookup"
        return "No Graph Access"
    }
    
    if ([string]::IsNullOrWhiteSpace($PrincipalId)) {
        Write-Debug "Empty or null principal ID provided"
        return "Empty Principal ID"
    }
    
    try {
        Write-Debug "Looking up principal: $PrincipalId"
        
        # Method 1: Try using PowerShell Graph cmdlets if context is available
        if ($Script:AuthenticationStatus.GraphContext) {
            Write-Debug "Attempting principal lookup using PowerShell Graph cmdlets"
            
            # Try user first with Get-MgUser
            try {
                if (Get-Command Get-MgUser -ErrorAction SilentlyContinue) {
                    $user = Get-MgUser -UserId $PrincipalId -Property "Id,DisplayName,UserPrincipalName" -ErrorAction SilentlyContinue
                    if ($user -and $user.DisplayName) {
                        Write-Debug "Found user via Get-MgUser: $($user.DisplayName)"
                        return $user.DisplayName
                    }
                }
            } catch {
                Write-Debug "Get-MgUser failed for $PrincipalId : $($_.Exception.Message)"
            }
            
            # Try group with Get-MgGroup
            try {
                if (Get-Command Get-MgGroup -ErrorAction SilentlyContinue) {
                    $group = Get-MgGroup -GroupId $PrincipalId -Property "Id,DisplayName" -ErrorAction SilentlyContinue
                    if ($group -and $group.DisplayName) {
                        Write-Debug "Found group via Get-MgGroup: $($group.DisplayName)"
                        return $group.DisplayName
                    }
                }
            } catch {
                Write-Debug "Get-MgGroup failed for $PrincipalId : $($_.Exception.Message)"
            }
            
            # Try service principal with Get-MgServicePrincipal
            try {
                if (Get-Command Get-MgServicePrincipal -ErrorAction SilentlyContinue) {
                    $servicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $PrincipalId -Property "Id,DisplayName,AppId" -ErrorAction SilentlyContinue
                    if ($servicePrincipal -and $servicePrincipal.DisplayName) {
                        Write-Debug "Found service principal via Get-MgServicePrincipal: $($servicePrincipal.DisplayName)"
                        return $servicePrincipal.DisplayName
                    }
                }
            } catch {
                Write-Debug "Get-MgServicePrincipal failed for $PrincipalId : $($_.Exception.Message)"
            }
        }
        
        # Method 2: Try REST API calls if we have an access token
        if ($AccessTokenGraph) {
            Write-Debug "Attempting principal lookup using Graph REST API"
            
            # Try user first
            try {
                $user = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$PrincipalId" -ErrorAction SilentlyContinue
                if ($user -and $user.displayName) {
                    Write-Debug "Found user via REST API: $($user.displayName)"
                    return $user.displayName
                }
            } catch {
                Write-Debug "REST API user lookup failed for $PrincipalId : $($_.Exception.Message)"
            }
            
            # Try group
            try {
                $group = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$PrincipalId" -ErrorAction SilentlyContinue
                if ($group -and $group.displayName) {
                    Write-Debug "Found group via REST API: $($group.displayName)"
                    return $group.displayName
                }
            } catch {
                Write-Debug "REST API group lookup failed for $PrincipalId : $($_.Exception.Message)"
            }
            
            # Try service principal
            try {
                $servicePrincipal = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId" -ErrorAction SilentlyContinue
                if ($servicePrincipal -and $servicePrincipal.displayName) {
                    Write-Debug "Found service principal via REST API: $($servicePrincipal.displayName)"
                    return $servicePrincipal.displayName
                }
            } catch {
                Write-Debug "REST API service principal lookup failed for $PrincipalId : $($_.Exception.Message)"
            }
        }
        
        Write-Debug "Principal not found through any method: $PrincipalId"
        return "Principal Not Found"
        
    } catch {
        Write-Debug "Principal lookup failed for $PrincipalId : $($_.Exception.Message)"
        return "Lookup Failed: $($_.Exception.Message)"
    }
}

#region Enhanced Display Functions

function Show-EnumerationHeader {
    [CmdletBinding()]
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$TenantId,
        [string]$AuthMethod
    )
    
    $separator = "=" * 80
    Write-Host ""
    Write-Host $separator -ForegroundColor Cyan
    Write-Host " AZURE ENUMERATION RESULTS" -ForegroundColor Cyan
    Write-Host $separator -ForegroundColor Cyan
    Write-Host " Subscription: $SubscriptionName" -ForegroundColor White
    Write-Host " ID: $SubscriptionId" -ForegroundColor Gray
    Write-Host " Tenant: $TenantId" -ForegroundColor Gray
    Write-Host " Authentication: $AuthMethod" -ForegroundColor Gray
    Write-Host " Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" -ForegroundColor Gray
    Write-Host $separator -ForegroundColor Cyan
}

function Show-RoleAssignmentsSummary {
    [CmdletBinding()]
    param(
        [array]$RoleAssignments,
        [string]$Title = "ROLE ASSIGNMENTS SUMMARY"
    )
    
    if (-not $RoleAssignments -or $RoleAssignments.Count -eq 0) {
        Write-Host "`n[$Title] No role assignments found or insufficient permissions" -ForegroundColor Yellow
        return
    }
    
    $separator = "-" * 80
    Write-Host ""
    Write-Host $separator -ForegroundColor Green
    Write-Host " $Title ($($RoleAssignments.Count) assignments)" -ForegroundColor Green
    Write-Host $separator -ForegroundColor Green
    
    # Group by role for better readability
    $groupedRoles = $RoleAssignments | Group-Object RoleDefinitionName | Sort-Object Count -Descending
    
    foreach ($roleGroup in $groupedRoles) {
        Write-Host "`n* $($roleGroup.Name) ($($roleGroup.Count) assignments)" -ForegroundColor Cyan
        
        $roleTable = @()
        foreach ($assignment in $roleGroup.Group) {
            $roleTable += [PSCustomObject]@{
                'Principal Name' = if ($assignment.PrincipalName -and $assignment.PrincipalName -ne "Principal Not Found") { 
                    $assignment.PrincipalName 
                } else { 
                    "Unknown ($($assignment.PrincipalType))" 
                }
                'Principal ID' = $assignment.PrincipalId
                'Type' = $assignment.PrincipalType
                'Scope' = if ($assignment.Scope -match "/subscriptions/[^/]+/resourceGroups/([^/]+)") { 
                    "RG: $($matches[1])" 
                } elseif ($assignment.Scope -match "/subscriptions/([^/]+)$") { 
                    "Subscription" 
                } else { 
                    "Resource" 
                }
            }
        }
        
        $roleTable | Format-Table -AutoSize | Out-String -Width 120 | Write-Host
    }
}

function Show-ResourcesSummary {
    [CmdletBinding()]
    param(
        [hashtable]$Resources
    )
    
    $separator = "-" * 80
    Write-Host ""
    Write-Host $separator -ForegroundColor Magenta
    Write-Host " AZURE RESOURCES DISCOVERED" -ForegroundColor Magenta
    Write-Host $separator -ForegroundColor Magenta
    
    # Debug: Show what Key Vault data we received
    Write-Verbose "[DEBUG] Show-ResourcesSummary called"
    Write-Verbose "[DEBUG] Key Vaults count: $(if ($Resources.KeyVaults) { $Resources.KeyVaults.Count } else { 'null' })"
    
    # Virtual Machines
    if ($Resources.VirtualMachines -and $Resources.VirtualMachines.Count -gt 0) {
        $vmStats = $Resources.VirtualMachines | Group-Object Location | ForEach-Object {
            [PSCustomObject]@{
                Location = $_.Name
                Count = $_.Count
                Names = ($_.Group | Select-Object -First 3).Name -join ", "
                Status = ($_.Group | Where-Object {$_.PowerState -eq "VM running"}).Count
            }
        }
        
        Write-Host "`n* Virtual Machines ($($Resources.VirtualMachines.Count) total)" -ForegroundColor Yellow
        if ($vmStats) {
            $vmStats | Format-Table -AutoSize @{
                Name="Location"; Expression={$_.Location}; Width=15
            }, @{
                Name="Count"; Expression={$_.Count}; Width=8
            }, @{
                Name="Running"; Expression={$_.Status}; Width=8
            }, @{
                Name="Examples"; Expression={$_.Names}; Width=40
            } | Out-String | Write-Host
        }
    }
    
    # Storage Accounts
    if ($Resources.StorageAccounts -and $Resources.StorageAccounts.Count -gt 0) {
        Write-Host "`n* Storage Accounts ($($Resources.StorageAccounts.Count) total)" -ForegroundColor Yellow
        $storageTable = $Resources.StorageAccounts | Select-Object -First 10 | ForEach-Object {
            [PSCustomObject]@{
                'Name' = $_.Name
                'Location' = $_.Location
                'Tier' = $_.Tier
                'Kind' = $_.Kind
                'Replication' = $_.ReplicationType
                'Public Access' = if ($_.AllowBlobPublicAccess) { "Allowed" } else { "Blocked" }
            }
        }
        $storageTable | Format-Table -AutoSize | Out-String | Write-Host
        
        if ($Resources.StorageAccounts.Count -gt 10) {
            Write-Host "   ... and $($Resources.StorageAccounts.Count - 10) more (see JSON output for complete list)" -ForegroundColor Gray
        }
    }
    
    # Key Vaults
    Write-Verbose "[DEBUG] Checking Key Vaults section..."
    Write-Verbose "[DEBUG] Resources.KeyVaults exists: $($null -ne $Resources.KeyVaults)"
    Write-Verbose "[DEBUG] Resources.KeyVaults.Count: $(if ($Resources.KeyVaults) { $Resources.KeyVaults.Count } else { 'N/A' })"
    
    if ($Resources.KeyVaults -and $Resources.KeyVaults.Count -gt 0) {
        Write-Host "`n* Key Vaults ($($Resources.KeyVaults.Count) total)" -ForegroundColor Yellow
        $kvTable = $Resources.KeyVaults | ForEach-Object {
            $secretsCount = if ($_.SecretsInfo -and $_.SecretsInfo.Secrets) { $_.SecretsInfo.Secrets.Count } else { 0 }
            Write-Verbose "[DEBUG] Processing KV: $($_.Name), Secrets count: $secretsCount"
            [PSCustomObject]@{
                'Name' = $_.Name
                'Location' = $_.Location
                'Secrets' = $secretsCount
                'Soft Delete' = if ($_.SoftDeleteRetentionInDays) { "$($_.SoftDeleteRetentionInDays) days" } else { "Disabled" }
                'Deployment' = if ($_.EnabledForDeployment) { "Yes" } else { "No" }
                'Encryption' = if ($_.EnabledForDiskEncryption) { "Yes" } else { "No" }
            }
        }
        $kvTable | Format-Table -AutoSize | Out-String | Write-Host
        
        # Show secrets summary if any found
        Write-Verbose "   [DEBUG] Key Vaults count: $($Resources.KeyVaults.Count)"
        Write-Verbose "   [DEBUG] Key Vaults list: $($Resources.KeyVaults | ForEach-Object { $_.Name })"
        
        $totalSecrets = ($Resources.KeyVaults | ForEach-Object { 
            if ($_.SecretsInfo -and $_.SecretsInfo.Secrets) { $_.SecretsInfo.Secrets.Count } else { 0 }
        } | Measure-Object -Sum).Sum
        
        Write-Verbose "   [DEBUG] Total secrets calculated: $totalSecrets"
        
        if ($totalSecrets -gt 0) {
            Write-Host "`n   *** KEY VAULT SECRETS DISCOVERED ***" -ForegroundColor Green
            Write-Host "   * Total Secrets Found: $totalSecrets" -ForegroundColor Cyan
            
            $allSecrets = @()
            
            foreach ($kv in $Resources.KeyVaults) {
                $kvName = $kv.Name
                Write-Verbose "   [DEBUG] Processing Key Vault: $kvName"
                
                if ($kv.SecretsInfo -and $kv.SecretsInfo.Secrets) {
                    Write-Verbose "   [DEBUG] SecretsInfo exists, processing $($kv.SecretsInfo.Secrets.Count) secrets"
                    
                    foreach ($secret in $kv.SecretsInfo.Secrets) {
                        Write-Verbose "   [DEBUG] Processing secret: $($secret.Name)"
                        
                        $secretObject = [PSCustomObject]@{
                            'Vault' = $kvName
                            'Secret Name' = $secret.Name
                            'Type' = $secret.SecretType
                            'Content-Type' = $secret.ContentType
                            'Enabled' = $secret.Enabled
                            'Source' = $secret.Source
                            'Value Retrieved' = if ($secret.ValueRetrieved) { "Yes" } else { "No" }
                            'Value Preview' = if ($secret.ValueRetrieved -and $secret.Value) { 
                                $secret.Value 
                            } else { 
                                "[Not Retrieved]" 
                            }
                        }
                        
                        $allSecrets += $secretObject
                        Write-Verbose "   [DEBUG] Added secret object to array. Current count: $($allSecrets.Count)"
                    }
                } else {
                    Write-Verbose "   [DEBUG] No SecretsInfo or Secrets for $kvName"
                }
            }
            
            if ($allSecrets -and $allSecrets.Count -gt 0) {
                $secretSeparator = "=" * 78
                Write-Host "`n   SECRETS DETAILS:" -ForegroundColor Yellow
                Write-Host "   $secretSeparator" -ForegroundColor Yellow
                
                foreach ($secret in $allSecrets) {
                    Write-Host "`n   VAULT: $($secret.Vault)" -ForegroundColor Cyan
                    Write-Host "   SECRET NAME: $($secret.'Secret Name')" -ForegroundColor White
                    Write-Host "   TYPE: $($secret.Type)" -ForegroundColor Gray
                    Write-Host "   CONTENT-TYPE: $($secret.'Content-Type')" -ForegroundColor Gray
                    Write-Host "   ENABLED: $($secret.Enabled)" -ForegroundColor Gray
                    Write-Host "   SOURCE: $($secret.Source)" -ForegroundColor Gray
                    Write-Host "   VALUE RETRIEVED: $($secret.'Value Retrieved')" -ForegroundColor $(if ($secret.'Value Retrieved' -eq "Yes") { "Green" } else { "Red" })
                    if ($secret.'Value Retrieved' -eq "Yes") {
                        Write-Host "   VALUE PREVIEW: $($secret.'Value Preview')" -ForegroundColor Yellow
                    }
                    $lineSeparator = "-" * 78
                    Write-Host "   $lineSeparator" -ForegroundColor Gray
                }
                
                if ($allSecrets.Count -gt 10) {
                    Write-Host "`n   ... showing first 10 secrets (see JSON output for complete list)" -ForegroundColor Gray
                }
                
                # Show any secrets with actual values
                $secretsWithValues = $allSecrets | Where-Object { $_.'Value Retrieved' -eq "Yes" }
                if ($secretsWithValues.Count -gt 0) {
                    Write-Host "`n   *** SECRETS WITH RETRIEVED VALUES ***" -ForegroundColor Red
                    Write-Host "   WARNING: The following secrets have values that were successfully retrieved:" -ForegroundColor Red
                    $warningSeparator = "!" * 78
                    Write-Host "   $warningSeparator" -ForegroundColor Red
                    foreach ($secret in $secretsWithValues) {
                        Write-Host "`n   VAULT: $($secret.Vault)" -ForegroundColor Red
                        Write-Host "   SECRET: $($secret.'Secret Name')" -ForegroundColor Red
                        Write-Host "   PREVIEW: $($secret.'Value Preview')" -ForegroundColor Yellow
                    }
                    $warningSeparator = "!" * 78
                    Write-Host "`n   $warningSeparator" -ForegroundColor Red
                    Write-Host "   Full secret values are available in the JSON output file." -ForegroundColor Yellow
                }
            } else {
                Write-Verbose "   [DEBUG] No secrets array created or empty"
            }
        } else {
            # Debug why no secrets were found
            Write-Verbose "   [DEBUG] No secrets found. Checking Key Vault structure:"
            $Resources.KeyVaults | ForEach-Object {
                Write-Verbose "   [DEBUG] Key Vault: $($_.Name)"
                Write-Verbose "   [DEBUG]   - SecretsInfo exists: $($null -ne $_.SecretsInfo)"
                if ($_.SecretsInfo) {
                    Write-Verbose "   [DEBUG]   - SecretsInfo.Secrets exists: $($null -ne $_.SecretsInfo.Secrets)"
                    Write-Verbose "   [DEBUG]   - SecretsInfo.SecretsCount: $($_.SecretsInfo.SecretsCount)"
                    Write-Verbose "   [DEBUG]   - SecretsInfo.Success: $($_.SecretsInfo.Success)"
                }
            }
        }
    }
    
    # Web Apps & Function Apps
    $webApps = @()
    if ($Resources.WebApps) { $webApps += $Resources.WebApps }
    if ($Resources.AzureFunctions) { $webApps += $Resources.AzureFunctions }
    
    if ($webApps.Count -gt 0) {
        Write-Host "`n* Web Apps & Functions ($($webApps.Count) total)" -ForegroundColor Yellow
        $webAppTable = $webApps | Select-Object -First 10 | ForEach-Object {
            [PSCustomObject]@{
                'Name' = $_.Name
                'Type' = if ($_.Kind -like "*function*") { "Function App" } else { "Web App" }
                'Location' = $_.Location
                'State' = $_.State
                'SKU' = $_.AppServicePlan.Sku.Name
                'Default Hostname' = $_.DefaultHostName
            }
        }
        $webAppTable | Format-Table -AutoSize | Out-String | Write-Host
        
        if ($webApps.Count -gt 10) {
            Write-Host "   ... and $($webApps.Count - 10) more (see JSON output for complete list)" -ForegroundColor Gray
        }
    }
    
    # Resource Groups
    if ($Resources.ResourceGroups -and $Resources.ResourceGroups.Count -gt 0) {
        Write-Host "`n* Resource Groups ($($Resources.ResourceGroups.Count) total)" -ForegroundColor Yellow
        $rgTable = $Resources.ResourceGroups | Select-Object -First 15 | ForEach-Object {
            [PSCustomObject]@{
                'Name' = $_.Name
                'Location' = $_.Location
                'State' = $_.ProvisioningState
                'Deployments' = $_.DeploymentCount
                'Role Assignments' = $_.RoleAssignmentCount
            }
        }
        $rgTable | Format-Table -AutoSize | Out-String | Write-Host
        
        if ($Resources.ResourceGroups.Count -gt 15) {
            Write-Host "   ... and $($Resources.ResourceGroups.Count - 15) more (see JSON output for complete list)" -ForegroundColor Gray
        }
        
        # Show resource groups with high activity
        $activeRgs = $Resources.ResourceGroups | Where-Object { $_.DeploymentCount -gt 5 -or $_.RoleAssignmentCount -gt 3 } | Select-Object -First 5
        if ($activeRgs.Count -gt 0) {
            Write-Host "`n   * Most Active Resource Groups:" -ForegroundColor Cyan
            foreach ($rg in $activeRgs) {
                Write-Host "     - $($rg.Name): $($rg.DeploymentCount) deployments, $($rg.RoleAssignmentCount) role assignments" -ForegroundColor White
            }
        }
        
        # Show deployments with extracted parameters (potential sensitive data)
        $deploymentsWithParams = @()
        foreach ($rg in $Resources.ResourceGroups) {
            if ($rg.Deployments) {
                foreach ($deployment in $rg.Deployments) {
                    if ($deployment.ParametersExtracted -and $deployment.Parameters -and $deployment.Parameters.Count -gt 0) {
                        $deploymentsWithParams += [PSCustomObject]@{
                            ResourceGroup = $rg.Name
                            DeploymentName = $deployment.Name
                            ParameterCount = $deployment.Parameters.Count
                            Status = $deployment.Status
                            Timestamp = $deployment.Timestamp
                            Parameters = $deployment.Parameters
                        }
                    }
                }
            }
        }
        
        if ($deploymentsWithParams.Count -gt 0) {
            Write-Host "`n   *** DEPLOYMENTS WITH EXTRACTED PARAMETERS ***" -ForegroundColor Red
            Write-Host "   WARNING: Found $($deploymentsWithParams.Count) deployment(s) with accessible parameters - potential sensitive data!" -ForegroundColor Yellow
            
            foreach ($dep in $deploymentsWithParams | Select-Object -First 5) {
                Write-Host "`n   Resource Group: $($dep.ResourceGroup)" -ForegroundColor Cyan
                Write-Host "   Deployment: $($dep.DeploymentName)" -ForegroundColor White
                Write-Host "   Parameters Found: $($dep.ParameterCount)" -ForegroundColor Yellow
                Write-Host "   Status: $($dep.Status)" -ForegroundColor Gray
                Write-Host "   Timestamp: $($dep.Timestamp)" -ForegroundColor Gray
                
                # Display actual parameter names and values for immediate visibility
                if ($dep.Parameters -and $dep.Parameters.PSObject.Properties.Count -gt 0) {
                    Write-Host "`n   PARAMETER DETAILS:" -ForegroundColor Red
                    foreach ($param in $dep.Parameters.PSObject.Properties) {
                        Write-Host "   • Parameter: $($param.Name)" -ForegroundColor Yellow
                        Write-Host "     Value: $($param.Value)" -ForegroundColor White
                        
                        # Highlight potentially sensitive parameter names
                        $sensitiveKeywords = @('password', 'secret', 'key', 'token', 'connection', 'auth', 'credential', 'pass', 'pwd')
                        $isSensitive = $sensitiveKeywords | Where-Object { $param.Name -like "*$_*" -or $param.Value -like "*$_*" }
                        if ($isSensitive) {
                            Write-Host "     ⚠️  POTENTIALLY SENSITIVE DATA DETECTED! ⚠️" -ForegroundColor Red
                        }
                        Write-Host ""
                    }
                }
                
                Write-Host "   Command to view: Get-AzResourceGroupDeployment -ResourceGroupName '$($dep.ResourceGroup)' -Name '$($dep.DeploymentName)'" -ForegroundColor Cyan
            }
            
            if ($deploymentsWithParams.Count -gt 5) {
                Write-Host "`n   ... and $($deploymentsWithParams.Count - 5) more deployments with parameters (see JSON output)" -ForegroundColor Gray
            }
            
            Write-Host "`n   SECURITY IMPACT:" -ForegroundColor Red
            Write-Host "   - Deployment parameters may contain passwords, connection strings, API keys" -ForegroundColor Yellow
            Write-Host "   - This data is accessible to anyone with Reader permissions on the resource group" -ForegroundColor Yellow
            Write-Host "   - Review the JSON output for complete parameter details" -ForegroundColor Yellow
        }
    }
    
    # Azure AD / Microsoft Graph Information
    if ($Resources.TenantUsers -or $Resources.TenantGroups -or $Resources.TenantApplications) {
        Write-Host "`n* Azure AD / Microsoft Graph Objects" -ForegroundColor Yellow
        $adStats = @()
        
        if ($Resources.TenantUsers) {
            $adStats += "$($Resources.TenantUsers.Users.Count) users"
        }
        if ($Resources.TenantGroups) {
            $adStats += "$($Resources.TenantGroups.Groups.Count) groups"
        }
        if ($Resources.TenantApplications) {
            $adStats += "$($Resources.TenantApplications.Applications.Count) applications"
            $adStats += "$($Resources.TenantApplications.ServicePrincipals.Count) service principals"
        }
        
        if ($adStats.Count -gt 0) {
            Write-Host "   $($adStats -join ' | ')" -ForegroundColor Cyan
        }
        
        # Show applications with secrets if available
        if ($Resources.TenantApplications -and $Resources.TenantApplications.Analysis.ApplicationsWithSecrets -gt 0) {
            Write-Host "   WARNING: $($Resources.TenantApplications.Analysis.ApplicationsWithSecrets) applications have secrets/certificates" -ForegroundColor Yellow
        }
    }
}

function Show-SecurityHighlights {
    [CmdletBinding()]
    param(
        [hashtable]$Resources
    )
    
    $separator = "-" * 80
    Write-Host ""
    Write-Host $separator -ForegroundColor Red
    Write-Host " SECURITY HIGHLIGHTS & RECOMMENDATIONS" -ForegroundColor Red
    Write-Host $separator -ForegroundColor Red
    
    $findings = @()
    
    # Check for public storage accounts
    if ($Resources.StorageAccounts) {
        $publicStorage = $Resources.StorageAccounts | Where-Object { $_.AllowBlobPublicAccess -eq $true }
        if ($publicStorage.Count -gt 0) {
            $findings += "WARNING: $($publicStorage.Count) storage accounts allow public blob access"
        }
    }
    
    # Check for admin/owner role assignments
    if ($Resources.SubscriptionRoleAssignments) {
        $adminRoles = $Resources.SubscriptionRoleAssignments | Where-Object { 
            $_.RoleDefinitionName -in @("Owner", "Contributor", "User Access Administrator") 
        }
        if ($adminRoles.Count -gt 0) {
            $findings += "HIGH-PRIVILEGE: $($adminRoles.Count) high-privilege role assignments (Owner/Contributor/User Access Admin)"
        }
    }
    
    # Check for Key Vault secrets
    if ($Resources.KeyVaults) {
        $secretsFound = ($Resources.KeyVaults | ForEach-Object { 
            if ($_.SecretsInfo -and $_.SecretsInfo.Secrets) { $_.SecretsInfo.Secrets.Count } else { 0 }
        } | Measure-Object -Sum).Sum
        
        if ($secretsFound -gt 0) {
            $findings += "SECRETS: $secretsFound secrets discovered across $($Resources.KeyVaults.Count) Key Vaults"
        }
    }
    
    # Check for VMs
    if ($Resources.VirtualMachines) {
        $runningVMs = $Resources.VirtualMachines | Where-Object { $_.PowerState -eq "VM running" }
        if ($runningVMs.Count -gt 0) {
            $findings += "COMPUTE: $($runningVMs.Count) running virtual machines detected"
        }
    }
    
    # Check for public IPs
    if ($Resources.PublicIPs) {
        $findings += "NETWORK: $($Resources.PublicIPs.Count) public IP addresses allocated"
    }
    
    # Resource Groups with role assignments
    if ($Resources.ResourceGroups) {
        $rgWithRoles = $Resources.ResourceGroups | Where-Object { $_.RoleAssignmentCount -gt 0 }
        if ($rgWithRoles.Count -gt 0) {
            $totalRgRoles = ($rgWithRoles | ForEach-Object { $_.RoleAssignmentCount } | Measure-Object -Sum).Sum
            $findings += "RBAC: $totalRgRoles role assignments across $($rgWithRoles.Count) resource groups"
        }
    }
    
    # Azure AD / Microsoft Graph findings
    if ($Resources.TenantApplications -and $Resources.TenantApplications.Analysis.ApplicationsWithSecrets -gt 0) {
        $findings += "APPS: $($Resources.TenantApplications.Analysis.ApplicationsWithSecrets) applications with stored secrets/certificates"
    }
    
    # Owned objects - critical for privilege escalation
    if ($Resources.OwnedObjects -and $Resources.OwnedObjects.Analysis.PrivilegeEscalationOpportunities -gt 0) {
        $findings += "PRIVILEGE ESCALATION: $($Resources.OwnedObjects.Analysis.PrivilegeEscalationOpportunities) owned applications detected - you can create new secrets!"
    }
    
    if ($Resources.OwnedObjects -and $Resources.OwnedObjects.Analysis.TotalOwnedObjects -gt 0) {
        $findings += "OWNED OBJECTS: $($Resources.OwnedObjects.Analysis.TotalOwnedObjects) total objects owned by current user"
    }
    
    # Check for deployments with extracted parameters (potential sensitive data exposure)
    if ($Resources.ResourceGroups) {
        $deploymentsWithParams = 0
        $totalParameters = 0
        $Resources.ResourceGroups | ForEach-Object {
            if ($_.Deployments) {
                $_.Deployments | ForEach-Object {
                    if ($_.ParametersExtracted -and $_.Parameters -and $_.Parameters.Count -gt 0) {
                        $deploymentsWithParams++
                        $totalParameters += $_.Parameters.Count
                    }
                }
            }
        }
        
        if ($deploymentsWithParams -gt 0) {
            $findings += "DEPLOYMENT PARAMETERS: $totalParameters parameters extracted from $deploymentsWithParams deployments - potential sensitive data exposure!"
        }
    }
    
    if ($Resources.TenantUsers) {
        $findings += "IDENTITY: $($Resources.TenantUsers.Users.Count) Azure AD users enumerated"
    }
    
    if ($findings.Count -eq 0) {
        Write-Host "[OK] No immediate security concerns identified" -ForegroundColor Green
    } else {
        foreach ($finding in $findings) {
            Write-Host "   $finding" -ForegroundColor Yellow
        }
        
        Write-Host "`nRECOMMENDED ACTIONS:" -ForegroundColor Cyan
        Write-Host "   - Review role assignments for least privilege principle" -ForegroundColor White
        Write-Host "   - Audit Key Vault access policies and secret usage" -ForegroundColor White
        Write-Host "   - Verify storage account public access is intentional" -ForegroundColor White
        Write-Host "   - Check VM security configurations and update status" -ForegroundColor White
        Write-Host "   - Review application secrets and certificate expiration dates" -ForegroundColor White
        Write-Host "   - Validate resource group access permissions" -ForegroundColor White
        
        # Add privilege escalation guidance if owned applications found
        if ($Resources.OwnedObjects -and $Resources.OwnedObjects.Analysis.PrivilegeEscalationOpportunities -gt 0) {
            Write-Host "`nPRIVILEGE ESCALATION OPPORTUNITIES:" -ForegroundColor Red
            Write-Host "   - You own $($Resources.OwnedObjects.Analysis.PrivilegeEscalationOpportunities) application(s) - you can create new secrets!" -ForegroundColor Yellow
            Write-Host "   - Command: az ad app credential reset --id <APP_ID>" -ForegroundColor Cyan
            Write-Host "   - Then use the new secret to authenticate as the application" -ForegroundColor Cyan
            Write-Host "   - Check the application's permissions and role assignments" -ForegroundColor Cyan
        }
    }
}

function Show-OwnedApplicationsDetails {
    <#
    .SYNOPSIS
        Displays detailed information about owned applications with privilege escalation guidance.
    #>
    [CmdletBinding()]
    param(
        [array]$Applications,
        [string]$Title = "OWNED APPLICATIONS - PRIVILEGE ESCALATION OPPORTUNITIES"
    )
    
    if (-not $Applications -or $Applications.Count -eq 0) {
        return
    }
    
    $ownedApps = $Applications | Where-Object { $_.IsOwned -eq $true }
    
    if ($ownedApps.Count -eq 0) {
        return
    }
    
    $separator = "=" * 80
    Write-Host ""
    Write-Host $separator -ForegroundColor Red
    Write-Host " $Title" -ForegroundColor Red
    Write-Host $separator -ForegroundColor Red
    
    Write-Host "`nYou own $($ownedApps.Count) application(s). You can create new secrets for privilege escalation!" -ForegroundColor Yellow
    
    foreach ($app in $ownedApps) {
        Write-Host "`n>>> Application: $($app.DisplayName)" -ForegroundColor Cyan
        Write-Host "    App ID: $($app.AppId)" -ForegroundColor White
        Write-Host "    Object ID: $($app.Id)" -ForegroundColor White
        if ($app.HasSecrets) {
            Write-Host "    Current Secrets: $($app.PasswordCredentials) passwords, $($app.KeyCredentials) certificates" -ForegroundColor Yellow
        }
        Write-Host "    Created: $($app.CreatedDateTime)" -ForegroundColor Gray
        
        Write-Host "`n    PRIVILEGE ESCALATION COMMANDS:" -ForegroundColor Red
        Write-Host "    1. Create new secret: az ad app credential reset --id $($app.AppId)" -ForegroundColor Cyan
        Write-Host "    2. Authenticate as app: az login --service-principal -u $($app.AppId) -p <NEW_SECRET> --tenant <TENANT_ID>" -ForegroundColor Cyan
        Write-Host "    3. Check app permissions: az ad app permission list --id $($app.AppId)" -ForegroundColor Cyan
        Write-Host "    4. Check role assignments: az role assignment list --assignee $($app.AppId)" -ForegroundColor Cyan
    }
    
    Write-Host "`nIMPORTANT NOTES:" -ForegroundColor Yellow
    Write-Host "- Creating new secrets may alert administrators" -ForegroundColor White
    Write-Host "- Check the application's permissions and role assignments first" -ForegroundColor White
    Write-Host "- The application may have elevated privileges in Azure AD or Azure resources" -ForegroundColor White
    Write-Host "- Document findings for security assessment reporting" -ForegroundColor White
    
    $separator = "=" * 80
    Write-Host $separator -ForegroundColor Red
}

function Show-QuickStats {
    [CmdletBinding()]
    param(
        [hashtable]$Summary
    )
    
    $separator = "-" * 40
    Write-Host ""
    Write-Host $separator -ForegroundColor Blue
    Write-Host " QUICK STATISTICS" -ForegroundColor Blue
    Write-Host $separator -ForegroundColor Blue
    
    $statsTable = @(
        [PSCustomObject]@{ 'Resource Type' = 'Virtual Machines'; 'Count' = $Summary.VirtualMachines }
        [PSCustomObject]@{ 'Resource Type' = 'Storage Accounts'; 'Count' = $Summary.StorageAccounts }
        [PSCustomObject]@{ 'Resource Type' = 'Key Vaults'; 'Count' = $Summary.KeyVaults }
        [PSCustomObject]@{ 'Resource Type' = 'Web Apps'; 'Count' = $Summary.WebApps }
        [PSCustomObject]@{ 'Resource Type' = 'Function Apps'; 'Count' = $Summary.FunctionApps }
        [PSCustomObject]@{ 'Resource Type' = 'Public IPs'; 'Count' = $Summary.PublicIPs }
        [PSCustomObject]@{ 'Resource Type' = 'Role Assignments'; 'Count' = $Summary.SubscriptionRoleAssignments }
        [PSCustomObject]@{ 'Resource Type' = 'Resource Groups'; 'Count' = $Summary.ResourceGroups }
    )
    
    $statsTable | Format-Table -AutoSize | Out-String | Write-Host
}

#endregion

function Get-KeyVaultSecrets {
    <#
    .SYNOPSIS
        Retrieves secrets from Azure Key Vault using multiple authentication methods and approaches.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyVaultName,
        
        [Parameter(Mandatory=$true)]
        [string]$VaultUri,
        
        [Parameter(Mandatory=$false)]
        [string]$SubscriptionId
    )
    
    $secrets = @()
    $secretsFound = $false
    
    try {
        Write-Debug "Attempting to retrieve secrets from Key Vault: $KeyVaultName"
        Write-Debug "Vault URI: $VaultUri"
        
        # Method 1: Azure CLI (often most successful in CTF scenarios)
        Write-Debug "Method 1: Attempting Azure CLI secret enumeration..."
        try {
            $azCliAvailable = Get-Command az -ErrorAction SilentlyContinue
            if ($azCliAvailable) {
                Write-Debug "Azure CLI detected, attempting secret list for Key Vault: $KeyVaultName"
                
                # First try with --include-managed flag (newer Azure CLI versions) - this is crucial for managed secrets
                Write-Debug "Attempting CLI with --include-managed flag..."
                $azCliOutput = & az keyvault secret list --vault-name $KeyVaultName --include-managed --output json --only-show-errors 2>&1
                
                # Check if the error is SSL-related and enable global SSL bypass
                if ($azCliOutput -and ($azCliOutput -like "*CERTIFICATE_VERIFY_FAILED*" -or $azCliOutput -like "*SSL*" -or $azCliOutput -like "*certificate*")) {
                    if (-not $Script:SSLBypassEnabled) {
                        Enable-SSLBypass -Reason "Azure CLI SSL error detected: $($azCliOutput | Where-Object { $_ -like '*CERTIFICATE*' -or $_ -like '*SSL*' } | Select-Object -First 1)"
                        # Retry the command after SSL bypass is enabled
                        $azCliOutput = & az keyvault secret list --vault-name $KeyVaultName --include-managed --output json --only-show-errors 2>$null
                    }
                }
                
                # If that fails, try without --include-managed (some environments don't support this flag)
                if (-not $azCliOutput -or $azCliOutput -eq "[]" -or $azCliOutput -like "*ERROR*") {
                    Write-Debug "Retrying without --include-managed flag..."
                    $azCliOutput = & az keyvault secret list --vault-name $KeyVaultName --output json --only-show-errors 2>$null
                }
                
                # Final fallback: try with verbose error output for debugging
                if (-not $azCliOutput -or $azCliOutput -eq "[]" -or $azCliOutput -like "*ERROR*") {
                    Write-Debug "Final attempt with full error output..."
                    $azCliOutput = & az keyvault secret list --vault-name $KeyVaultName --output json 2>&1
                }
                
                if ($azCliOutput -and $azCliOutput -ne "[]" -and -not ($azCliOutput -like "*ERROR*")) {
                    try {
                        $azSecrets = $azCliOutput | ConvertFrom-Json -ErrorAction SilentlyContinue
                        
                        if ($azSecrets -and $azSecrets.Count -gt 0) {
                            Write-Debug "Azure CLI found $($azSecrets.Count) secrets in Key Vault $KeyVaultName"
                            $secretsFound = $true
                            
                            foreach ($azSecret in $azSecrets) {
                                $secretInfo = @{
                                    Name = $azSecret.name
                                    Id = $azSecret.id
                                    Enabled = $azSecret.attributes.enabled
                                    Created = $azSecret.attributes.created
                                    Updated = $azSecret.attributes.updated
                                    ContentType = $azSecret.contentType
                                    Tags = $azSecret.tags
                                    Managed = $azSecret.managed
                                    SecretType = if ($azSecret.managed) { "Managed Secret" } else { "User Secret" }
                                    Value = "[PROTECTED - Use: az keyvault secret show --vault-name $KeyVaultName --name $($azSecret.name)]"
                                    VaultUri = "$($VaultUri.TrimEnd('/'))/secrets/$($azSecret.name)"
                                    ValueRetrieved = $false
                                    Source = "Azure CLI"
                                    RetrievalMethod = "az keyvault secret list"
                                }
                                
                                # Try to get the actual secret value using Azure CLI
                                try {
                                    Write-Debug "Attempting to retrieve secret value for: $($azSecret.name)"
                                    $secretValueOutput = & az keyvault secret show --vault-name $KeyVaultName --name $azSecret.name --output json --only-show-errors 2>$null
                                    
                                    if ($secretValueOutput -and -not ($secretValueOutput -like "*ERROR*")) {
                                        $secretValueObj = $secretValueOutput | ConvertFrom-Json -ErrorAction SilentlyContinue
                                        if ($secretValueObj -and $secretValueObj.value) {
                                            $secretInfo.Value = $secretValueObj.value
                                            $secretInfo.ValueRetrieved = $true
                                            Write-Debug "Successfully retrieved secret value for: $($azSecret.name)"
                                        }
                                    }
                                } catch {
                                    Write-Debug "Could not retrieve secret value for $($azSecret.name): $($_.Exception.Message)"
                                }
                                
                                $secrets += [pscustomobject]$secretInfo
                            }
                        }
                    } catch {
                        Write-Debug "Failed to parse Azure CLI output: $($_.Exception.Message)"
                    }
                } else {
                    Write-Debug "Azure CLI command failed or returned empty result"
                    Write-Debug "CLI Output: $azCliOutput"
                }
            } else {
                Write-Debug "Azure CLI not available"
            }
        } catch {
            Write-Debug "Azure CLI method failed: $($_.Exception.Message)"
        }
        
        # Method 2: Direct Key Vault REST API with multiple approaches (if CLI didn't work)
        if (-not $secretsFound) {
            Write-Debug "Method 2: Attempting direct Key Vault REST API calls..."
            
            # Get available tokens
            $tokensToTry = @()
            
            # Add Key Vault token first (highest priority if available from service principal auth)
            if ($Script:KeyVaultToken) {
                $tokensToTry += @{ Token = $Script:KeyVaultToken; Type = "KeyVault (Service Principal)" }
                Write-Debug "Will try Key Vault token from Service Principal authentication"
            }
            
            if ($AccessTokenARM) { 
                $tokensToTry += @{ Token = $AccessTokenARM; Type = "ARM" }
                Write-Debug "Will try ARM token for Key Vault access"
            }
            if ($AccessTokenGraph) { 
                $tokensToTry += @{ Token = $AccessTokenGraph; Type = "Graph" }
                Write-Debug "Will try Graph token for Key Vault access"
            }
            
            # Try to get a Key Vault specific token if we have Azure CLI
            try {
                if ($azCliAvailable) {
                    $kvTokenOutput = & az account get-access-token --resource=https://vault.azure.net --output json --only-show-errors 2>&1
                    
                    # Check for SSL errors and enable bypass if needed
                    if ($kvTokenOutput -and ($kvTokenOutput -like "*CERTIFICATE_VERIFY_FAILED*" -or $kvTokenOutput -like "*SSL*" -or $kvTokenOutput -like "*certificate*")) {
                        if (-not $Script:SSLBypassEnabled) {
                            Enable-SSLBypass -Reason "Azure CLI token acquisition SSL error"
                            $kvTokenOutput = & az account get-access-token --resource=https://vault.azure.net --output json --only-show-errors 2>$null
                        }
                    }
                    
                    if ($kvTokenOutput -and -not ($kvTokenOutput -like "*ERROR*")) {
                        $kvTokenObj = $kvTokenOutput | ConvertFrom-Json -ErrorAction SilentlyContinue
                        if ($kvTokenObj -and $kvTokenObj.accessToken) {
                            $tokensToTry += @{ Token = $kvTokenObj.accessToken; Type = "KeyVault" }
                            $Script:KeyVaultToken = $kvTokenObj.accessToken  # Store for reuse
                            Write-Debug "Obtained Key Vault specific token via Azure CLI"
                        }
                    }
                }
            } catch {
                Write-Debug "Could not obtain Key Vault token via CLI: $($_.Exception.Message)"
            }
            
            if ($tokensToTry.Count -eq 0) {
                Write-Debug "No tokens available for REST API calls"
            } else {
                # Try multiple API versions and approaches
                $apiVersions = @("7.4", "7.3", "7.2", "7.1")
                $includeManaged = @($true, $false)
                
                foreach ($tokenInfo in $tokensToTry) {
                    if ($secretsFound) { break }
                    
                    Write-Debug "Trying $($tokenInfo.Type) token for Key Vault access..."
                    
                    foreach ($apiVersion in $apiVersions) {
                        if ($secretsFound) { break }
                        
                        foreach ($includeManagedParam in $includeManaged) {
                            try {
                                # Build URI with different parameters
                                $secretsListUri = "$($VaultUri.TrimEnd('/'))/secrets?api-version=$apiVersion"
                                if ($includeManagedParam) {
                                    $secretsListUri += "&includeManagedSecrets=true"
                                }
                                
                                Write-Debug "Attempting REST API call: $secretsListUri (Token: $($tokenInfo.Type))"
                                
                                $headers = @{
                                    'Authorization' = "Bearer $($tokenInfo.Token)"
                                    'Content-Type' = 'application/json'
                                    'User-Agent' = 'Enum-AzureARM/2.0'
                                }
                                
                                # SSL handling is now managed globally, so just make the request
                                $secretsListResponse = Invoke-RestMethod -Uri $secretsListUri -Headers $headers -Method GET -ErrorAction Stop
                                
                                if ($secretsListResponse -and $secretsListResponse.value -and $secretsListResponse.value.Count -gt 0) {
                                    Write-Debug "SUCCESS: Found $($secretsListResponse.value.Count) secrets via REST API (Token: $($tokenInfo.Type), API: $apiVersion, Managed: $includeManagedParam)"
                                    $secretsFound = $true
                                    
                                    foreach ($secret in $secretsListResponse.value) {
                                        $secretProperties = if ($secret.properties) { $secret.properties } else { $secret.attributes }
                                        
                                        $secretInfo = @{
                                            Name = if ($secret.name) { $secret.name } else { ($secret.id -split '/')[-1] }
                                            Id = $secret.id
                                            Enabled = $secretProperties.enabled
                                            Created = $secretProperties.created
                                            Updated = $secretProperties.updated
                                            ContentType = if ($secret.contentType) { $secret.contentType } else { $secretProperties.contentType }
                                            Tags = $secret.tags
                                            Managed = $secret.managed
                                            RecoveryLevel = $secretProperties.recoveryLevel
                                            RecoverableDays = $secretProperties.recoverableDays
                                            Value = "[PROTECTED - Use Key Vault URI to retrieve]"
                                            VaultUri = "$($VaultUri.TrimEnd('/'))/secrets/$($secret.name -replace '^.*/secrets/', '')"
                                            ValueRetrieved = $false
                                            Source = "REST API ($($tokenInfo.Type) Token)"
                                            RetrievalMethod = "REST API v$apiVersion"
                                        }
                                        
                                        if ($secret.managed -eq $true) {
                                            $secretInfo.SecretType = "Managed Secret"
                                            Write-Debug "Found managed secret via REST API: $($secretInfo.Name)"
                                        } else {
                                            $secretInfo.SecretType = "User Secret"
                                        }
                                        
                                        # Try to get the actual secret value
                                        $secretName = $secretInfo.Name
                                        try {
                                            foreach ($apiVer in @("7.4", "7.3", "7.2")) {
                                                $secretValueUri = "$($VaultUri.TrimEnd('/'))/secrets/$secretName" + "?api-version=$apiVer"
                                                
                                                try {
                                                    $secretValue = Invoke-RestMethod -Uri $secretValueUri -Headers $headers -Method GET -ErrorAction Stop
                                                    if ($secretValue -and $secretValue.value) {
                                                        $secretInfo.Value = $secretValue.value
                                                        $secretInfo.ValueRetrieved = $true
                                                        Write-Debug "Successfully retrieved secret value for: $secretName"
                                                        break
                                                    }
                                                } catch {
                                                    Write-Debug "Secret value retrieval failed for $secretName : $($_.Exception.Message)"
                                                }
                                            }
                                        } catch {
                                            Write-Debug "Could not retrieve secret value for $secretName : $($_.Exception.Message)"
                                        }
                                        
                                        $secrets += [pscustomobject]$secretInfo
                                    }
                                    break
                                }
                                
                            } catch {
                                Write-Debug "REST API attempt failed (Token: $($tokenInfo.Type), API: $apiVersion, Managed: $includeManagedParam): $($_.Exception.Message)"
                            }
                        }
                    }
                }
            }
        }
        
        # Method 3: ARM Resource Provider API (alternative approach)
        if (-not $secretsFound -and $AccessTokenARM -and $SubscriptionId) {
            Write-Debug "Method 3: Attempting ARM Resource Provider API..."
            try {
                $armSecretsUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$KeyVaultName/secrets?api-version=2023-02-01"
                
                # Try to get the resource group from Key Vault resource info
                if ($script:currentResourceGroup) {
                    $armSecretsUri = $armSecretsUri -replace "resourceGroups/\$ResourceGroupName", "resourceGroups/$script:currentResourceGroup"
                    
                    Write-Debug "Attempting ARM Resource Provider API: $armSecretsUri"
                    $armSecretsResponse = Invoke-ARMRequest -Uri $armSecretsUri
                    
                    if ($armSecretsResponse -and $armSecretsResponse.value) {
                        Write-Debug "Found $($armSecretsResponse.value.Count) secrets via ARM Resource Provider API"
                        $secretsFound = $true
                        
                        foreach ($secret in $armSecretsResponse.value) {
                            $secretInfo = @{
                                Name = $secret.name
                                Id = $secret.id
                                Type = $secret.type
                                Properties = $secret.properties
                                Value = "[PROTECTED - ARM Resource Provider API]"
                                Source = "ARM Resource Provider API"
                                RetrievalMethod = "ARM Management API"
                                ValueRetrieved = $false
                            }
                            
                            $secrets += [pscustomobject]$secretInfo
                        }
                    }
                }
            } catch {
                Write-Debug "ARM Resource Provider API failed: $($_.Exception.Message)"
            }
        }
        
        # Final status reporting
        if ($secretsFound) {
            Write-Debug "SUCCESS: Found $($secrets.Count) secrets in Key Vault $KeyVaultName"
        } else {
            Write-Debug "No accessible secrets found or insufficient permissions for Key Vault: $KeyVaultName"
            Write-Debug "This could indicate:"
            Write-Debug "  1. No secrets exist in this Key Vault"
            Write-Debug "  2. Insufficient permissions (need Key Vault Reader + Key Vault Secrets User or similar)"
            Write-Debug "  3. Key Vault access policies don't allow current identity"
            Write-Debug "  4. Managed secrets require specific Azure CLI context"
            Write-Debug "  5. Network access restrictions (firewall, private endpoint)"
        }
        
    } catch {
        Write-Debug "Failed to retrieve secrets from Key Vault $KeyVaultName : $($_.Exception.Message)"
        return @{
            Error = "Failed to access Key Vault secrets: $($_.Exception.Message)"
            AccessNote = "Key Vault access requires specific permissions and proper authentication context"
            DiagnosticInfo = @{
                KeyVaultName = $KeyVaultName
                VaultUri = $VaultUri
                HasARMToken = ($null -ne $AccessTokenARM)
                HasGraphToken = ($null -ne $AccessTokenGraph)
                AzureCLIAvailable = ($null -ne (Get-Command az -ErrorAction SilentlyContinue))
                ErrorDetails = $_.Exception.Message
            }
        }
    }
    
    return @{
        KeyVaultName = $KeyVaultName
        VaultUri = $VaultUri
        SecretsCount = $secrets.Count
        Secrets = $secrets
        AccessTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
        MethodsAttempted = @("Azure CLI", "REST API (Multiple Tokens)", "ARM Resource Provider API")
        Success = $secretsFound
    }
}

function Get-AzureBlueprints {
    <#
    .SYNOPSIS
        Comprehensive Azure Blueprint enumeration including definitions, assignments, and artifacts.
    .DESCRIPTION
        Retrieves Azure Blueprint information at subscription and management group levels,
        including blueprint definitions, assignments, published versions, and artifacts.
        Also searches for blueprint-related files in storage accounts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory=$false)]
        [string]$ManagementGroupId = "root",
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeStorageSearch
    )
    
    $blueprintResults = @{
        SubscriptionBlueprints = @()
        ManagementGroupBlueprints = @()
        BlueprintAssignments = @()
        PublishedBlueprints = @()
        BlueprintArtifacts = @()
        StorageBlueprintFiles = @()
        Summary = @{
            TotalBlueprints = 0
            TotalAssignments = 0
            TotalArtifacts = 0
            TotalStorageFiles = 0
        }
        AccessTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
    }
    
    Write-Debug "Starting comprehensive Azure Blueprint enumeration for subscription: $SubscriptionId"
    
    # Blueprint API endpoints
    $blueprintEndpoints = @(
        @{
            Name = "SubscriptionBlueprints"
            Uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
            Description = "Blueprint definitions at subscription level"
        },
        @{
            Name = "ManagementGroupBlueprints"
            Uri = "https://management.azure.com/providers/Microsoft.Management/managementGroups/$ManagementGroupId/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
            Description = "Blueprint definitions at management group level"
        },
        @{
            Name = "BlueprintAssignments"
            Uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Blueprint/blueprintAssignments?api-version=2018-11-01-preview"
            Description = "Blueprint assignments in subscription"
        }
    )
    
    # Enumerate blueprints from different scopes
    foreach ($endpoint in $blueprintEndpoints) {
        try {
            Write-Debug "Querying: $($endpoint.Description)"
            $response = Invoke-ARMRequest -Uri $endpoint.Uri
            
            if ($response -and $response.value) {
                Write-Debug "Found $($response.value.Count) items for $($endpoint.Name)"
                
                switch ($endpoint.Name) {
                    "SubscriptionBlueprints" {
                        foreach ($blueprint in $response.value) {
                            $blueprintDetail = @{
                                Id = $blueprint.id
                                Name = $blueprint.name
                                Type = $blueprint.type
                                Scope = "Subscription"
                                SubscriptionId = $SubscriptionId
                                DisplayName = $blueprint.properties.displayName
                                Description = $blueprint.properties.description
                                Status = $blueprint.properties.status
                                TargetScope = $blueprint.properties.targetScope
                                Parameters = $blueprint.properties.parameters
                                ResourceGroups = $blueprint.properties.resourceGroups
                                Versions = @()
                                Artifacts = @()
                            }
                            
                            # Get published versions of this blueprint
                            try {
                                $versionsUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Blueprint/blueprints/$($blueprint.name)/versions?api-version=2018-11-01-preview"
                                $versions = Invoke-ARMRequest -Uri $versionsUri
                                if ($versions -and $versions.value) {
                                    $blueprintDetail.Versions = $versions.value
                                    Write-Debug "Found $($versions.value.Count) versions for blueprint: $($blueprint.name)"
                                }
                            } catch {
                                Write-Debug "Could not retrieve versions for blueprint $($blueprint.name): $($_.Exception.Message)"
                            }
                            
                            # Get artifacts for this blueprint
                            try {
                                $artifactsUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Blueprint/blueprints/$($blueprint.name)/artifacts?api-version=2018-11-01-preview"
                                $artifacts = Invoke-ARMRequest -Uri $artifactsUri
                                if ($artifacts -and $artifacts.value) {
                                    $blueprintDetail.Artifacts = $artifacts.value
                                    $blueprintResults.BlueprintArtifacts += $artifacts.value
                                    Write-Debug "Found $($artifacts.value.Count) artifacts for blueprint: $($blueprint.name)"
                                }
                            } catch {
                                Write-Debug "Could not retrieve artifacts for blueprint $($blueprint.name): $($_.Exception.Message)"
                            }
                            
                            $blueprintResults.SubscriptionBlueprints += [pscustomobject]$blueprintDetail
                        }
                    }
                    
                    "ManagementGroupBlueprints" {
                        foreach ($blueprint in $response.value) {
                            $blueprintDetail = @{
                                Id = $blueprint.id
                                Name = $blueprint.name
                                Type = $blueprint.type
                                Scope = "ManagementGroup"
                                ManagementGroupId = $ManagementGroupId
                                DisplayName = $blueprint.properties.displayName
                                Description = $blueprint.properties.description
                                Status = $blueprint.properties.status
                                TargetScope = $blueprint.properties.targetScope
                                Parameters = $blueprint.properties.parameters
                                ResourceGroups = $blueprint.properties.resourceGroups
                                Versions = @()
                                Artifacts = @()
                            }
                            
                            # Get published versions
                            try {
                                $versionsUri = "https://management.azure.com/providers/Microsoft.Management/managementGroups/$ManagementGroupId/providers/Microsoft.Blueprint/blueprints/$($blueprint.name)/versions?api-version=2018-11-01-preview"
                                $versions = Invoke-ARMRequest -Uri $versionsUri
                                if ($versions -and $versions.value) {
                                    $blueprintDetail.Versions = $versions.value
                                }
                            } catch {
                                Write-Debug "Could not retrieve versions for MG blueprint $($blueprint.name): $($_.Exception.Message)"
                            }
                            
                            # Get artifacts
                            try {
                                $artifactsUri = "https://management.azure.com/providers/Microsoft.Management/managementGroups/$ManagementGroupId/providers/Microsoft.Blueprint/blueprints/$($blueprint.name)/artifacts?api-version=2018-11-01-preview"
                                $artifacts = Invoke-ARMRequest -Uri $artifactsUri
                                if ($artifacts -and $artifacts.value) {
                                    $blueprintDetail.Artifacts = $artifacts.value
                                    $blueprintResults.BlueprintArtifacts += $artifacts.value
                                }
                            } catch {
                                Write-Debug "Could not retrieve artifacts for MG blueprint $($blueprint.name): $($_.Exception.Message)"
                            }
                            
                            $blueprintResults.ManagementGroupBlueprints += [pscustomobject]$blueprintDetail
                        }
                    }
                    
                    "BlueprintAssignments" {
                        foreach ($assignment in $response.value) {
                            $assignmentDetail = @{
                                Id = $assignment.id
                                Name = $assignment.name
                                Type = $assignment.type
                                Location = $assignment.location
                                Identity = $assignment.identity
                                BlueprintId = $assignment.properties.blueprintId
                                Scope = $assignment.properties.scope
                                Parameters = $assignment.properties.parameters
                                ResourceGroups = $assignment.properties.resourceGroups
                                Status = $assignment.properties.status
                                Locks = $assignment.properties.locks
                                ProvisioningState = $assignment.properties.provisioningState
                            }
                            
                            $blueprintResults.BlueprintAssignments += [pscustomobject]$assignmentDetail
                        }
                    }
                }
            } else {
                Write-Debug "No items found for $($endpoint.Name)"
            }
            
        } catch {
            Write-Debug "Failed to query $($endpoint.Name): $($_.Exception.Message)"
            if ($_.Exception.Response.StatusCode -eq 403) {
                Write-Debug "Access denied for $($endpoint.Name) - insufficient permissions"
            } elseif ($_.Exception.Response.StatusCode -eq 404) {
                Write-Debug "$($endpoint.Name) not found - may not exist in this tenant"
            }
        }
    }
    
    # Search for blueprint-related files in storage accounts if requested
    if ($IncludeStorageSearch) {
        Write-Debug "Searching for blueprint-related files in storage accounts"
        try {
            $storageUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01"
            $storageAccounts = Invoke-ARMRequest -Uri $storageUri
            
            if ($storageAccounts -and $storageAccounts.value) {
                foreach ($account in $storageAccounts.value) {
                    # Focus on accounts that might contain blueprints
                    if ($account.name -like "*blueprint*" -or $account.name -like "*template*" -or $account.name -eq "examplestorage") {
                        Write-Debug "Checking blueprint-related storage account: $($account.name)"
                        
                        try {
                            # Try to list containers
                            $containerUrl = "https://$($account.name).blob.core.windows.net/?comp=list"
                            
                            # Attempt public access first
                            $containers = Invoke-RestMethod -Uri $containerUrl -Method GET -ErrorAction SilentlyContinue
                            
                            if ($containers -and $containers.EnumerationResults.Containers.Container) {
                                foreach ($container in $containers.EnumerationResults.Containers.Container) {
                                    $containerName = if ($container.Name) { $container.Name } else { $container }
                                    
                                    if ($containerName -like "*blueprint*" -or $containerName -eq "blueprint") {
                                        Write-Debug "Found blueprint container: $containerName in $($account.name)"
                                        
                                        # Try to list blobs in blueprint container
                                        $blobListUrl = "https://$($account.name).blob.core.windows.net/$containerName?restype=container&comp=list"
                                        try {
                                            $blobs = Invoke-RestMethod -Uri $blobListUrl -Method GET -ErrorAction SilentlyContinue
                                            
                                            if ($blobs.EnumerationResults.Blobs.Blob) {
                                                foreach ($blob in $blobs.EnumerationResults.Blobs.Blob) {
                                                    $blobName = if ($blob.Name) { $blob.Name } else { $blob }
                                                    
                                                    $blueprintFile = @{
                                                        StorageAccount = $account.name
                                                        Container = $containerName
                                                        BlobName = $blobName
                                                        Size = $blob.Properties.ContentLength
                                                        LastModified = $blob.Properties.LastModified
                                                        ContentType = $blob.Properties.ContentType
                                                        BlobUrl = "https://$($account.name).blob.core.windows.net/$containerName/$blobName"
                                                        DownloadAttempted = $false
                                                    }
                                                    
                                                    # Try to download small files
                                                    if ($blob.Properties.ContentLength -and $blob.Properties.ContentLength -lt 1MB) {
                                                        try {
                                                            $content = Invoke-RestMethod -Uri $blueprintFile.BlobUrl -Method GET -ErrorAction Stop
                                                            $blueprintFile.Content = $content
                                                            $blueprintFile.DownloadAttempted = $true
                                                            $blueprintFile.DownloadSuccess = $true
                                                            Write-Debug "Successfully downloaded blueprint file: $blobName"
                                                        } catch {
                                                            $blueprintFile.DownloadAttempted = $true
                                                            $blueprintFile.DownloadSuccess = $false
                                                            $blueprintFile.DownloadError = $_.Exception.Message
                                                        }
                                                    }
                                                    
                                                    $blueprintResults.StorageBlueprintFiles += [pscustomobject]$blueprintFile
                                                }
                                            }
                                        } catch {
                                            Write-Debug "Could not list blobs in container $containerName"
                                        }
                                    }
                                }
                            }
                        } catch {
                            Write-Debug "Could not access storage account $($account.name) for blueprint search"
                        }
                    }
                }
            }
        } catch {
            Write-Debug "Failed to search storage accounts for blueprints: $($_.Exception.Message)"
        }
    }
    
    # Update summary
    $blueprintResults.Summary.TotalBlueprints = $blueprintResults.SubscriptionBlueprints.Count + $blueprintResults.ManagementGroupBlueprints.Count
    $blueprintResults.Summary.TotalAssignments = $blueprintResults.BlueprintAssignments.Count
    $blueprintResults.Summary.TotalArtifacts = $blueprintResults.BlueprintArtifacts.Count
    $blueprintResults.Summary.TotalStorageFiles = $blueprintResults.StorageBlueprintFiles.Count
    
    Write-Debug "Blueprint enumeration complete: $($blueprintResults.Summary.TotalBlueprints) blueprints, $($blueprintResults.Summary.TotalAssignments) assignments, $($blueprintResults.Summary.TotalArtifacts) artifacts, $($blueprintResults.Summary.TotalStorageFiles) storage files"
    
    return $blueprintResults
}

function Get-StorageBlobs {
    <#
    .SYNOPSIS
        Downloads blobs from Azure Storage container using multiple authentication methods.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$StorageAccountName,
        
        [Parameter(Mandatory=$true)]
        [string]$ContainerName,
        
        [Parameter(Mandatory=$true)]
        [array]$BlobList,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [string]$StorageAccountKey = $null,
        
        [Parameter(Mandatory=$false)]
        [string]$AccountId = "unknown"
    )
    
    try {
        # Create output directory structure
        $downloadPath = Join-Path $OutputPath "${AccountId}_${StorageAccountName}_${ContainerName}"
        if (-not (Test-Path $downloadPath)) {
            New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
            Write-Verbose "Created download directory: $downloadPath"
        }
        
        $downloadResults = @{
            DownloadPath = $downloadPath
            SuccessfulDownloads = @()
            FailedDownloads = @()
            TotalFiles = $BlobList.Count
        }
        
        Write-Output "  Downloading $($BlobList.Count) blobs to: $downloadPath"
        
        foreach ($blob in $BlobList) {
            try {
                $blobName = $blob.Name
                $localFilePath = Join-Path $downloadPath $blobName
                $downloadSuccess = $false
                
                Write-Debug "Attempting to download blob: $blobName"
                
                # Method 1: Try Azure CLI first (most reliable for RBAC)
                try {
                    az storage blob download --account-name $StorageAccountName --container-name $ContainerName --name $blobName --file $localFilePath --auth-mode login 2>$null | Out-Null
                    if (Test-Path $localFilePath) {
                        $downloadSuccess = $true
                        Write-Debug "Successfully downloaded $blobName using Azure CLI"
                    }
                } catch {
                    Write-Debug "Azure CLI download failed for $blobName : $($_.Exception.Message)"
                }
                
                # Method 2: Try PowerShell Az.Storage module
                if (-not $downloadSuccess) {
                    try {
                        if (Get-Module -ListAvailable -Name Az.Storage) {
                            Import-Module Az.Storage -Force -ErrorAction SilentlyContinue
                            $ctx = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount -ErrorAction SilentlyContinue
                            
                            if ($ctx) {
                                Get-AzStorageBlobContent -Container $ContainerName -Blob $blobName -Destination $localFilePath -Context $ctx -Force -ErrorAction Stop | Out-Null
                                if (Test-Path $localFilePath) {
                                    $downloadSuccess = $true
                                    Write-Debug "Successfully downloaded $blobName using Az.Storage"
                                }
                            }
                        }
                    } catch {
                        Write-Debug "Az.Storage download failed for $blobName : $($_.Exception.Message)"
                    }
                }
                
                # Method 3: Try direct HTTP download with storage key (if available)
                if (-not $downloadSuccess -and $StorageAccountKey) {
                    try {
                        $blobUrl = "https://$StorageAccountName.blob.core.windows.net/$ContainerName/$blobName"
                        $authHeaders = Get-StorageBlobAuthHeader -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey -HttpMethod "GET" -ResourcePath "/$ContainerName/$blobName"
                        
                        if ($authHeaders) {
                            Invoke-RestMethod -Uri $blobUrl -Headers $authHeaders -OutFile $localFilePath -ErrorAction Stop
                            if (Test-Path $localFilePath) {
                                $downloadSuccess = $true
                                Write-Debug "Successfully downloaded $blobName using storage key"
                            }
                        }
                    } catch {
                        Write-Debug "Storage key download failed for $blobName : $($_.Exception.Message)"
                    }
                }
                
                # Record results
                if ($downloadSuccess) {
                    $fileInfo = Get-Item $localFilePath
                    $downloadResults.SuccessfulDownloads += @{
                        BlobName = $blobName
                        LocalPath = $localFilePath
                        Size = $fileInfo.Length
                        Downloaded = Get-Date
                    }
                    Write-Verbose "    [OK] Downloaded: $blobName ($($fileInfo.Length) bytes)"
                } else {
                    $downloadResults.FailedDownloads += @{
                        BlobName = $blobName
                        Error = "All download methods failed"
                    }
                    Write-Warning "    [FAIL] Failed to download: $blobName"
                }
                
            } catch {
                $downloadResults.FailedDownloads += @{
                    BlobName = $blob.Name
                    Error = $_.Exception.Message
                }
                Write-Warning "    [ERROR] Error downloading $($blob.Name): $($_.Exception.Message)"
            }
        }
        
        Write-Output "  Download complete: $($downloadResults.SuccessfulDownloads.Count)/$($downloadResults.TotalFiles) files successful"
        return $downloadResults
        
    } catch {
        Write-Warning "Failed to download blobs from $StorageAccountName/$ContainerName : $($_.Exception.Message)"
        return @{
            DownloadPath = $null
            SuccessfulDownloads = @()
            FailedDownloads = @($BlobList | ForEach-Object { @{ BlobName = $_.Name; Error = "Download setup failed" } })
            TotalFiles = $BlobList.Count
            Error = $_.Exception.Message
        }
    }
}

function Get-StorageBlobAuthHeader {
    <#
    .SYNOPSIS
        Creates authorization header for Azure Storage Blob REST API calls.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$StorageAccountName,
        
        [Parameter(Mandatory=$true)]
        [string]$StorageAccountKey,
        
        [Parameter(Mandatory=$true)]
        [string]$HttpMethod,
        
        [Parameter(Mandatory=$true)]
        [string]$ResourcePath,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$QueryParams = @{},
        
        [Parameter(Mandatory=$false)]
        [string]$ContentType = "",
        
        [Parameter(Mandatory=$false)]
        [string]$ContentLength = "0"
    )
    
    try {
        $utcNow = [DateTime]::UtcNow.ToString("R")
        
        # Build canonical resource string
        $canonicalResource = "/$StorageAccountName$ResourcePath"
        if ($QueryParams.Keys.Count -gt 0) {
            $sortedParams = $QueryParams.GetEnumerator() | Sort-Object Name
            $paramString = ($sortedParams | ForEach-Object { "$($_.Name):$($_.Value)" }) -join "`n"
            $canonicalResource += "`n$paramString"
        }
        
        # Build string to sign
        $stringToSign = @(
            $HttpMethod.ToUpper(),
            "",  # Content-Encoding
            "",  # Content-Language
            $ContentLength,  # Content-Length
            "",  # Content-MD5
            $ContentType,  # Content-Type
            "",  # Date
            "",  # If-Modified-Since
            "",  # If-Match
            "",  # If-None-Match
            "",  # If-Unmodified-Since
            "",  # Range
            "x-ms-date:$utcNow",  # Custom headers
            "x-ms-version:2020-10-02",
            $canonicalResource
        ) -join "`n"
        
        # Create signature
        $keyBytes = [Convert]::FromBase64String($StorageAccountKey)
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = $keyBytes
        $signatureBytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($stringToSign))
        $signature = [Convert]::ToBase64String($signatureBytes)
        
        # Return headers
        return @{
            "Authorization" = "SharedKey $StorageAccountName`:$signature"
            "x-ms-date" = $utcNow
            "x-ms-version" = "2020-10-02"
        }
        
    } catch {
        Write-Warning "Failed to create storage auth header: $($_.Exception.Message)"
        return $null
    }
}

function Get-StorageAccountDetails {
    <#
    .SYNOPSIS
        Retrieves comprehensive Storage Account details including containers, blobs, and permissions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$StorageAccountId,
        
        [Parameter(Mandatory=$true)]
        [string]$StorageAccountName
    )
    
    try {
        Write-Debug "Enumerating storage account details for: $StorageAccountName"
        
        $storageDetails = @{
            Name = $StorageAccountName
            Id = $StorageAccountId
            Containers = @()
            Permissions = @()
            AccessKeys = @()
            NetworkRules = $null
            BlobServiceProperties = $null
            StorageContext = $null
            Error = $null
        }
        
        # Get storage account keys (if we have permission)
        $storageAccountKey = $null
        try {
            $keysResponse = Invoke-ARMRequest -Uri "https://management.azure.com$StorageAccountId/listKeys?api-version=2022-05-01" -Method "POST" -SuppressWarnings
            if ($keysResponse -and $keysResponse.keys) {
                foreach ($key in $keysResponse.keys) {
                    $storageDetails.AccessKeys += @{
                        KeyName = $key.keyName
                        Permissions = $key.permissions
                        CreationTime = $key.creationTime
                    }
                    
                    # Use the first key for blob enumeration
                    if (-not $storageAccountKey -and $key.value) {
                        $storageAccountKey = $key.value
                        Write-Debug "Using storage account key '$($key.keyName)' for blob enumeration"
                    }
                }
                Write-Debug "Retrieved $($keysResponse.keys.Count) storage keys for $StorageAccountName"
            }
        } catch {
            Write-Debug "Could not retrieve storage keys for $StorageAccountName : $($_.Exception.Message)"
            Write-Debug "Note: Storage Account Key access requires 'Storage Account Key Operator Service Role' or higher permissions"
        }
        
        # Get blob service properties
        try {
            $blobProps = Invoke-ARMRequest -Uri "https://management.azure.com$StorageAccountId/blobServices/default?api-version=2022-05-01"
            if ($blobProps) {
                $storageDetails.BlobServiceProperties = @{
                    PublicAccess = $blobProps.properties.publicAccess
                    ChangeFeed = $blobProps.properties.changeFeed
                    VersioningEnabled = $blobProps.properties.isVersioningEnabled
                    DefaultServiceVersion = $blobProps.properties.defaultServiceVersion
                }
            }
        } catch {
            Write-Debug "Could not retrieve blob service properties for $StorageAccountName : $($_.Exception.Message)"
        }
        
        # Get containers
        try {
            $containersResponse = Invoke-ARMRequest -Uri "https://management.azure.com$StorageAccountId/blobServices/default/containers?api-version=2022-05-01"
            if ($containersResponse -and $containersResponse.value) {
                Write-Debug "Found $($containersResponse.value.Count) containers in $StorageAccountName"
                
                foreach ($container in $containersResponse.value) {
                    $containerDetail = @{
                        Name = $container.name
                        PublicAccess = $container.properties.publicAccess
                        LastModified = $container.properties.lastModifiedTime
                        LeaseStatus = $container.properties.leaseStatus
                        HasImmutabilityPolicy = $container.properties.hasImmutabilityPolicy
                        HasLegalHold = $container.properties.hasLegalHold
                        Blobs = @()
                        BlobCount = 0
                        Error = $null
                    }
                    
                    # Try multiple approaches to enumerate blobs
                    $blobEnumerated = $false
                    
                    # Method 1: Use Storage REST API with account key (if available)
                    if ($storageAccountKey) {
                        try {
                            Write-Debug "Enumerating blobs using storage account key in container: $($container.name)"
                            
                            $resourcePath = "/$($container.name)"
                            $queryParams = @{
                                "restype" = "container"
                                "comp" = "list"
                                "maxresults" = "1000"  # Limit to first 1000 blobs for performance
                            }
                            
                            $authHeaders = Get-StorageBlobAuthHeader -StorageAccountName $StorageAccountName -StorageAccountKey $storageAccountKey -HttpMethod "GET" -ResourcePath $resourcePath -QueryParams $queryParams
                            
                            if ($authHeaders) {
                                $blobUrl = "https://$StorageAccountName.blob.core.windows.net$resourcePath" + "?" + (($queryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&")
                                
                                $response = Invoke-RestMethod -Uri $blobUrl -Headers $authHeaders -Method GET -TimeoutSec 30 -ErrorAction Stop
                                
                                if ($response -and $response.EnumerationResults -and $response.EnumerationResults.Blobs) {
                                    $blobs = @()
                                    
                                    # Handle both single blob and multiple blobs
                                    $blobList = $response.EnumerationResults.Blobs.Blob
                                    if ($blobList) {
                                        if ($blobList -is [array]) {
                                            foreach ($blob in $blobList) {
                                                $blobs += @{
                                                    Name = $blob.Name
                                                    Size = [long]$blob.Properties.'Content-Length'
                                                    LastModified = $blob.Properties.'Last-Modified'
                                                    ContentType = $blob.Properties.'Content-Type'
                                                    ETag = $blob.Properties.Etag
                                                    BlobType = $blob.Properties.BlobType
                                                }
                                            }
                                        } else {
                                            # Single blob
                                            $blobs += @{
                                                Name = $blobList.Name
                                                Size = [long]$blobList.Properties.'Content-Length'
                                                LastModified = $blobList.Properties.'Last-Modified'
                                                ContentType = $blobList.Properties.'Content-Type'
                                                ETag = $blobList.Properties.Etag
                                                BlobType = $blobList.Properties.BlobType
                                            }
                                        }
                                    }
                                    
                                    $containerDetail.Blobs = $blobs
                                    $containerDetail.BlobCount = $blobs.Count
                                    $blobEnumerated = $true
                                    
                                    Write-Debug "Found $($blobs.Count) blobs in container $($container.name) using storage key"
                                    
                                } else {
                                    $containerDetail.Blobs = @()
                                    $containerDetail.BlobCount = 0
                                    $blobEnumerated = $true
                                    Write-Debug "No blobs found in container $($container.name)"
                                }
                            }
                            
                        } catch {
                            Write-Debug "Failed to enumerate blobs using storage key in container $($container.name): $($_.Exception.Message)"
                        }
                    }
                    
                    # Method 2: Try using Azure CLI (if available and authenticated)
                    if (-not $blobEnumerated) {
                        try {
                            Write-Debug "Attempting blob enumeration using Azure CLI for container: $($container.name)"
                            
                            # Check if Azure CLI is available and authenticated
                            $azAccount = az account show 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
                            if ($azAccount) {
                                $blobListJson = az storage blob list --account-name $StorageAccountName --container-name $container.name --auth-mode login --output json 2>$null
                                
                                if ($blobListJson -and $blobListJson -ne "[]") {
                                    $blobList = $blobListJson | ConvertFrom-Json
                                    $blobs = @()
                                    
                                    foreach ($blob in $blobList) {
                                        $blobs += @{
                                            Name = $blob.name
                                            Size = [long]$blob.properties.contentLength
                                            LastModified = $blob.properties.lastModified
                                            ContentType = $blob.properties.contentSettings.contentType
                                            ETag = $blob.etag
                                            BlobType = $blob.properties.blobType
                                        }
                                    }
                                    
                                    $containerDetail.Blobs = $blobs
                                    $containerDetail.BlobCount = $blobs.Count
                                    $blobEnumerated = $true
                                    
                                    Write-Debug "Found $($blobs.Count) blobs in container $($container.name) using Azure CLI"
                                }
                            }
                            
                        } catch {
                            Write-Debug "Failed to enumerate blobs using Azure CLI in container $($container.name): $($_.Exception.Message)"
                        }
                    }
                    
                    # Method 3: Try using PowerShell Az.Storage module (if available)
                    if (-not $blobEnumerated) {
                        try {
                            Write-Debug "Attempting blob enumeration using Az.Storage module for container: $($container.name)"
                            
                            if (Get-Module -ListAvailable -Name Az.Storage) {
                                Import-Module Az.Storage -Force -ErrorAction SilentlyContinue
                                
                                # Try to get storage context using current Az context
                                $ctx = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount -ErrorAction SilentlyContinue
                                
                                if ($ctx) {
                                    $blobList = Get-AzStorageBlob -Container $container.name -Context $ctx -ErrorAction SilentlyContinue
                                    
                                    if ($blobList) {
                                        $blobs = @()
                                        
                                        foreach ($blob in $blobList) {
                                            $blobs += @{
                                                Name = $blob.Name
                                                Size = $blob.Length
                                                LastModified = $blob.LastModified
                                                ContentType = $blob.ICloudBlob.Properties.ContentType
                                                ETag = $blob.ICloudBlob.Properties.ETag
                                                BlobType = $blob.BlobType.ToString()
                                            }
                                        }
                                        
                                        $containerDetail.Blobs = $blobs
                                        $containerDetail.BlobCount = $blobs.Count
                                        $blobEnumerated = $true
                                        
                                        Write-Debug "Found $($blobs.Count) blobs in container $($container.name) using Az.Storage"
                                    }
                                }
                            }
                            
                        } catch {
                            Write-Debug "Failed to enumerate blobs using Az.Storage in container $($container.name): $($_.Exception.Message)"
                        }
                    }
                    
                    # If all methods failed, provide informative message
                    if (-not $blobEnumerated) {
                        if (-not $storageAccountKey) {
                            $containerDetail.Blobs = @("Blob enumeration requires Storage Blob Data Reader role or storage account key access")
                            Write-Debug "No storage account key available and alternative methods failed for $($container.name)"
                        } else {
                            $containerDetail.Blobs = @("Failed to enumerate blobs - insufficient permissions or connectivity issues")
                            $containerDetail.Error = "All blob enumeration methods failed"
                        }
                    }
                    
                    # Download blobs if enumeration was successful and blobs were found
                    if ($blobEnumerated -and $containerDetail.Blobs -and $containerDetail.Blobs.Count -gt 0 -and $containerDetail.Blobs[0] -is [hashtable]) {
                        try {
                            Write-Output "  Initiating blob download for container: $($container.name)"
                            
                            # Determine account identifier for folder naming
                            $accountIdentifier = "unknown"
                            if ($AccountId) {
                                $accountIdentifier = $AccountId -replace '[\\/:*?"<>|]', '_'
                            } else {
                                try {
                                    $context = Get-AzContext -ErrorAction SilentlyContinue
                                    if ($context -and $context.Account.Id) {
                                        $accountIdentifier = $context.Account.Id -replace '[\\/:*?"<>|]', '_'
                                    }
                                } catch {
                                    Write-Debug "Could not determine account identifier for download path"
                                }
                            }
                            
                            # Download blobs
                            $downloadResults = Get-StorageBlobs -StorageAccountName $StorageAccountName -ContainerName $container.name -BlobList $containerDetail.Blobs -OutputPath "Results" -StorageAccountKey $storageAccountKey -AccountId $accountIdentifier
                            
                            # Add download results to container details
                            $containerDetail.DownloadResults = $downloadResults
                            
                        } catch {
                            Write-Warning "Failed to download blobs from container $($container.name): $($_.Exception.Message)"
                            $containerDetail.DownloadResults = @{
                                Error = $_.Exception.Message
                                SuccessfulDownloads = @()
                                FailedDownloads = @()
                            }
                        }
                    } else {
                        Write-Debug "Skipping blob download for container $($container.name) - no blobs enumerated or enumeration failed"
                    }
                    
                    $storageDetails.Containers += $containerDetail
                }
            } else {
                # ARM API succeeded but returned no containers - try PowerShell fallback
                Write-Output "  ARM API returned no containers - attempting PowerShell fallback method..."
                Write-Debug "containersResponse exists: $($containersResponse -ne $null), has value: $($containersResponse.value -ne $null)"
                
                # Fallback: Try using Get-AzStorageContainer with storage account context
                try {
                    # Extract resource group name from storage account ID
                    # Format: /subscriptions/{subscription}/resourceGroups/{resourceGroup}/providers/Microsoft.Storage/storageAccounts/{name}
                    $resourceGroupName = ($StorageAccountId -split '/')[4]
                    Write-Debug "Storage Account ID: $StorageAccountId"
                    Write-Debug "Extracted resource group name: $resourceGroupName"
                    Write-Output "  Resource Group: $resourceGroupName (extracted from storage account ID)"
                    
                    # Create storage account context
                    Write-Debug "Attempting to get storage account: $StorageAccountName in resource group: $resourceGroupName"
                    $storageAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $StorageAccountName -ErrorAction Stop
                    Write-Debug "Successfully retrieved storage account object"
                    $ctx = $storageAccount.Context
                    Write-Debug "Successfully created storage context"
                    
                    # Store the storage context for later use in downloads
                    $storageDetails.StorageContext = $ctx
                    Write-Debug "Successfully created and stored storage context for $StorageAccountName"
                    Write-Output "  Storage context created successfully for blob downloads"
                    
                    # Get containers using storage context
                    $containers = Get-AzStorageContainer -Context $ctx -ErrorAction Stop
                    Write-Debug "Found $($containers.Count) containers using storage context fallback for $StorageAccountName"
                    Write-Output "  Successfully found $($containers.Count) containers using PowerShell fallback method"
                    
                    foreach ($container in $containers) {
                        $containerDetail = @{
                            Name = $container.Name
                            PublicAccess = $container.PublicAccess
                            LastModified = $container.LastModified
                            LeaseStatus = "Unknown"
                            HasImmutabilityPolicy = $false
                            HasLegalHold = $false
                            Blobs = @()
                            BlobCount = 0
                            Error = $null
                        }
                        
                        # Try to enumerate blobs in this container
                        try {
                            Write-Debug "Enumerating blobs in container: $($container.Name)"
                            $blobs = Get-AzStorageBlob -Container $container.Name -Context $ctx -ErrorAction Stop
                            
                            foreach ($blob in $blobs) {
                                $blobDetail = @{
                                    Name = $blob.Name
                                    Size = $blob.Length
                                    LastModified = $blob.LastModified
                                    ContentType = $blob.BlobType
                                    ETag = $blob.ETag
                                    BlobType = $blob.BlobType
                                }
                                $containerDetail.Blobs += $blobDetail
                            }
                            $containerDetail.BlobCount = $blobs.Count
                            Write-Debug "Successfully enumerated $($blobs.Count) blobs in container: $($container.Name)"
                            Write-Output "    Container '$($container.Name)': Found $($blobs.Count) blobs"
                        } catch {
                            Write-Debug "Failed to enumerate blobs in container $($container.Name): $($_.Exception.Message)"
                            Write-Output "    Container '$($container.Name)': Blob enumeration failed - $($_.Exception.Message)"
                            $containerDetail.Error = "Could not enumerate blobs: $($_.Exception.Message)"
                        }
                        
                        $storageDetails.Containers += $containerDetail
                    }
                    
                    # Clear any previous error since fallback succeeded
                    $storageDetails.Error = $null
                    
                } catch {
                    Write-Debug "PowerShell fallback container enumeration also failed for $StorageAccountName : $($_.Exception.Message)"
                    Write-Output "  PowerShell fallback method also failed: $($_.Exception.Message)"
                    $storageDetails.Error = "Could not retrieve containers via ARM API or PowerShell: $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Debug "Could not retrieve containers via ARM API for $StorageAccountName : $($_.Exception.Message)"
            Write-Output "  ARM container enumeration failed - attempting PowerShell fallback method..."
            
            # Fallback: Try using Get-AzStorageContainer with storage account context
            Write-Debug "Attempting container enumeration using Get-AzStorageContainer fallback method"
            try {
                # Extract resource group name from storage account ID
                # Format: /subscriptions/{subscription}/resourceGroups/{resourceGroup}/providers/Microsoft.Storage/storageAccounts/{name}
                $resourceGroupName = ($StorageAccountId -split '/')[4]
                Write-Debug "Storage Account ID: $StorageAccountId"
                Write-Debug "Extracted resource group name: $resourceGroupName"
                Write-Output "  Resource Group: $resourceGroupName (extracted from storage account ID)"
                
                # Create storage account context
                Write-Debug "Attempting to get storage account: $StorageAccountName in resource group: $resourceGroupName"
                $storageAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $StorageAccountName -ErrorAction Stop
                Write-Debug "Successfully retrieved storage account object"
                $ctx = $storageAccount.Context
                Write-Debug "Successfully created storage context"
                
                # Get containers using storage context
                $containers = Get-AzStorageContainer -Context $ctx -ErrorAction Stop
                Write-Debug "Found $($containers.Count) containers using storage context fallback for $StorageAccountName"
                Write-Output "  Successfully found $($containers.Count) containers using PowerShell fallback method"
                
                foreach ($container in $containers) {
                    $containerDetail = @{
                        Name = $container.Name
                        PublicAccess = $container.PublicAccess
                        LastModified = $container.LastModified
                        LeaseStatus = "Unknown"
                        HasImmutabilityPolicy = $false
                        HasLegalHold = $false
                        Blobs = @()
                        BlobCount = 0
                        Error = $null
                    }
                    
                    # Try to enumerate blobs in this container
                    try {
                        Write-Debug "Enumerating blobs in container: $($container.Name)"
                        $blobs = Get-AzStorageBlob -Container $container.Name -Context $ctx -ErrorAction Stop
                        
                        foreach ($blob in $blobs) {
                            $blobDetail = @{
                                Name = $blob.Name
                                Size = $blob.Length
                                LastModified = $blob.LastModified
                                ContentType = $blob.BlobType
                                ETag = $blob.ETag
                                BlobType = $blob.BlobType
                            }
                            $containerDetail.Blobs += $blobDetail
                        }
                        $containerDetail.BlobCount = $blobs.Count
                        Write-Debug "Successfully enumerated $($blobs.Count) blobs in container: $($container.Name)"
                    } catch {
                        Write-Debug "Failed to enumerate blobs in container $($container.Name): $($_.Exception.Message)"
                        $containerDetail.Error = "Could not enumerate blobs: $($_.Exception.Message)"
                    }
                    
                    $storageDetails.Containers += $containerDetail
                }
                
                # Clear the error since fallback method succeeded
                $storageDetails.Error = $null
                
            } catch {
                Write-Debug "Fallback container enumeration also failed for $StorageAccountName : $($_.Exception.Message)"
                Write-Output "  PowerShell fallback method also failed: $($_.Exception.Message)"
                $storageDetails.Error = "Could not retrieve containers via ARM API or storage context: $($_.Exception.Message)"
            }
        }
        
        # Get IAM permissions on the storage account
        try {
            $permissions = Invoke-ARMRequest -Uri "https://management.azure.com$StorageAccountId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
            if ($permissions -and $permissions.value) {
                Write-Debug "Found $($permissions.value.Count) role assignments for $StorageAccountName"
                
                foreach ($perm in $permissions.value) {
                    $roleName = Get-RoleDefinitionName -RoleDefinitionId $perm.properties.roleDefinitionId
                    $principalName = Get-PrincipalName -PrincipalId $perm.properties.principalId
                    
                    # Get detailed role definition for permissions analysis
                    $roleDetails = $null
                    try {
                        $roleDefResponse = Invoke-ARMRequest -Uri "https://management.azure.com$($perm.properties.roleDefinitionId)?api-version=2022-04-01"
                        if ($roleDefResponse -and $roleDefResponse.properties) {
                            $roleDetails = @{
                                Description = $roleDefResponse.properties.description
                                Actions = $roleDefResponse.properties.permissions[0].actions
                                NotActions = $roleDefResponse.properties.permissions[0].notActions
                                DataActions = $roleDefResponse.properties.permissions[0].dataActions
                                NotDataActions = $roleDefResponse.properties.permissions[0].notDataActions
                            }
                        }
                    } catch {
                        Write-Debug "Could not retrieve role definition details for $($perm.properties.roleDefinitionId)"
                    }
                    
                    $storageDetails.Permissions += @{
                        PrincipalId = $perm.properties.principalId
                        PrincipalName = $principalName
                        RoleDefinitionId = $perm.properties.roleDefinitionId
                        RoleName = $roleName
                        Scope = $perm.properties.scope
                        PrincipalType = $perm.properties.principalType
                        RoleDetails = $roleDetails
                        CreatedOn = $perm.properties.createdOn
                        UpdatedOn = $perm.properties.updatedOn
                    }
                }
            }
        } catch {
            Write-Debug "Could not retrieve IAM permissions for $StorageAccountName : $($_.Exception.Message)"
        }
        
        # Get current user's effective permissions on the storage account
        try {
            # Try to get current user context
            $currentUserContext = $null
            if ($UseCurrentUser) {
                $currentUserContext = Get-AzContext -ErrorAction SilentlyContinue
            }
            
            if ($currentUserContext -and $currentUserContext.Account.Id) {
                Write-Debug "Analyzing effective permissions for current user: $($currentUserContext.Account.Id)"
                
                # Get user's role assignments on this storage account
                $userPermissions = $storageDetails.Permissions | Where-Object { 
                    $_.PrincipalName -like "*$($currentUserContext.Account.Id)*" -or 
                    $_.PrincipalId -eq $currentUserContext.Account.Id 
                }
                
                $effectivePermissions = @{
                    UserId = $currentUserContext.Account.Id
                    UserType = $currentUserContext.Account.Type
                    DirectAssignments = $userPermissions
                    EffectiveActions = @()
                    EffectiveDataActions = @()
                    BlobPermissions = @{
                        CanListBlobs = $false
                        CanReadBlobs = $false
                        CanWriteBlobs = $false
                        CanDeleteBlobs = $false
                    }
                }
                
                # Analyze effective permissions
                foreach ($perm in $userPermissions) {
                    if ($perm.RoleDetails) {
                        $effectivePermissions.EffectiveActions += $perm.RoleDetails.Actions
                        $effectivePermissions.EffectiveDataActions += $perm.RoleDetails.DataActions
                    }
                }
                
                # Determine blob-specific permissions
                $allDataActions = $effectivePermissions.EffectiveDataActions
                if ($allDataActions -contains "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read" -or 
                    $allDataActions -contains "*" -or 
                    ($allDataActions -contains "Microsoft.Storage/storageAccounts/blobServices/*")) {
                    $effectivePermissions.BlobPermissions.CanReadBlobs = $true
                }
                
                if ($allDataActions -contains "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action" -or 
                    $allDataActions -contains "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write" -or
                    $allDataActions -contains "*") {
                    $effectivePermissions.BlobPermissions.CanWriteBlobs = $true
                }
                
                if ($allDataActions -contains "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete" -or 
                    $allDataActions -contains "*") {
                    $effectivePermissions.BlobPermissions.CanDeleteBlobs = $true
                }
                
                if ($allDataActions -contains "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/list/action" -or
                    $effectivePermissions.BlobPermissions.CanReadBlobs) {
                    $effectivePermissions.BlobPermissions.CanListBlobs = $true
                }
                
                $storageDetails.CurrentUserPermissions = $effectivePermissions
            }
        } catch {
            Write-Debug "Could not analyze current user permissions for $StorageAccountName : $($_.Exception.Message)"
        }
        
        return $storageDetails
        
    } catch {
        Write-Warning "Failed to get detailed storage account information for $StorageAccountName : $($_.Exception.Message)"
        return @{
            Name = $StorageAccountName
            Id = $StorageAccountId
            Error = "Failed to retrieve details: $($_.Exception.Message)"
        }
    }
}

function Get-StorageAccountFiles {
    <#
    .SYNOPSIS
        Downloads all accessible files from a Storage Account with organized folder structure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$StorageAccountName,
        
        [Parameter(Mandatory=$false)]
        [string]$StorageAccountKey,
        
        [Parameter(Mandatory=$true)]
        [array]$ContainerDetails,
        
        [Parameter(Mandatory=$false)]
        [string]$AccountId = "unknown",
        
        [Parameter(Mandatory=$false)]
        [object]$StorageContext = $null
    )
    
    try {
        Write-Output "  Initiating comprehensive file download for Storage Account: $StorageAccountName"
        Write-Output "  Processing $(@($ContainerDetails).Count) containers for file downloads..."
        
        # Show container summary for debugging
        $normalContainers = @($ContainerDetails | Where-Object { $_.Blobs -and $_.Blobs.Count -gt 0 -and $_.Blobs[0] -isnot [string] })
        $blindDownloadContainers = @($ContainerDetails | Where-Object { $_.Error -and $_.Error -like "*blind download*" })
        $emptyContainers = @($ContainerDetails | Where-Object { (-not $_.Blobs -or $_.Blobs.Count -eq 0) -and (-not ($_.Error -and $_.Error -like "*blind download*")) })
        
        Write-Output "    Container Analysis:"
        Write-Output "      Normal containers with enumerated blobs: $($normalContainers.Count)"
        Write-Output "      Containers requiring blind download: $($blindDownloadContainers.Count)"  
        Write-Output "      Empty/inaccessible containers (will be skipped): $($emptyContainers.Count)"
        
        # Show available authentication methods
        $hasStorageKey = $StorageAccountKey -ne $null -and $StorageAccountKey -ne ""
        $hasStorageContext = $StorageContext -ne $null
        $hasAccessToken = $script:accessToken -ne $null -and $script:accessToken -ne ""
        $hasAzureCLI = $false
        try {
            $azAccount = az account show 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
            $hasAzureCLI = $azAccount -ne $null
        } catch { }
        
        Write-Output "    Available Authentication Methods:"
        Write-Output "      Storage Context: $(if ($hasStorageContext) { 'Available' } else { 'Not Available' })"
        Write-Output "      Storage Account Key: $(if ($hasStorageKey) { 'Available' } else { 'Not Available' })"
        Write-Output "      Azure CLI Login: $(if ($hasAzureCLI) { 'Available' } else { 'Not Available' })"
        Write-Output "      Bearer Token: $(if ($hasAccessToken) { 'Available' } else { 'Not Available' })"
        
        # Note: Account identifier handling moved to individual file processing for better organization
        
        # Create base Results directory
        $resultsDir = Join-Path -Path (Split-Path $script:MyInvocation.MyCommand.Path -Parent) -ChildPath "Results"
        if (-not (Test-Path $resultsDir)) {
            New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null
        }
        
        $downloadSummary = @{
            StorageAccountName = $StorageAccountName
            TotalContainers = $ContainerDetails.Count
            ProcessedContainers = 0
            SuccessfulDownloads = 0
            FailedDownloads = 0
            TotalFilesProcessed = 0
            BlindDownloadAttempts = 0
            BlindDownloadSuccesses = 0
            DownloadFolders = @()
            Errors = @()
        }
        
        foreach ($container in $ContainerDetails) {
            $isBlindDownload = $false
            
            # Enhanced container processing logic - don't skip containers too aggressively
            if (-not $container.Blobs -or $container.Blobs.Count -eq 0) {
                # If no blobs enumerated but container exists, offer blind download
                Write-Debug "    Container $($container.name) - no blobs enumerated, checking for blind download eligibility"
                if ($container.Error -and $container.Error -like "*blind download*") {
                    $isBlindDownload = $true
                    Write-Debug "    Container marked for blind download: $($container.name)"
                } else {
                    Write-Debug "    Skipping container $($container.name) - no accessible blobs and not marked for blind download"
                    continue
                }
            }
            
            # Check if blobs are error messages (enumeration failure) but still allow processing
            if (-not $isBlindDownload -and $container.Blobs -and $container.Blobs.Count -gt 0 -and $container.Blobs[0] -is [string]) {
                # If first blob is a string (error), check if we should do blind download
                Write-Debug "    Container $($container.name) - blob enumeration had errors, checking for blind download option"
                if ($container.Error -and $container.Error -like "*blind download*") {
                    $isBlindDownload = $true
                    Write-Debug "    Converting to blind download: $($container.name)"
                } else {
                    Write-Debug "    Skipping container $($container.name) - blob enumeration failed and no blind download option"
                    continue
                }
            }
            
            # Check if this is a blind download attempt (fake blob entry)
            if ($container.Error -and $container.Error -like "*blind download*") {
                $isBlindDownload = $true
                Write-Debug "    Attempting blind download for container $($container.name)"
            }
            
            try {
                # Create organized folder structure: storageaccount_NAME_CONTAINER_NAME
                $folderName = "storageaccount_$($StorageAccountName)_$($container.name)" -replace '[\\/:*?"<>|]', '_'
                $downloadPath = Join-Path -Path $resultsDir -ChildPath $folderName
                
                if (-not (Test-Path $downloadPath)) {
                    New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null
                    Write-Output "    Created download folder: $folderName"
                }
                
                $downloadSummary.DownloadFolders += $folderName
                $containerSuccess = 0
                $containerFailed = 0
                
                # Handle blind download attempts
                if ($isBlindDownload) {
                    Write-Output "    Attempting blind download for container: $($container.name) (trying common file names)"
                    
                    # Try common blob/file names when we can't enumerate
                    $commonBlobNames = @(
                        'index.html', 'default.html', 'home.html', 'main.html',
                        'config.json', 'settings.json', 'app.config', 'web.config',
                        'README.md', 'readme.txt', 'README.txt', 'LICENSE', 'LICENSE.txt',
                        'backup.zip', 'data.zip', 'files.zip', 'export.zip',
                        'log.txt', 'error.log', 'access.log', 'debug.log',
                        'data.csv', 'export.csv', 'users.csv', 'records.csv',
                        'image.jpg', 'photo.png', 'logo.png', 'banner.jpg',
                        'document.pdf', 'report.pdf', 'manual.pdf', 'guide.pdf',
                        'database.sql', 'schema.sql', 'backup.sql',
                        'app.js', 'main.js', 'script.js', 'bundle.js',
                        'style.css', 'main.css', 'theme.css', 'bootstrap.css',
                        'package.json', 'composer.json', 'requirements.txt', 'Gemfile'
                    )
                    
                    # Add container-specific file names based on container name
                    $containerSpecificNames = @()
                    $containerNameLower = $container.name.ToLower()
                    
                    # Add variations of the container name with common extensions
                    $containerSpecificNames += "$containerNameLower.json"
                    $containerSpecificNames += "$containerNameLower.jpg"
                    $containerSpecificNames += "$containerNameLower.txt"
                    $containerSpecificNames += "$containerNameLower.xml"
                    $containerSpecificNames += "$containerNameLower.yml"
                    $containerSpecificNames += "$containerNameLower.yaml"
                    $containerSpecificNames += "$containerNameLower.pdf"
                    $containerSpecificNames += "$containerNameLower.zip"
                    $containerSpecificNames += "$($containerNameLower)_backup.zip"
                    $containerSpecificNames += "$($containerNameLower)_data.csv"
                    
                    # Specific patterns for known container types
                    switch -Wildcard ($containerNameLower) {
                        "*blueprint*" { 
                            $containerSpecificNames += @("template.json", "architecture.json", "design.pdf", "specification.pdf")
                        }
                        "*backup*" { 
                            $containerSpecificNames += @('backup.tar.gz', 'dump.sql', 'restore.sql', 'backup.bak')
                        }
                        "*log*" { 
                            $containerSpecificNames += @('application.log', 'system.log', 'audit.log', 'error.log')
                        }
                        "*config*" { 
                            $containerSpecificNames += @('configuration.xml', 'settings.ini', 'config.properties')
                        }
                        "*data*" { 
                            $containerSpecificNames += @('database.db', 'data.sqlite', 'export.xlsx')
                        }
                    }
                    
                    # Combine common names with container-specific names
                    $allBlobNames = $commonBlobNames + $containerSpecificNames | Select-Object -Unique
                    
                    $blobsToTry = @()
                    foreach ($blobName in $allBlobNames) {
                        $blobsToTry += @{
                            Name = $blobName
                            Size = 0
                            LastModified = "Unknown"
                            ContentType = "Unknown"
                            ETag = "Unknown"
                            BlobType = "Unknown"
                        }
                    }
                    
                    Write-Output "    Trying $($blobsToTry.Count) common file names for blind download"
                    Write-Output "    This may take 15-30 minutes - progress will be shown below..."
                } else {
                    Write-Output "    Processing container: $($container.name) ($($container.Blobs.Count) blobs)"
                    $blobsToTry = $container.Blobs
                }
                
                # Initialize progress tracking
                $totalFiles = $blobsToTry.Count
                $currentFileIndex = 0
                
                foreach ($blob in $blobsToTry) {
                    try {
                        $downloadSummary.TotalFilesProcessed++
                        $currentFileIndex++
                        
                        if ($isBlindDownload) {
                            $downloadSummary.BlindDownloadAttempts++
                            # Show progress for blind downloads
                            $progressPercent = [math]::Round(($currentFileIndex / $totalFiles) * 100, 1)
                            Write-Output "      [$currentFileIndex/$totalFiles] ($progressPercent%) Trying: $($blob.Name)"
                        }
                        
                        # Create safe filename
                        $safeFileName = $blob.Name -replace '[\\/:*?"<>|]', '_'
                        $localFilePath = Join-Path -Path $downloadPath -ChildPath $safeFileName
                        
                        # Ensure subdirectories exist for nested blob paths
                        $parentDir = Split-Path $localFilePath -Parent
                        if ($parentDir -and -not (Test-Path $parentDir)) {
                            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
                        }
                        
                        $downloadSuccess = $false
                        $permissionError = $false
                        $authMethodUsed = "none"
                        
                        # Enhanced authentication method selection with better error handling
                        Write-Verbose "      Starting download for $($blob.Name) - trying multiple auth methods..."
                        $authMethodDetails = @()
                        
                        # Method 1: Try using Az.Storage module with established storage context (BEST METHOD)
                        if (-not $downloadSuccess) {
                            try {
                                Write-Verbose "      AUTH METHOD 1: Attempting Az.Storage module with storage context..."
                                if (Get-Module -ListAvailable Az.Storage -ErrorAction SilentlyContinue) {
                                    Import-Module Az.Storage -ErrorAction SilentlyContinue
                                    
                                    # Use the passed storage context if available, otherwise try to create one
                                    $contextToUse = $StorageContext
                                    if (-not $contextToUse -and $StorageAccountKey) {
                                        Write-Verbose "      No storage context provided, attempting to create one with storage key"
                                        $contextToUse = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey -ErrorAction SilentlyContinue
                                        $authMethodDetails += "StorageKey-Context"
                                    } elseif (-not $contextToUse) {
                                        Write-Verbose "      No storage context or key available, attempting connected account context"
                                        # Check if we're logged into Azure PowerShell first
                                        $azContext = Get-AzContext -ErrorAction SilentlyContinue
                                        if ($azContext) {
                                            Write-Verbose "      Azure PowerShell context found, creating storage context"
                                            $contextToUse = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount -ErrorAction SilentlyContinue
                                            $authMethodDetails += "AzPowerShell-ConnectedAccount"
                                        } else {
                                            Write-Verbose "      No Azure PowerShell context available"
                                            $authMethodDetails += "AzPowerShell-NotLoggedIn"
                                        }
                                    } else {
                                        Write-Verbose "      Using provided storage context for download"
                                        $authMethodDetails += "ProvidedContext"
                                    }
                                    
                                    if ($contextToUse) {
                                        Write-Verbose "      Attempting download with storage context..."
                                        Get-AzStorageBlobContent -Blob $blob.Name -Container $container.name -Destination $localFilePath -Context $contextToUse -Force -ErrorAction Stop
                                        $downloadSuccess = $true
                                        $authMethodUsed = "Az.Storage-Context ($($authMethodDetails -join ','))"
                                        Write-Verbose "      Downloaded $($blob.Name) using Az.Storage module with context"
                                    } else {
                                        Write-Verbose "      Failed to create storage context for Az.Storage method"
                                        $authMethodDetails += "ContextCreationFailed"
                                    }
                                } else {
                                    Write-Verbose "      Az.Storage module not available"
                                    $authMethodDetails += "Az.Storage-ModuleNotAvailable"
                                }
                            } catch {
                                $errorMsg = $_.Exception.Message
                                if ($errorMsg -match "(403|Forbidden|Unauthorized|401)") {
                                    $permissionError = $true
                                }
                                Write-Verbose "      Failed to download $($blob.Name) using Az.Storage: $errorMsg"
                                $authMethodDetails += "Az.Storage-Exception: $($errorMsg -replace '\n|\r', ' ')"
                            }
                        }
                        
                        # Method 2: Try using storage account key with direct API call
                        if ($StorageAccountKey -and -not $downloadSuccess) {
                            try {
                                Write-Verbose "      AUTH METHOD 2: Attempting storage account key with direct API call..."
                                $blobUri = "https://$StorageAccountName.blob.core.windows.net/$($container.name)/$($blob.Name)"
                                $headers = Get-StorageBlobAuthHeader -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey -HttpMethod "GET" -ResourcePath "/$($container.name)/$($blob.Name)"
                                
                                if ($headers) {
                                    Write-Verbose "      Storage auth headers created, attempting download..."
                                    Invoke-WebRequest -Uri $blobUri -Headers $headers -OutFile $localFilePath -ErrorAction Stop | Out-Null
                                    $downloadSuccess = $true
                                    $authMethodUsed = "StorageKey-API"
                                    Write-Verbose "      Downloaded $($blob.Name) using storage key API"
                                } else {
                                    Write-Verbose "      Failed to create storage auth headers"
                                    $authMethodDetails += "StorageKey-HeaderCreationFailed"
                                }
                            } catch {
                                $errorMsg = $_.Exception.Message
                                if ($errorMsg -match "(403|Forbidden|Unauthorized|401)") {
                                    $permissionError = $true
                                }
                                Write-Verbose "      Failed to download $($blob.Name) using storage key API: $errorMsg"
                                $authMethodDetails += "StorageKey-Exception: $($errorMsg -replace '\n|\r', ' ')"
                            }
                        } elseif (-not $StorageAccountKey -and -not $downloadSuccess) {
                            Write-Verbose "      AUTH METHOD 2: Skipping storage key API - no storage key available"
                            $authMethodDetails += "StorageKey-NotAvailable"
                        }
                        
                        # Method 3: Try using Azure CLI if available
                        if (-not $downloadSuccess) {
                            try {
                                Write-Verbose "      AUTH METHOD 3: Attempting Azure CLI authentication..."
                                $azAccount = az account show 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
                                if ($azAccount) {
                                    Write-Verbose "      Azure CLI is logged in (Account: $($azAccount.user.name)), attempting blob download..."
                                    Write-Verbose "      CLI Command: az storage blob download --account-name $StorageAccountName --container-name $($container.name) --name $($blob.Name) --file `"$localFilePath`" --auth-mode login"
                                    
                                    # Create temp files to capture both stdout and stderr
                                    $tempErrorFile = [System.IO.Path]::GetTempFileName()
                                    $tempOutputFile = [System.IO.Path]::GetTempFileName()
                                    
                                    # Try with login first, then with key if available
                                    $cliArgs = @("storage","blob","download","--account-name",$StorageAccountName,"--container-name",$container.name,"--name",$blob.Name,"--file",$localFilePath)
                                    
                                    # First attempt: OAuth/login authentication
                                    $cliArgs += @("--auth-mode","login")
                                    $process = Start-Process -FilePath "az" -ArgumentList $cliArgs -RedirectStandardError $tempErrorFile -RedirectStandardOutput $tempOutputFile -NoNewWindow -Wait -PassThru
                                    
                                    $cliError = if (Test-Path $tempErrorFile) { Get-Content $tempErrorFile -Raw -ErrorAction SilentlyContinue } else { "" }
                                    $cliOutput = if (Test-Path $tempOutputFile) { Get-Content $tempOutputFile -Raw -ErrorAction SilentlyContinue } else { "" }
                                    
                                    # Clean up temp files
                                    Remove-Item $tempErrorFile -ErrorAction SilentlyContinue
                                    Remove-Item $tempOutputFile -ErrorAction SilentlyContinue
                                    
                                    Write-Verbose "      CLI Exit Code: $($process.ExitCode)"
                                    if ($cliOutput) { Write-Verbose "      CLI Output: $($cliOutput -replace '\n|\r', ' ')" }
                                    if ($cliError) { Write-Verbose "      CLI Error: $($cliError -replace '\n|\r', ' ')" }
                                    
                                    # Check if file was actually downloaded
                                    $fileExists = Test-Path $localFilePath
                                    $fileSize = if ($fileExists) { (Get-Item $localFilePath -ErrorAction SilentlyContinue).Length } else { 0 }
                                    Write-Verbose "      File exists after CLI: $fileExists, Size: $fileSize bytes"
                                    
                                    if ($process.ExitCode -eq 0 -and $fileExists -and $fileSize -gt 0) {
                                        $downloadSuccess = $true
                                        $authMethodUsed = "AzureCLI-Login"
                                        Write-Verbose "      Downloaded $($blob.Name) using Azure CLI (OAuth)"
                                    } else {
                                        $failureReason = "LoginAuth: ExitCode=$($process.ExitCode)"
                                        if ($cliError) { $failureReason += ", Error=$($cliError -replace '\n|\r', ' ')" }
                                        if (-not $fileExists) { $failureReason += ", FileNotCreated" }
                                        elseif ($fileSize -eq 0) { $failureReason += ", EmptyFile" }
                                        
                                        Write-Verbose "      Azure CLI OAuth download failed: $failureReason"
                                        
                                        # If OAuth failed due to permissions and we have a storage account key, try with key authentication
                                        if ($StorageAccountKey -and $cliError -match "(required permissions|Storage Blob Data|permission)") {
                                            Write-Verbose "      Retrying Azure CLI download with storage account key..."
                                            
                                            # Clear previous temp files and create new ones for key attempt
                                            Remove-Item $tempErrorFile -ErrorAction SilentlyContinue
                                            Remove-Item $tempOutputFile -ErrorAction SilentlyContinue
                                            $tempErrorFile = [System.IO.Path]::GetTempFileName()
                                            $tempOutputFile = [System.IO.Path]::GetTempFileName()
                                            
                                            # Remove the file if it was partially created
                                            if (Test-Path $localFilePath) { Remove-Item $localFilePath -Force -ErrorAction SilentlyContinue }
                                            
                                            # Build command with key authentication
                                            $keyCliArgs = @("storage","blob","download","--account-name",$StorageAccountName,"--container-name",$container.name,"--name",$blob.Name,"--file",$localFilePath,"--account-key",$StorageAccountKey)
                                            Write-Verbose "      CLI Key Command: az storage blob download --account-name $StorageAccountName --container-name $($container.name) --name $($blob.Name) --file `"$localFilePath`" --account-key [KEY_REDACTED]"
                                            
                                            $keyProcess = Start-Process -FilePath "az" -ArgumentList $keyCliArgs -RedirectStandardError $tempErrorFile -RedirectStandardOutput $tempOutputFile -NoNewWindow -Wait -PassThru
                                            
                                            $keyCliError = if (Test-Path $tempErrorFile) { Get-Content $tempErrorFile -Raw -ErrorAction SilentlyContinue } else { "" }
                                            $keyCliOutput = if (Test-Path $tempOutputFile) { Get-Content $tempOutputFile -Raw -ErrorAction SilentlyContinue } else { "" }
                                            
                                            Write-Verbose "      CLI Key Exit Code: $($keyProcess.ExitCode)"
                                            if ($keyCliOutput) { Write-Verbose "      CLI Key Output: $($keyCliOutput -replace '\n|\r', ' ')" }
                                            if ($keyCliError) { Write-Verbose "      CLI Key Error: $($keyCliError -replace '\n|\r', ' ')" }
                                            
                                            # Check if key-based download succeeded
                                            $keyFileExists = Test-Path $localFilePath
                                            $keyFileSize = if ($keyFileExists) { (Get-Item $localFilePath -ErrorAction SilentlyContinue).Length } else { 0 }
                                            Write-Verbose "      File exists after CLI key attempt: $keyFileExists, Size: $keyFileSize bytes"
                                            
                                            if ($keyProcess.ExitCode -eq 0 -and $keyFileExists -and $keyFileSize -gt 0) {
                                                $downloadSuccess = $true
                                                $authMethodUsed = "AzureCLI-Key"
                                                Write-Verbose "      Downloaded $($blob.Name) using Azure CLI (Storage Key)"
                                            } else {
                                                $keyFailureReason = "KeyAuth: ExitCode=$($keyProcess.ExitCode)"
                                                if ($keyCliError) { $keyFailureReason += ", Error=$($keyCliError -replace '\n|\r', ' ')" }
                                                Write-Verbose "      Azure CLI key download also failed: $keyFailureReason"
                                                $authMethodDetails += "AzureCLI-Failed: $failureReason; $keyFailureReason"
                                            }
                                        } else {
                                            $authMethodDetails += "AzureCLI-Failed: $failureReason"
                                        }
                                        
                                        if ($cliError -match "(403|Forbidden|Unauthorized|401|BlobNotFound|ContainerNotFound|required permissions|Storage Blob Data|Storage Queue Data|Storage Table Data|auth-mode.*key)") {
                                            $permissionError = $true
                                        }
                                    }
                                } else {
                                    Write-Verbose "      Azure CLI not logged in or not available"
                                    $authMethodDetails += "AzureCLI-NotLoggedIn"
                                }
                            } catch {
                                $errorMsg = $_.Exception.Message
                                if ($errorMsg -match "(403|Forbidden|Unauthorized|401)") {
                                    $permissionError = $true
                                }
                                Write-Verbose "      Failed to download $($blob.Name) using Azure CLI: $errorMsg"
                                $authMethodDetails += "AzureCLI-Exception: $($errorMsg -replace '\n|\r', ' ')"
                            }
                        }
                        
                        # Method 4: Try direct HTTP request with storage-specific token
                        if (-not $downloadSuccess -and $Script:StorageToken) {
                            try {
                                Write-Verbose "      AUTH METHOD 4: Attempting direct HTTP request with storage-specific token..."
                                $blobUri = "https://$StorageAccountName.blob.core.windows.net/$($container.name)/$($blob.Name)"
                                $headers = @{
                                    'Authorization' = "Bearer $Script:StorageToken"
                                    'x-ms-version' = '2020-10-02'
                                }
                                
                                Write-Verbose "      Making storage token request to: $blobUri"
                                Invoke-WebRequest -Uri $blobUri -Headers $headers -OutFile $localFilePath -ErrorAction Stop | Out-Null
                                $downloadSuccess = $true
                                $authMethodUsed = "StorageToken"
                                Write-Verbose "      Downloaded $($blob.Name) using storage-specific token"
                            } catch {
                                $errorMsg = $_.Exception.Message
                                if ($errorMsg -match "(403|Forbidden|Unauthorized|401)") {
                                    $permissionError = $true
                                }
                                Write-Verbose "      Failed to download $($blob.Name) using storage token: $errorMsg"
                                $authMethodDetails += "StorageToken-Exception: $($errorMsg -replace '\n|\r', ' ')"
                            }
                        } elseif (-not $downloadSuccess -and -not $Script:StorageToken) {
                            # Try to get storage token automatically
                            Write-Verbose "      AUTH METHOD 4: No storage token available, attempting to retrieve..."
                            try {
                                $storageTokenResult = Get-ResourceSpecificTokens -TokenType "Storage"
                                if ($storageTokenResult.Success -and $storageTokenResult.StorageToken) {
                                    Write-Verbose "      Storage token retrieved successfully, retrying download..."
                                    $blobUri = "https://$StorageAccountName.blob.core.windows.net/$($container.name)/$($blob.Name)"
                                    $headers = @{
                                        'Authorization' = "Bearer $($storageTokenResult.StorageToken)"
                                        'x-ms-version' = '2020-10-02'
                                    }
                                    
                                    Write-Verbose "      Making auto-retrieved storage token request to: $blobUri"
                                    Invoke-WebRequest -Uri $blobUri -Headers $headers -OutFile $localFilePath -ErrorAction Stop | Out-Null
                                    $downloadSuccess = $true
                                    $authMethodUsed = "StorageToken-AutoRetrieved"
                                    Write-Verbose "      Downloaded $($blob.Name) using auto-retrieved storage token"
                                } else {
                                    Write-Verbose "      Failed to automatically retrieve storage token"
                                    $authMethodDetails += "StorageToken-AutoRetrievalFailed"
                                }
                            } catch {
                                $errorMsg = $_.Exception.Message
                                Write-Verbose "      Failed to download $($blob.Name) using auto-retrieved storage token: $errorMsg"
                                $authMethodDetails += "StorageToken-AutoRetrieval-Exception: $($errorMsg -replace '\n|\r', ' ')"
                            }
                        }
                        
                        # Method 5: Fallback to ARM bearer token (less likely to work for storage)
                        if (-not $downloadSuccess -and $script:accessToken) {
                            try {
                                Write-Verbose "      AUTH METHOD 5: Attempting direct HTTP request with ARM bearer token (fallback)..."
                                $blobUri = "https://$StorageAccountName.blob.core.windows.net/$($container.name)/$($blob.Name)"
                                $headers = @{
                                    'Authorization' = "Bearer $script:accessToken"
                                    'x-ms-version' = '2020-10-02'
                                }
                                
                                Write-Verbose "      Making ARM bearer token request to: $blobUri"
                                Invoke-WebRequest -Uri $blobUri -Headers $headers -OutFile $localFilePath -ErrorAction Stop | Out-Null
                                $downloadSuccess = $true
                                $authMethodUsed = "ARMBearerToken-Fallback"
                                Write-Verbose "      Downloaded $($blob.Name) using ARM bearer token (unexpected success)"
                            } catch {
                                $errorMsg = $_.Exception.Message
                                if ($errorMsg -match "(403|Forbidden|Unauthorized|401)") {
                                    $permissionError = $true
                                }
                                Write-Verbose "      Failed to download $($blob.Name) using ARM bearer token: $errorMsg"
                                $authMethodDetails += "ARMBearerToken-Exception: $($errorMsg -replace '\n|\r', ' ')"
                            }
                        } elseif (-not $downloadSuccess -and -not $script:accessToken) {
                            Write-Verbose "      AUTH METHOD 5: Skipping ARM bearer token - no access token available"
                            $authMethodDetails += "ARMBearerToken-NotAvailable"
                        }
                        
                        # If all methods failed, add comprehensive failure details and guidance
                        if (-not $downloadSuccess) {
                            Write-Verbose "      All authentication methods failed for $($blob.Name). Attempted methods: $($authMethodDetails -join ' | ')"
                            Write-Host "        DETAILED AUTH FAILURE for $($blob.Name): $($authMethodDetails -join ' | ')" -ForegroundColor Yellow
                            $downloadSummary.Errors += "Detailed auth failure for $($blob.Name): $($authMethodDetails -join ' | ')"
                            
                            # Show resource-specific token guidance if this looks like a permission/token issue
                            $needsStorageToken = $authMethodDetails | Where-Object { 
                                $_ -match "(permission|forbidden|unauthorized|StorageToken|required permissions)" 
                            }
                            if ($needsStorageToken -and -not $Script:StorageToken) {
                                Write-Host "        HINT: This may require a storage-specific token. Run:" -ForegroundColor Cyan
                                Write-Host "              az account get-access-token --resource=https://storage.azure.com/" -ForegroundColor White
                                Write-Host "              Then use the token with direct REST API calls" -ForegroundColor Gray
                            }
                        }
                        
                        if ($downloadSuccess) {
                            # Validate that file was actually downloaded and has content
                            if (Test-Path $localFilePath) {
                                $fileInfo = Get-Item $localFilePath
                                if ($fileInfo.Length -eq 0 -and -not $isBlindDownload) {
                                    Write-Debug "      Downloaded file $($blob.Name) is empty - this may be normal"
                                }
                                
                                $containerSuccess++
                                $downloadSummary.SuccessfulDownloads++
                                
                                $fileSizeText = if ($fileInfo.Length -gt 0) { " ($($fileInfo.Length) bytes)" } else { " (empty file)" }
                                
                                if ($isBlindDownload) {
                                    $downloadSummary.BlindDownloadSuccesses++
                                    Write-Host "        SUCCESS: $($blob.Name) downloaded successfully (via $authMethodUsed)$fileSizeText" -ForegroundColor Green
                                } else {
                                    Write-Host "        SUCCESS: $($blob.Name) downloaded successfully (via $authMethodUsed)$fileSizeText" -ForegroundColor Green
                                }
                            } else {
                                # Download method claimed success but file doesn't exist
                                Write-Debug "      Download method claimed success but file not found: $localFilePath"
                                $downloadSuccess = $false
                                $containerFailed++
                                $downloadSummary.FailedDownloads++
                                Write-Host "        FAILED: $($blob.Name) - download method reported success but file not created" -ForegroundColor Red
                            }
                            
                            # Add metadata file with blob information
                            $metadataFile = "$localFilePath.metadata.txt"
                            $blobSize = if ($blob.Size -and $blob.Size -ne 0) { "$($blob.Size) bytes" } else { "Unknown" }
                            $lastModified = if ($blob.LastModified -and $blob.LastModified -ne "Unknown") { $blob.LastModified } else { "Unknown" }
                            $contentType = if ($blob.ContentType -and $blob.ContentType -ne "Unknown") { $blob.ContentType } else { "Unknown" }
                            $eTag = if ($blob.ETag -and $blob.ETag -ne "Unknown") { $blob.ETag } else { "Unknown" }
                            $blobType = if ($blob.BlobType -and $blob.BlobType -ne "Unknown") { $blob.BlobType } else { "Unknown" }
                            $downloadMethod = if ($isBlindDownload) { "Blind Download (no enumeration permissions)" } else { "Normal Download" }
                            
                            $metadataContent = @"
Blob Name: $($blob.Name)
Container: $($container.name)
Storage Account: $StorageAccountName
Size: $blobSize
Last Modified: $lastModified
Content Type: $contentType
ETag: $eTag
Blob Type: $blobType
Download Method: $downloadMethod
Downloaded: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")
"@
                            Set-Content -Path $metadataFile -Value $metadataContent -Encoding UTF8
                        } else {
                            $containerFailed++
                            $downloadSummary.FailedDownloads++
                            $errorDetail = "Failed to download $($blob.Name) from container $($container.name) - all auth methods failed"
                            if ($permissionError) {
                                $errorDetail += " (permission denied)"
                            }
                            $downloadSummary.Errors += $errorDetail
                            
                            # For blind downloads, only show permission errors, not file-not-found errors
                            if ($isBlindDownload) {
                                if ($permissionError) {
                                    Write-Host "        PERMISSION ERROR: $($blob.Name) - access denied" -ForegroundColor Yellow
                                }
                                # Silent for file-not-found cases (expected in blind downloads)
                            } else {
                                $failureReason = if ($permissionError) { "permission denied" } else { "authentication failed" }
                                Write-Host "        FAILED: $($blob.Name) - download failed ($failureReason)" -ForegroundColor Red
                                Write-Debug "        All authentication methods failed for $($blob.Name). Available methods were tried in order: Az.Storage-Context, StorageKey-API, AzureCLI, BearerToken"
                            }
                        }
                        
                    } catch {
                        $containerFailed++
                        $downloadSummary.FailedDownloads++
                        $downloadSummary.Errors += "Error processing blob $($blob.Name): $($_.Exception.Message)"
                        
                        # Check if this is a permission error worth reporting
                        $errorMessage = $_.Exception.Message
                        if ($errorMessage -match "(403|Forbidden|Unauthorized|401)" -and $isBlindDownload) {
                            Write-Host "        PERMISSION ERROR: $($blob.Name) - access denied" -ForegroundColor Yellow
                        } elseif (-not $isBlindDownload) {
                            Write-Host "        ERROR: $($blob.Name) - $errorMessage" -ForegroundColor Red
                        }
                        # Silent for other blind download errors (expected file-not-found cases)
                        
                        Write-Debug "      Error processing blob $($blob.Name): $($_.Exception.Message)"
                    }
                }
                
                $downloadSummary.ProcessedContainers++
                
                if ($isBlindDownload) {
                    Write-Output "      Container $($container.name) (Blind): $containerSuccess successful, $containerFailed failed attempts"
                    if ($containerSuccess -gt 0) {
                        Write-Output "        Successfully found $containerSuccess files using blind download technique!"
                        Write-Output "        Files saved to: $folderName"
                    } else {
                        Write-Output "        No files found using blind download - this may be normal if container is empty or uses non-standard file names"
                        Write-Output "        Tip: If you know specific file names in this container, they can be added to the script's blind download list"
                    }
                } else {
                    Write-Output "      Container $($container.name): $containerSuccess successful, $containerFailed failed downloads"
                }
                
            } catch {
                $downloadSummary.Errors += "Error processing container $($container.name): $($_.Exception.Message)"
                Write-Warning "    Failed to process container $($container.name): $($_.Exception.Message)"
            }
        }
        
        # Create summary report
        $summaryFile = Join-Path -Path $resultsDir -ChildPath "StorageDownload_$($StorageAccountName)_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        $summaryContent = @"
Storage Account File Download Summary
=====================================
Storage Account: $StorageAccountName
Total Containers: $($downloadSummary.TotalContainers)
Processed Containers: $($downloadSummary.ProcessedContainers)
Total Files Processed: $($downloadSummary.TotalFilesProcessed)
Successful Downloads: $($downloadSummary.SuccessfulDownloads)
Failed Downloads: $($downloadSummary.FailedDownloads)
Success Rate: $(if ($downloadSummary.TotalFilesProcessed -gt 0) { [math]::Round(($downloadSummary.SuccessfulDownloads / $downloadSummary.TotalFilesProcessed) * 100, 2) } else { 0 })%

Blind Download Statistics:
  Blind Download Attempts: $($downloadSummary.BlindDownloadAttempts)
  Blind Download Successes: $($downloadSummary.BlindDownloadSuccesses)
  Blind Success Rate: $(if ($downloadSummary.BlindDownloadAttempts -gt 0) { [math]::Round(($downloadSummary.BlindDownloadSuccesses / $downloadSummary.BlindDownloadAttempts) * 100, 2) } else { 0 })%

Download Folders Created:
$($downloadSummary.DownloadFolders | ForEach-Object { "  - $_" } | Out-String)

$(if ($downloadSummary.Errors.Count -gt 0) { 
"Errors Encountered:
$($downloadSummary.Errors | ForEach-Object { "  - $_" } | Out-String)"
} else { "No errors encountered during download process." })

Download completed at: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")
"@
        Set-Content -Path $summaryFile -Value $summaryContent -Encoding UTF8
        
        Write-Output "  Storage Account file download complete. Summary: $($downloadSummary.SuccessfulDownloads)/$($downloadSummary.TotalFilesProcessed) files downloaded"
        if ($downloadSummary.DownloadFolders.Count -gt 0) {
            Write-Output "  Files saved to: $($downloadSummary.DownloadFolders -join ', ')"
        }
        
        return $downloadSummary
        
    } catch {
        Write-Warning "Failed to download files from Storage Account $StorageAccountName : $($_.Exception.Message)"
        return @{
            StorageAccountName = $StorageAccountName
            Error = "Download process failed: $($_.Exception.Message)"
        }
    }
}

function Get-CosmosDbAccountDetails {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CosmosDbAccountId,
        
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            'Authorization' = "Bearer $AccessToken"
            'Content-Type' = 'application/json'
        }
        
        Write-Verbose "Analyzing Cosmos DB Account: $CosmosDbAccountId"
        
        # Initialize account details
        $accountDetails = [PSCustomObject]@{
            AccountId = $CosmosDbAccountId
            AccountName = ($CosmosDbAccountId -split '/')[-1]
            ResourceGroup = ($CosmosDbAccountId -split '/')[4]
            Properties = $null
            Keys = $null
            Databases = @()
            ConnectionStrings = @()
            EffectivePermissions = @()
            RoleAssignments = @()
            Error = $null
        }
        
        # Get account properties
        try {
            $accountUri = "https://management.azure.com$CosmosDbAccountId" + "?api-version=2023-04-15"
            $accountResponse = Invoke-RestMethod -Uri $accountUri -Headers $headers -Method GET
            $accountDetails.Properties = $accountResponse
            Write-Verbose "  Retrieved account properties"
        }
        catch {
            Write-Warning "  Failed to get account properties: $($_.Exception.Message)"
        }
        
        # Get connection strings (requires Cosmos DB Account Reader Role or higher)
        try {
            $connectionStringsUri = "https://management.azure.com$CosmosDbAccountId/listConnectionStrings?api-version=2023-04-15"
            $connectionStringsResponse = Invoke-RestMethod -Uri $connectionStringsUri -Headers $headers -Method POST
            $accountDetails.ConnectionStrings = $connectionStringsResponse.connectionStrings
            Write-Verbose "  Retrieved connection strings"
        }
        catch {
            Write-Verbose "  No access to connection strings: $($_.Exception.Message)"
        }
        
        # Get account keys (requires Cosmos DB Operator or Contributor role)
        try {
            $keysUri = "https://management.azure.com$CosmosDbAccountId/listKeys?api-version=2023-04-15"
            $keysResponse = Invoke-RestMethod -Uri $keysUri -Headers $headers -Method POST
            $accountDetails.Keys = [PSCustomObject]@{
                PrimaryMasterKey = if ($keysResponse.primaryMasterKey) { "[REDACTED - Available]" } else { $null }
                SecondaryMasterKey = if ($keysResponse.secondaryMasterKey) { "[REDACTED - Available]" } else { $null }
                PrimaryReadonlyMasterKey = if ($keysResponse.primaryReadonlyMasterKey) { "[REDACTED - Available]" } else { $null }
                SecondaryReadonlyMasterKey = if ($keysResponse.secondaryReadonlyMasterKey) { "[REDACTED - Available]" } else { $null }
            }
            Write-Verbose "  Retrieved account keys (redacted for security)"
        }
        catch {
            Write-Verbose "  No access to account keys: $($_.Exception.Message)"
        }
        
        # Get SQL databases (for Core SQL API)
        if ($accountDetails.Properties.kind -eq "GlobalDocumentDB") {
            try {
                $databasesUri = "https://management.azure.com$CosmosDbAccountId/sqlDatabases?api-version=2023-04-15"
                $databasesResponse = Invoke-RestMethod -Uri $databasesUri -Headers $headers -Method GET
                
                foreach ($database in $databasesResponse.value) {
                    $dbDetails = [PSCustomObject]@{
                        DatabaseId = $database.id
                        DatabaseName = $database.name
                        Properties = $database.properties
                        Containers = @()
                    }
                    
                    # Get containers for this database
                    try {
                        $containersUri = "https://management.azure.com$($database.id)/containers?api-version=2023-04-15"
                        $containersResponse = Invoke-RestMethod -Uri $containersUri -Headers $headers -Method GET
                        
                        foreach ($container in $containersResponse.value) {
                            $containerDetails = [PSCustomObject]@{
                                ContainerId = $container.id
                                ContainerName = $container.name
                                Properties = $container.properties
                                PartitionKey = $container.properties.resource.partitionKey
                                Throughput = $null
                                DocumentCount = "Unknown (requires direct Cosmos DB access)"
                            }
                            
                            # Try to get throughput settings
                            try {
                                $throughputUri = "https://management.azure.com$($container.id)/throughputSettings/default?api-version=2023-04-15"
                                $throughputResponse = Invoke-RestMethod -Uri $throughputUri -Headers $headers -Method GET
                                $containerDetails.Throughput = $throughputResponse.properties.resource.throughput
                            }
                            catch {
                                Write-Verbose "    No throughput data for container $($container.name)"
                            }
                            
                            $dbDetails.Containers += $containerDetails
                        }
                        
                        Write-Verbose "  Found $($dbDetails.Containers.Count) containers in database $($database.name)"
                    }
                    catch {
                        Write-Verbose "  Failed to get containers for database $($database.name): $($_.Exception.Message)"
                    }
                    
                    $accountDetails.Databases += $dbDetails
                }
                
                Write-Verbose "  Found $($accountDetails.Databases.Count) SQL databases"
            }
            catch {
                Write-Verbose "  Failed to get SQL databases: $($_.Exception.Message)"
            }
        }
        
        # Get MongoDB databases (for MongoDB API)
        if ($accountDetails.Properties.kind -eq "MongoDB") {
            try {
                $mongoDatabasesUri = "https://management.azure.com$CosmosDbAccountId/mongodbDatabases?api-version=2023-04-15"
                $mongoDatabasesResponse = Invoke-RestMethod -Uri $mongoDatabasesUri -Headers $headers -Method GET
                
                foreach ($database in $mongoDatabasesResponse.value) {
                    $dbDetails = [PSCustomObject]@{
                        DatabaseId = $database.id
                        DatabaseName = $database.name
                        Type = "MongoDB"
                        Properties = $database.properties
                        Collections = @()
                    }
                    
                    # Get collections for this MongoDB database
                    try {
                        $collectionsUri = "https://management.azure.com$($database.id)/collections?api-version=2023-04-15"
                        $collectionsResponse = Invoke-RestMethod -Uri $collectionsUri -Headers $headers -Method GET
                        $dbDetails.Collections = $collectionsResponse.value
                        Write-Verbose "  Found $($dbDetails.Collections.Count) collections in MongoDB database $($database.name)"
                    }
                    catch {
                        Write-Verbose "  Failed to get collections for MongoDB database $($database.name): $($_.Exception.Message)"
                    }
                    
                    $accountDetails.Databases += $dbDetails
                }
                
                Write-Verbose "  Found $($accountDetails.Databases.Count) MongoDB databases"
            }
            catch {
                Write-Verbose "  Failed to get MongoDB databases: $($_.Exception.Message)"
            }
        }
        
        # Get role assignments for this Cosmos DB account
        try {
            $roleAssignmentsUri = "https://management.azure.com$CosmosDbAccountId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
            $roleAssignmentsResponse = Invoke-RestMethod -Uri $roleAssignmentsUri -Headers $headers -Method GET
            
            foreach ($assignment in $roleAssignmentsResponse.value) {
                $roleDetails = Get-RoleDefinitionDetails -RoleDefinitionId $assignment.properties.roleDefinitionId -AccessToken $AccessToken
                
                $roleAssignment = [PSCustomObject]@{
                    PrincipalId = $assignment.properties.principalId
                    RoleDefinitionId = $assignment.properties.roleDefinitionId
                    RoleName = if ($roleDetails) { $roleDetails.DisplayName } else { "Unknown Role" }
                    RoleType = if ($roleDetails) { $roleDetails.RoleType } else { "Unknown" }
                    Scope = $assignment.properties.scope
                    Permissions = if ($roleDetails) { $roleDetails.Permissions } else { @() }
                }
                
                $accountDetails.RoleAssignments += $roleAssignment
            }
            
            Write-Verbose "  Found $($accountDetails.RoleAssignments.Count) role assignments"
        }
        catch {
            Write-Verbose "  Failed to get role assignments: $($_.Exception.Message)"
        }
        
        # Analyze effective permissions for current user
        $userPermissions = @()
        
        # Check common Cosmos DB permissions
        $cosmosPermissions = @(
            "Microsoft.DocumentDB/databaseAccounts/read",
            "Microsoft.DocumentDB/databaseAccounts/write", 
            "Microsoft.DocumentDB/databaseAccounts/delete",
            "Microsoft.DocumentDB/databaseAccounts/listKeys/action",
            "Microsoft.DocumentDB/databaseAccounts/listConnectionStrings/action",
            "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/read",
            "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/write",
            "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/read",
            "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/write"
        )
        
        foreach ($permission in $cosmosPermissions) {
            $hasPermission = Test-UserPermission -ResourceId $CosmosDbAccountId -Permission $permission -AccessToken $AccessToken
            if ($hasPermission) {
                $userPermissions += $permission
            }
        }
        
        $accountDetails.EffectivePermissions = $userPermissions
        Write-Verbose "  Current user has $($userPermissions.Count) effective permissions"
        
        return $accountDetails
    }
    catch {
        Write-Warning "Error analyzing Cosmos DB account $CosmosDbAccountId : $($_.Exception.Message)"
        return [PSCustomObject]@{
            AccountId = $CosmosDbAccountId
            Error = $_.Exception.Message
        }
    }
}

function Get-AutomationAccountDetails {
    <#
    .SYNOPSIS
        Retrieves comprehensive Automation Account details including runbooks, credentials, and scripts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AutomationAccountId,
        
        [Parameter(Mandatory=$true)]
        [string]$AutomationAccountName
    )
    
    try {
        Write-Debug "Enumerating automation account details for: $AutomationAccountName"
        
        $automationDetails = @{
            Name = $AutomationAccountName
            Id = $AutomationAccountId
            Runbooks = @()
            Credentials = @()
            Variables = @()
            Modules = @()
            Certificates = @()
            Connections = @()
            Schedules = @()
            Error = $null
        }
        
        # Get runbooks
        try {
            $runbooksResponse = Invoke-ARMRequest -Uri "https://management.azure.com$AutomationAccountId/runbooks?api-version=2020-01-13-preview"
            if ($runbooksResponse -and $runbooksResponse.value) {
                Write-Debug "Found $($runbooksResponse.value.Count) runbooks in $AutomationAccountName"
                
                foreach ($runbook in $runbooksResponse.value) {
                    $runbookDetail = @{
                        Name = $runbook.name
                        RunbookType = $runbook.properties.runbookType
                        State = $runbook.properties.state
                        LogVerbose = $runbook.properties.logVerbose
                        LogProgress = $runbook.properties.logProgress
                        CreationTime = $runbook.properties.creationTime
                        LastModifiedTime = $runbook.properties.lastModifiedTime
                        Description = $runbook.properties.description
                        ScriptContent = $null
                        Error = $null
                    }
                    
                    # Get runbook content/script
                    try {
                        $contentResponse = Invoke-ARMRequest -Uri "https://management.azure.com$AutomationAccountId/runbooks/$($runbook.name)/content?api-version=2020-01-13-preview"
                        if ($contentResponse) {
                            $runbookDetail.ScriptContent = $contentResponse
                            Write-Debug "Retrieved script content for runbook: $($runbook.name)"
                        }
                    } catch {
                        $runbookDetail.Error = "Could not retrieve script content: $($_.Exception.Message)"
                        Write-Debug "Could not retrieve script for runbook $($runbook.name): $($_.Exception.Message)"
                    }
                    
                    $automationDetails.Runbooks += $runbookDetail
                }
            }
        } catch {
            Write-Debug "Could not retrieve runbooks for $AutomationAccountName : $($_.Exception.Message)"
        }
        
        # Get credentials
        try {
            $credsResponse = Invoke-ARMRequest -Uri "https://management.azure.com$AutomationAccountId/credentials?api-version=2020-01-13-preview"
            if ($credsResponse -and $credsResponse.value) {
                Write-Debug "Found $($credsResponse.value.Count) credentials in $AutomationAccountName"
                
                foreach ($cred in $credsResponse.value) {
                    $automationDetails.Credentials += @{
                        Name = $cred.name
                        UserName = $cred.properties.userName
                        Description = $cred.properties.description
                        CreationTime = $cred.properties.creationTime
                        LastModifiedTime = $cred.properties.lastModifiedTime
                        # Note: Password values are not returned by the API for security
                    }
                }
            }
        } catch {
            Write-Debug "Could not retrieve credentials for $AutomationAccountName : $($_.Exception.Message)"
        }
        
        # Get variables
        try {
            $varsResponse = Invoke-ARMRequest -Uri "https://management.azure.com$AutomationAccountId/variables?api-version=2020-01-13-preview"
            if ($varsResponse -and $varsResponse.value) {
                Write-Debug "Found $($varsResponse.value.Count) variables in $AutomationAccountName"
                
                foreach ($var in $varsResponse.value) {
                    $automationDetails.Variables += @{
                        Name = $var.name
                        Value = $var.properties.value
                        IsEncrypted = $var.properties.isEncrypted
                        Description = $var.properties.description
                        CreationTime = $var.properties.creationTime
                        LastModifiedTime = $var.properties.lastModifiedTime
                    }
                }
            }
        } catch {
            Write-Debug "Could not retrieve variables for $AutomationAccountName : $($_.Exception.Message)"
        }
        
        # Get modules
        try {
            $modulesResponse = Invoke-ARMRequest -Uri "https://management.azure.com$AutomationAccountId/modules?api-version=2020-01-13-preview"
            if ($modulesResponse -and $modulesResponse.value) {
                Write-Debug "Found $($modulesResponse.value.Count) modules in $AutomationAccountName"
                
                foreach ($module in $modulesResponse.value) {
                    $automationDetails.Modules += @{
                        Name = $module.name
                        Version = $module.properties.version
                        SizeInBytes = $module.properties.sizeInBytes
                        ActivityCount = $module.properties.activityCount
                        ProvisioningState = $module.properties.provisioningState
                        CreationTime = $module.properties.creationTime
                        LastModifiedTime = $module.properties.lastModifiedTime
                    }
                }
            }
        } catch {
            Write-Debug "Could not retrieve modules for $AutomationAccountName : $($_.Exception.Message)"
        }
        
        # Get certificates
        try {
            $certsResponse = Invoke-ARMRequest -Uri "https://management.azure.com$AutomationAccountId/certificates?api-version=2020-01-13-preview"
            if ($certsResponse -and $certsResponse.value) {
                Write-Debug "Found $($certsResponse.value.Count) certificates in $AutomationAccountName"
                
                foreach ($cert in $certsResponse.value) {
                    $automationDetails.Certificates += @{
                        Name = $cert.name
                        Thumbprint = $cert.properties.thumbprint
                        ExpiryTime = $cert.properties.expiryTime
                        IsExportable = $cert.properties.isExportable
                        Description = $cert.properties.description
                        CreationTime = $cert.properties.creationTime
                        LastModifiedTime = $cert.properties.lastModifiedTime
                    }
                }
            }
        } catch {
            Write-Debug "Could not retrieve certificates for $AutomationAccountName : $($_.Exception.Message)"
        }
        
        return $automationDetails
        
    } catch {
        Write-Warning "Failed to get detailed automation account information for $AutomationAccountName : $($_.Exception.Message)"
        return @{
            Name = $AutomationAccountName
            Id = $AutomationAccountId
            Error = "Failed to retrieve details: $($_.Exception.Message)"
        }
    }
}

function Get-AppConfigurationDetails {
    <#
    .SYNOPSIS
        Retrieves comprehensive details for an Azure App Configuration store.
    .PARAMETER AppConfigId
        The full resource ID of the App Configuration store
    .PARAMETER AppConfigName
        The name of the App Configuration store
    .PARAMETER AccessToken
        The access token for API authentication
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppConfigId,
        
        [Parameter(Mandatory = $true)]
        [string]$AppConfigName,
        
        [Parameter(Mandatory = $false)]
        [string]$AccessToken
    )

    try {
        Write-Debug "Getting detailed App Configuration information for: $AppConfigName"
        
        $appConfigDetails = @{
            Name = $AppConfigName
            Id = $AppConfigId
            Keys = @()
            KeyValues = @()
            Features = @()
            AccessPolicies = @()
            PrivateEndpoints = @()
            NetworkAcls = @{}
            Replicas = @()
            Error = $null
        }

        # Get App Configuration store details
        $appConfigInfo = Invoke-ARMRequest -Uri "https://management.azure.com$AppConfigId" + "?api-version=2023-03-01"
        if ($appConfigInfo) {
            $appConfigDetails.Endpoint = $appConfigInfo.properties.endpoint
            $appConfigDetails.CreationDate = $appConfigInfo.properties.creationDate
            $appConfigDetails.ProvisioningState = $appConfigInfo.properties.provisioningState
            $appConfigDetails.PublicNetworkAccess = $appConfigInfo.properties.publicNetworkAccess
            $appConfigDetails.DisableLocalAuth = $appConfigInfo.properties.disableLocalAuth
            $appConfigDetails.SoftDeleteRetentionInDays = $appConfigInfo.properties.softDeleteRetentionInDays
            $appConfigDetails.EnablePurgeProtection = $appConfigInfo.properties.enablePurgeProtection
            $appConfigDetails.Sku = $appConfigInfo.sku
            $appConfigDetails.SystemData = $appConfigInfo.systemData
        }

        # Get access keys (if we have permissions)
        try {
            Write-Debug "Attempting to retrieve access keys for $AppConfigName"
            $keysResponse = Invoke-ARMRequest -Uri "https://management.azure.com$AppConfigId/listKeys?api-version=2023-03-01" -Method POST
            if ($keysResponse -and $keysResponse.value) {
                Write-Debug "Found $($keysResponse.value.Count) access keys for $AppConfigName"
                
                foreach ($key in $keysResponse.value) {
                    $appConfigDetails.Keys += @{
                        Name = $key.name
                        Id = $key.id
                        ReadOnly = $key.readOnly
                        ConnectionString = if ($key.connectionString) { "[REDACTED - Available]" } else { "Not Available" }
                        LastModified = $key.lastModified
                    }
                }
            }
        } catch {
            Write-Debug "Could not retrieve access keys for $AppConfigName (likely insufficient permissions): $($_.Exception.Message)"
            $appConfigDetails.Keys = @(@{ Error = "Access denied or insufficient permissions" })
        }

        # Get key-values (configuration data) - this requires data plane access
        try {
            if ($appConfigInfo -and $appConfigInfo.properties.endpoint) {
                Write-Debug "Attempting to retrieve configuration key-values for $AppConfigName"
                
                # Try to get key-values using REST API (requires appropriate authentication)
                $endpoint = $appConfigInfo.properties.endpoint.TrimEnd('/')
                
                # Note: This would require App Configuration data plane authentication
                # For enumeration purposes, we'll document the attempt
                $appConfigDetails.KeyValues = @(@{ 
                    Note = "Key-value enumeration requires App Configuration data plane access"
                    Endpoint = $endpoint
                    ApiVersion = "1.0"
                    DataPlaneUrl = "$endpoint/kv?api-version=1.0"
                })
            }
        } catch {
            Write-Debug "Could not retrieve key-values for $AppConfigName : $($_.Exception.Message)"
            $appConfigDetails.KeyValues = @(@{ Error = $_.Exception.Message })
        }

        # Get feature flags (if any)
        try {
            if ($appConfigInfo -and $appConfigInfo.properties.endpoint) {
                Write-Debug "Checking for feature flags in $AppConfigName"
                $appConfigDetails.Features = @(@{ 
                    Note = "Feature flag enumeration requires App Configuration data plane access"
                    Endpoint = $appConfigInfo.properties.endpoint
                })
            }
        } catch {
            Write-Debug "Could not retrieve feature flags for $AppConfigName : $($_.Exception.Message)"
        }

        # Get private endpoints
        try {
            Write-Debug "Retrieving private endpoints for $AppConfigName"
            $privateEndpointsResponse = Invoke-ARMRequest -Uri "https://management.azure.com$AppConfigId/privateEndpointConnections?api-version=2023-03-01"
            if ($privateEndpointsResponse -and $privateEndpointsResponse.value) {
                Write-Debug "Found $($privateEndpointsResponse.value.Count) private endpoints for $AppConfigName"
                
                foreach ($pe in $privateEndpointsResponse.value) {
                    $appConfigDetails.PrivateEndpoints += @{
                        Name = $pe.name
                        Id = $pe.id
                        ProvisioningState = $pe.properties.provisioningState
                        PrivateEndpointId = $pe.properties.privateEndpoint.id
                        ConnectionState = $pe.properties.privateLinkServiceConnectionState.status
                        Description = $pe.properties.privateLinkServiceConnectionState.description
                    }
                }
            } else {
                $appConfigDetails.PrivateEndpoints = @(@{ Note = "No private endpoints configured" })
            }
        } catch {
            Write-Debug "Could not retrieve private endpoints for $AppConfigName : $($_.Exception.Message)"
            $appConfigDetails.PrivateEndpoints = @(@{ Error = $_.Exception.Message })
        }

        # Get replicas (for geo-replication)
        try {
            Write-Debug "Retrieving replicas for $AppConfigName"
            $replicasResponse = Invoke-ARMRequest -Uri "https://management.azure.com$AppConfigId/replicas?api-version=2023-03-01"
            if ($replicasResponse -and $replicasResponse.value) {
                Write-Debug "Found $($replicasResponse.value.Count) replicas for $AppConfigName"
                
                foreach ($replica in $replicasResponse.value) {
                    $appConfigDetails.Replicas += @{
                        Name = $replica.name
                        Location = $replica.location
                        Endpoint = $replica.properties.endpoint
                        ProvisioningState = $replica.properties.provisioningState
                    }
                }
            } else {
                $appConfigDetails.Replicas = @(@{ Note = "No replicas configured" })
            }
        } catch {
            Write-Debug "Could not retrieve replicas for $AppConfigName : $($_.Exception.Message)"
            $appConfigDetails.Replicas = @(@{ Error = $_.Exception.Message })
        }

        return $appConfigDetails
        
    } catch {
        Write-Warning "Failed to get detailed App Configuration information for $AppConfigName : $($_.Exception.Message)"
        return @{
            Name = $AppConfigName
            Id = $AppConfigId
            Error = "Failed to retrieve details: $($_.Exception.Message)"
        }
    }
}

function Get-ApplicationDetails {
    <#
    .SYNOPSIS
        Retrieves comprehensive details for a Microsoft Graph application.
    .PARAMETER ApplicationId
        The ID of the application to get details for
    .PARAMETER AccessTokenGraph
        The Graph API access token (optional)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApplicationId,
        
        [Parameter(Mandatory = $false)]
        [string]$AccessTokenGraph
    )

    try {
        Write-Debug "Getting comprehensive application details for: $ApplicationId"
        
        $appDetails = @{
            Id = $ApplicationId
            BasicInfo = @{}
            Authentication = @{}
            Permissions = @{}
            Credentials = @{}
            Owners = @()
            ServicePrincipal = @{}
            Error = $null
        }

        # Get detailed application information with expanded properties
        $selectFields = @(
            "id", "appId", "displayName", "description", "publisherDomain", "createdDateTime", "deletedDateTime",
            "identifierUris", "signInAudience", "tags", "tokenEncryptionKeyId", "defaultRedirectUri",
            "groupMembershipClaims", "optionalClaims", "publicClient", "spa", "web", "api", "keyCredentials",
            "passwordCredentials", "requiredResourceAccess", "parentalControlSettings", "verifiedPublisher",
            "certification", "samlMetadataUrl", "addIns", "appRoles", "oauth2RequirePostResponse",
            "isFallbackPublicClient", "requestSignatureVerification", "serviceManagementReference"
        ) -join ","
        
        $appUrl = "https://graph.microsoft.com/v1.0/applications/$ApplicationId" + "?`$select=$selectFields"
        
        if ($AccessTokenGraph) {
            $headers = @{
                'Authorization' = "Bearer $AccessTokenGraph"
                'Content-Type' = 'application/json'
            }
            $application = Invoke-RestMethod -Uri $appUrl -Headers $headers -Method GET
        } else {
            $application = Invoke-GraphRequest -Uri $appUrl
        }
        
        if ($application) {
            # Basic Information
            $appDetails.BasicInfo = @{
                Id = $application.id
                AppId = $application.appId
                DisplayName = $application.displayName
                Description = $application.description
                PublisherDomain = $application.publisherDomain
                CreatedDateTime = $application.createdDateTime
                DeletedDateTime = $application.deletedDateTime
                IdentifierUris = $application.identifierUris
                SignInAudience = $application.signInAudience
                Tags = $application.tags
                DefaultRedirectUri = $application.defaultRedirectUri
                GroupMembershipClaims = $application.groupMembershipClaims
                IsFallbackPublicClient = $application.isFallbackPublicClient
                TokenEncryptionKeyId = $application.tokenEncryptionKeyId
            }

            # Authentication Configuration
            $appDetails.Authentication = @{
                PublicClient = $application.publicClient
                Spa = $application.spa
                Web = $application.web
                ImplicitGrantSettings = $application.web.implicitGrantSettings
                RedirectUris = @{
                    PublicClient = $application.publicClient.redirectUris
                    Spa = $application.spa.redirectUris
                    Web = $application.web.redirectUris
                }
                LogoutUrl = $application.web.logoutUrl
                HomePageUrl = $application.web.homePageUrl
            }

            # API Configuration
            if ($application.api) {
                $appDetails.API = @{
                    AcceptMappedClaims = $application.api.acceptMappedClaims
                    KnownClientApplications = $application.api.knownClientApplications
                    RequestedAccessTokenVersion = $application.api.requestedAccessTokenVersion
                    Oauth2PermissionScopes = $application.api.oauth2PermissionScopes
                    PreAuthorizedApplications = $application.api.preAuthorizedApplications
                }
            }

            # Application Roles
            if ($application.appRoles) {
                $appDetails.AppRoles = $application.appRoles | ForEach-Object {
                    @{
                        Id = $_.id
                        DisplayName = $_.displayName
                        Description = $_.description
                        Value = $_.value
                        IsEnabled = $_.isEnabled
                        AllowedMemberTypes = $_.allowedMemberTypes
                        Origin = $_.origin
                    }
                }
            }

            # Required Resource Access (API Permissions)
            if ($application.requiredResourceAccess) {
                $appDetails.Permissions.RequiredResourceAccess = $application.requiredResourceAccess | ForEach-Object {
                    @{
                        ResourceAppId = $_.resourceAppId
                        ResourceAccess = $_.resourceAccess | ForEach-Object {
                            @{
                                Id = $_.id
                                Type = $_.type
                            }
                        }
                    }
                }
            }

            # Optional Claims
            if ($application.optionalClaims) {
                $appDetails.OptionalClaims = @{
                    IdToken = $application.optionalClaims.idToken
                    AccessToken = $application.optionalClaims.accessToken
                    Saml2Token = $application.optionalClaims.saml2Token
                }
            }

            # Credentials (Keys and Secrets metadata only - not actual values)
            $appDetails.Credentials = @{
                KeyCredentials = @()
                PasswordCredentials = @()
            }
            
            if ($application.keyCredentials) {
                $appDetails.Credentials.KeyCredentials = $application.keyCredentials | ForEach-Object {
                    @{
                        KeyId = $_.keyId
                        Type = $_.type
                        Usage = $_.usage
                        DisplayName = $_.displayName
                        StartDateTime = $_.startDateTime
                        EndDateTime = $_.endDateTime
                        CustomKeyIdentifier = if ($_.customKeyIdentifier) { 
                            try {
                                # Handle hex string conversion to Base64
                                if ($_.customKeyIdentifier -is [string] -and $_.customKeyIdentifier.Length % 2 -eq 0) {
                                    # Convert hex string to byte array
                                    $byteArray = [byte[]]::new($_.customKeyIdentifier.Length / 2)
                                    for ($i = 0; $i -lt $_.customKeyIdentifier.Length; $i += 2) {
                                        $byteArray[$i / 2] = [Convert]::ToByte($_.customKeyIdentifier.Substring($i, 2), 16)
                                    }
                                    [System.Convert]::ToBase64String($byteArray)
                                } elseif ($_.customKeyIdentifier -is [byte[]]) {
                                    # Already a byte array
                                    [System.Convert]::ToBase64String($_.customKeyIdentifier)
                                } else {
                                    # Fallback - return as string
                                    $_.customKeyIdentifier.ToString()
                                }
                            } catch {
                                # If conversion fails, return the original value as string
                                $_.customKeyIdentifier.ToString()
                            }
                        } else { $null }
                    }
                }
            }
            
            if ($application.passwordCredentials) {
                $appDetails.Credentials.PasswordCredentials = $application.passwordCredentials | ForEach-Object {
                    @{
                        KeyId = $_.keyId
                        DisplayName = $_.displayName
                        Hint = $_.hint
                        StartDateTime = $_.startDateTime
                        EndDateTime = $_.endDateTime
                        SecretText = "[PROTECTED]"  # Never expose actual secrets
                    }
                }
            }

            # Verified Publisher
            if ($application.verifiedPublisher) {
                $appDetails.VerifiedPublisher = @{
                    DisplayName = $application.verifiedPublisher.displayName
                    VerifiedPublisherId = $application.verifiedPublisher.verifiedPublisherId
                    AddedDateTime = $application.verifiedPublisher.addedDateTime
                }
            }

            # Certification
            if ($application.certification) {
                $appDetails.Certification = $application.certification
            }
        }

        # Get Application Owners
        try {
            $ownersUrl = "https://graph.microsoft.com/v1.0/applications/$ApplicationId/owners"
            
            if ($AccessTokenGraph) {
                $owners = Invoke-RestMethod -Uri $ownersUrl -Headers $headers -Method GET
            } else {
                $owners = Invoke-GraphRequest -Uri $ownersUrl
            }
            
            if ($owners -and $owners.value) {
                $appDetails.Owners = $owners.value | ForEach-Object {
                    @{
                        Id = $_.id
                        DisplayName = $_.displayName
                        UserPrincipalName = $_.userPrincipalName
                        UserType = $_."@odata.type"
                    }
                }
            }
        } catch {
            Write-Debug "Could not retrieve owners for application $ApplicationId : $($_.Exception.Message)"
            $appDetails.Owners = @(@{ Error = "Could not retrieve owners: $($_.Exception.Message)" })
        }

        # Get associated Service Principal (if exists)
        try {
            $spUrl = "https://graph.microsoft.com/v1.0/servicePrincipals" + "?`$filter=appId eq '$($application.appId)'"
            
            if ($AccessTokenGraph) {
                $servicePrincipal = Invoke-RestMethod -Uri $spUrl -Headers $headers -Method GET
            } else {
                $servicePrincipal = Invoke-GraphRequest -Uri $spUrl
            }
            
            if ($servicePrincipal -and $servicePrincipal.value -and $servicePrincipal.value.Count -gt 0) {
                $sp = $servicePrincipal.value[0]
                $appDetails.ServicePrincipal = @{
                    Id = $sp.id
                    DisplayName = $sp.displayName
                    ServicePrincipalType = $sp.servicePrincipalType
                    AccountEnabled = $sp.accountEnabled
                    AppDisplayName = $sp.appDisplayName
                    AppId = $sp.appId
                    CreatedDateTime = $sp.createdDateTime
                    ServicePrincipalNames = $sp.servicePrincipalNames
                    Tags = $sp.tags
                    TokenEncryptionKeyId = $sp.tokenEncryptionKeyId
                    PreferredSingleSignOnMode = $sp.preferredSingleSignOnMode
                    ReplyUrls = $sp.replyUrls
                    LogoutUrl = $sp.logoutUrl
                    Homepage = $sp.homepage
                    PublisherName = $sp.publisherName
                }
                
                # Get Service Principal owners
                try {
                    $spOwnersUrl = "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/owners"
                    
                    if ($AccessTokenGraph) {
                        $spOwners = Invoke-RestMethod -Uri $spOwnersUrl -Headers $headers -Method GET
                    } else {
                        $spOwners = Invoke-GraphRequest -Uri $spOwnersUrl
                    }
                    
                    if ($spOwners -and $spOwners.value) {
                        $appDetails.ServicePrincipal.Owners = $spOwners.value | ForEach-Object {
                            @{
                                Id = $_.id
                                DisplayName = $_.displayName
                                UserPrincipalName = $_.userPrincipalName
                                UserType = $_."@odata.type"
                            }
                        }
                    }
                } catch {
                    Write-Debug "Could not retrieve service principal owners: $($_.Exception.Message)"
                }
                
            } else {
                $appDetails.ServicePrincipal = @{ Note = "No associated service principal found" }
            }
        } catch {
            Write-Debug "Could not retrieve service principal for application $ApplicationId : $($_.Exception.Message)"
            $appDetails.ServicePrincipal = @{ Error = "Could not retrieve service principal: $($_.Exception.Message)" }
        }

        return $appDetails
        
    } catch {
        Write-Warning "Failed to get detailed application information for $ApplicationId : $($_.Exception.Message)"
        return @{
            Id = $ApplicationId
            Error = "Failed to retrieve details: $($_.Exception.Message)"
        }
    }
}

function Get-NetworkSecurityGroupDetails {
    <#
    .SYNOPSIS
        Retrieves detailed Network Security Group information including rules and associations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$NsgId,
        
        [Parameter(Mandatory = $true)]
        [string]$NsgName
    )
    
    try {
        Write-Debug "Getting detailed NSG information for: $NsgName"
        
        # Get NSG details
        $nsgInfo = Invoke-ARMRequest -Uri "https://management.azure.com$NsgId" + "?api-version=2022-07-01"
        
        if (-not $nsgInfo) {
            return @{
                Name = $NsgName
                Error = "Failed to retrieve NSG details"
            }
        }
        
        $nsgDetails = @{
            Name = $nsgInfo.name
            Location = $nsgInfo.location
            ResourceGroup = ($nsgInfo.id -split '/')[4]
            Id = $nsgInfo.id
            SecurityRules = @()
            DefaultSecurityRules = @()
            NetworkInterfaces = @()
            Subnets = @()
            Associations = @()
            FlowLogsEnabled = $false
            Error = $null
        }
        
        # Parse security rules
        if ($nsgInfo.properties.securityRules) {
            $nsgDetails.SecurityRules = $nsgInfo.properties.securityRules | ForEach-Object {
                @{
                    Name = $_.name
                    Priority = $_.properties.priority
                    Protocol = $_.properties.protocol
                    Access = $_.properties.access
                    Direction = $_.properties.direction
                    SourceAddressPrefix = $_.properties.sourceAddressPrefix
                    SourceAddressPrefixes = $_.properties.sourceAddressPrefixes
                    SourcePortRange = $_.properties.sourcePortRange
                    SourcePortRanges = $_.properties.sourcePortRanges
                    DestinationAddressPrefix = $_.properties.destinationAddressPrefix
                    DestinationAddressPrefixes = $_.properties.destinationAddressPrefixes
                    DestinationPortRange = $_.properties.destinationPortRange
                    DestinationPortRanges = $_.properties.destinationPortRanges
                    SourceApplicationSecurityGroups = $_.properties.sourceApplicationSecurityGroups
                    DestinationApplicationSecurityGroups = $_.properties.destinationApplicationSecurityGroups
                    Description = $_.properties.description
                }
            }
        }
        
        # Parse default security rules
        if ($nsgInfo.properties.defaultSecurityRules) {
            $nsgDetails.DefaultSecurityRules = $nsgInfo.properties.defaultSecurityRules | ForEach-Object {
                @{
                    Name = $_.name
                    Priority = $_.properties.priority
                    Protocol = $_.properties.protocol
                    Access = $_.properties.access
                    Direction = $_.properties.direction
                    SourceAddressPrefix = $_.properties.sourceAddressPrefix
                    DestinationAddressPrefix = $_.properties.destinationAddressPrefix
                    SourcePortRange = $_.properties.sourcePortRange
                    DestinationPortRange = $_.properties.destinationPortRange
                    Description = $_.properties.description
                }
            }
        }
        
        # Get associated network interfaces
        if ($nsgInfo.properties.networkInterfaces) {
            $nsgDetails.NetworkInterfaces = $nsgInfo.properties.networkInterfaces | ForEach-Object {
                @{
                    Id = $_.id
                    Name = ($_.id -split '/')[-1]
                }
            }
        }
        
        # Get associated subnets
        if ($nsgInfo.properties.subnets) {
            $nsgDetails.Subnets = $nsgInfo.properties.subnets | ForEach-Object {
                @{
                    Id = $_.id
                    Name = ($_.id -split '/')[-1]
                    VirtualNetwork = ($_.id -split '/')[-3]
                }
            }
        }
        
        # Analyze security posture
        $openToInternet = $nsgDetails.SecurityRules | Where-Object { 
            ($_.SourceAddressPrefix -eq "*" -or $_.SourceAddressPrefix -eq "0.0.0.0/0" -or $_.SourceAddressPrefix -eq "Internet") -and 
            $_.Access -eq "Allow" -and 
            $_.Direction -eq "Inbound"
        }
        
        $commonDangerousPorts = $nsgDetails.SecurityRules | Where-Object {
            $_.Access -eq "Allow" -and 
            $_.Direction -eq "Inbound" -and
            ($_.SourceAddressPrefix -eq "*" -or $_.SourceAddressPrefix -eq "0.0.0.0/0" -or $_.SourceAddressPrefix -eq "Internet") -and
            ($_.DestinationPortRange -in @("22", "3389", "1433", "3306", "5432", "6379") -or
             ($_.DestinationPortRanges -and ($_.DestinationPortRanges | Where-Object { $_ -in @("22", "3389", "1433", "3306", "5432", "6379") })))
        }
        
        $nsgDetails.SecurityAnalysis = @{
            TotalCustomRules = $nsgDetails.SecurityRules.Count
            InboundAllowRules = ($nsgDetails.SecurityRules | Where-Object { $_.Direction -eq "Inbound" -and $_.Access -eq "Allow" }).Count
            OutboundAllowRules = ($nsgDetails.SecurityRules | Where-Object { $_.Direction -eq "Outbound" -and $_.Access -eq "Allow" }).Count
            RulesOpenToInternet = $openToInternet.Count
            DangerousPortsExposed = $commonDangerousPorts.Count
            HasWildcardSourceRules = ($nsgDetails.SecurityRules | Where-Object { $_.SourceAddressPrefix -eq "*" }).Count -gt 0
            HasAnyAnyRules = ($nsgDetails.SecurityRules | Where-Object { 
                $_.SourceAddressPrefix -eq "*" -and 
                $_.DestinationAddressPrefix -eq "*" -and 
                $_.Access -eq "Allow" 
            }).Count -gt 0
        }
        
        # Try to get flow logs information
        try {
            $flowLogsUri = "https://management.azure.com/subscriptions/$((($nsgInfo.id -split '/')[2]))/providers/Microsoft.Network/networkWatchers"
            $networkWatchers = Invoke-ARMRequest -Uri "$flowLogsUri" + "?api-version=2022-07-01" -SuppressWarnings $true
            
            if ($networkWatchers -and $networkWatchers.value) {
                foreach ($watcher in $networkWatchers.value) {
                    $flowLogsUri = "https://management.azure.com$($watcher.id)/flowLogs" + "?api-version=2022-07-01"
                    $flowLogs = Invoke-ARMRequest -Uri $flowLogsUri -SuppressWarnings $true
                    
                    if ($flowLogs -and $flowLogs.value) {
                        $nsgFlowLog = $flowLogs.value | Where-Object { 
                            $_.properties.targetResourceId -eq $nsgInfo.id 
                        }
                        if ($nsgFlowLog) {
                            $nsgDetails.FlowLogsEnabled = $true
                            $nsgDetails.FlowLogDetails = @{
                                Name = $nsgFlowLog.name
                                Enabled = $nsgFlowLog.properties.enabled
                                StorageAccount = $nsgFlowLog.properties.storageId
                                RetentionDays = $nsgFlowLog.properties.retentionPolicy.days
                                Version = $nsgFlowLog.properties.format.version
                            }
                        }
                    }
                }
            }
        } catch {
            Write-Debug "Could not retrieve flow log information for NSG $NsgName : $($_.Exception.Message)"
        }
        
        return $nsgDetails
        
    } catch {
        Write-Warning "Failed to get NSG details for $NsgName : $($_.Exception.Message)"
        return @{
            Name = $NsgName
            Error = "Failed to retrieve NSG details: $($_.Exception.Message)"
        }
    }
}

function Get-VirtualMachineDetails {
    <#
    .SYNOPSIS
        Retrieves comprehensive Virtual Machine information including extensions, disks, network interfaces, and diagnostics.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmId,
        
        [Parameter(Mandatory = $true)]
        [string]$VmName
    )
    
    try {
        Write-Debug "Getting detailed VM information for: $VmName"
        
        # Get VM details
        $vmInfo = Invoke-ARMRequest -Uri "https://management.azure.com$VmId" + "?api-version=2022-08-01"
        
        if (-not $vmInfo) {
            return @{
                Name = $VmName
                Error = "Failed to retrieve VM details"
            }
        }
        
        $vmDetails = @{
            Name = $vmInfo.name
            Location = $vmInfo.location
            ResourceGroup = ($vmInfo.id -split '/')[4]
            Id = $vmInfo.id
            VmSize = $vmInfo.properties.hardwareProfile.vmSize
            ProvisioningState = $vmInfo.properties.provisioningState
            OsType = $vmInfo.properties.storageProfile.osDisk.osType
            Publisher = $vmInfo.properties.storageProfile.imageReference.publisher
            Offer = $vmInfo.properties.storageProfile.imageReference.offer
            Sku = $vmInfo.properties.storageProfile.imageReference.sku
            Version = $vmInfo.properties.storageProfile.imageReference.version
            ComputerName = $vmInfo.properties.osProfile.computerName
            AdminUsername = $vmInfo.properties.osProfile.adminUsername
            DisablePasswordAuthentication = $vmInfo.properties.osProfile.linuxConfiguration.disablePasswordAuthentication
            Extensions = @()
            DataDisks = @()
            NetworkInterfaces = @()
            PowerState = "Unknown"
            BootDiagnostics = @{}
            SecurityProfile = @{}
            Error = $null
        }
        
        # Get OS Disk information
        if ($vmInfo.properties.storageProfile.osDisk) {
            $osDisk = $vmInfo.properties.storageProfile.osDisk
            $vmDetails.OsDisk = @{
                Name = $osDisk.name
                Size = $osDisk.diskSizeGB
                CreateOption = $osDisk.createOption
                Caching = $osDisk.caching
                StorageAccountType = $osDisk.managedDisk.storageAccountType
                DiskId = $osDisk.managedDisk.id
                EncryptionEnabled = if ($osDisk.encryptionSettings) { $true } else { $false }
            }
        }
        
        # Get Data Disks information
        if ($vmInfo.properties.storageProfile.dataDisks) {
            $vmDetails.DataDisks = $vmInfo.properties.storageProfile.dataDisks | ForEach-Object {
                @{
                    Name = $_.name
                    Size = $_.diskSizeGB
                    Lun = $_.lun
                    CreateOption = $_.createOption
                    Caching = $_.caching
                    StorageAccountType = $_.managedDisk.storageAccountType
                    DiskId = $_.managedDisk.id
                }
            }
        }
        
        # Get Network Interfaces
        if ($vmInfo.properties.networkProfile.networkInterfaces) {
            foreach ($nic in $vmInfo.properties.networkProfile.networkInterfaces) {
                try {
                    $nicInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($nic.id)" + "?api-version=2022-07-01" -SuppressWarnings $true
                    if ($nicInfo) {
                        $nicDetail = @{
                            Name = $nicInfo.name
                            Id = $nicInfo.id
                            Primary = $nic.properties.primary
                            PrivateIPAddress = $nicInfo.properties.ipConfigurations[0].properties.privateIPAddress
                            PrivateIPAllocationMethod = $nicInfo.properties.ipConfigurations[0].properties.privateIPAllocationMethod
                            Subnet = if ($nicInfo.properties.ipConfigurations[0].properties.subnet) { 
                                ($nicInfo.properties.ipConfigurations[0].properties.subnet.id -split '/')[-1] 
                            } else { "None" }
                            VirtualNetwork = if ($nicInfo.properties.ipConfigurations[0].properties.subnet) { 
                                ($nicInfo.properties.ipConfigurations[0].properties.subnet.id -split '/')[-3] 
                            } else { "None" }
                            NetworkSecurityGroup = if ($nicInfo.properties.networkSecurityGroup) { 
                                ($nicInfo.properties.networkSecurityGroup.id -split '/')[-1] 
                            } else { "None" }
                            PublicIPAddress = "None"
                            EnableIPForwarding = $nicInfo.properties.enableIPForwarding
                            EnableAcceleratedNetworking = $nicInfo.properties.enableAcceleratedNetworking
                        }
                        
                        # Get Public IP if attached
                        if ($nicInfo.properties.ipConfigurations[0].properties.publicIPAddress) {
                            try {
                                $pipInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($nicInfo.properties.ipConfigurations[0].properties.publicIPAddress.id)" + "?api-version=2022-05-01" -SuppressWarnings $true
                                if ($pipInfo) {
                                    $nicDetail.PublicIPAddress = $pipInfo.properties.ipAddress
                                    $nicDetail.PublicIPAllocationMethod = $pipInfo.properties.publicIPAllocationMethod
                                }
                            } catch {
                                Write-Debug "Could not retrieve public IP for NIC: $($_.Exception.Message)"
                            }
                        }
                        
                        $vmDetails.NetworkInterfaces += $nicDetail
                    }
                } catch {
                    Write-Debug "Could not retrieve NIC details for VM $VmName : $($_.Exception.Message)"
                }
            }
        }
        
        # Get VM Extensions
        try {
            $extensionsInfo = Invoke-ARMRequest -Uri "https://management.azure.com$VmId/extensions" + "?api-version=2022-08-01" -SuppressWarnings $true
            if ($extensionsInfo -and $extensionsInfo.value) {
                $vmDetails.Extensions = $extensionsInfo.value | ForEach-Object {
                    @{
                        Name = $_.name
                        Publisher = $_.properties.publisher
                        Type = $_.properties.type
                        TypeHandlerVersion = $_.properties.typeHandlerVersion
                        ProvisioningState = $_.properties.provisioningState
                        AutoUpgradeMinorVersion = $_.properties.autoUpgradeMinorVersion
                        Settings = if ($_.properties.settings) { "Present" } else { "None" }
                        ProtectedSettings = if ($_.properties.protectedSettings) { "Present" } else { "None" }
                    }
                }
            }
        } catch {
            Write-Debug "Could not retrieve extensions for VM $VmName : $($_.Exception.Message)"
        }
        
        # Get VM Power State
        try {
            $instanceView = Invoke-ARMRequest -Uri "https://management.azure.com$VmId/instanceView" + "?api-version=2022-08-01" -SuppressWarnings $true
            if ($instanceView) {
                $powerState = $instanceView.statuses | Where-Object { $_.code -like "PowerState/*" }
                if ($powerState) {
                    $vmDetails.PowerState = $powerState.displayStatus
                }
                
                # Get boot diagnostics status
                if ($instanceView.bootDiagnostics) {
                    $vmDetails.BootDiagnostics = @{
                        Enabled = if ($vmInfo.properties.diagnosticsProfile.bootDiagnostics.enabled) { $true } else { $false }
                        StorageUri = $vmInfo.properties.diagnosticsProfile.bootDiagnostics.storageUri
                        ConsoleScreenshotUri = $instanceView.bootDiagnostics.consoleScreenshotBlobUri
                        SerialConsoleLogUri = $instanceView.bootDiagnostics.serialConsoleLogBlobUri
                    }
                }
                
                # Get VM Agent status
                if ($instanceView.vmAgent) {
                    $vmDetails.VmAgent = @{
                        VmAgentVersion = $instanceView.vmAgent.vmAgentVersion
                        Statuses = $instanceView.vmAgent.statuses | ForEach-Object {
                            @{
                                Code = $_.code
                                DisplayStatus = $_.displayStatus
                                Message = $_.message
                                Level = $_.level
                            }
                        }
                    }
                }
            }
        } catch {
            Write-Debug "Could not retrieve instance view for VM $VmName : $($_.Exception.Message)"
        }
        
        # Get Security Profile information
        if ($vmInfo.properties.securityProfile) {
            $secProfile = $vmInfo.properties.securityProfile
            $vmDetails.SecurityProfile = @{
                SecurityType = $secProfile.securityType
                UefiSettings = if ($secProfile.uefiSettings) {
                    @{
                        SecureBootEnabled = $secProfile.uefiSettings.secureBootEnabled
                        VTpmEnabled = $secProfile.uefiSettings.vTpmEnabled
                    }
                } else { @{} }
                EncryptionAtHost = $secProfile.encryptionAtHost
            }
        }
        
        # Analyze VM security posture
        $vmDetails.SecurityAnalysis = @{
            HasPublicIP = ($vmDetails.NetworkInterfaces | Where-Object { $_.PublicIPAddress -ne "None" }).Count -gt 0
            HasNSGProtection = ($vmDetails.NetworkInterfaces | Where-Object { $_.NetworkSecurityGroup -ne "None" }).Count -gt 0
            BootDiagnosticsEnabled = $vmDetails.BootDiagnostics.Enabled
            ExtensionCount = $vmDetails.Extensions.Count
            DataDiskCount = $vmDetails.DataDisks.Count
            AcceleratedNetworkingEnabled = ($vmDetails.NetworkInterfaces | Where-Object { $_.EnableAcceleratedNetworking }).Count -gt 0
            IPForwardingEnabled = ($vmDetails.NetworkInterfaces | Where-Object { $_.EnableIPForwarding }).Count -gt 0
        }
        
        return $vmDetails
        
    } catch {
        Write-Warning "Failed to get VM details for $VmName : $($_.Exception.Message)"
        return @{
            Name = $VmName
            Error = "Failed to retrieve VM details: $($_.Exception.Message)"
        }
    }
}

function Get-AzureADDetails {
    <#
    .SYNOPSIS
        Retrieves comprehensive Azure Active Directory information including conditional access, service principals, and directory settings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$AccessTokenGraph
    )
    
    try {
        Write-Debug "Getting comprehensive Azure AD details"
        
        $aadDetails = @{
            ConditionalAccessPolicies = @()
            ServicePrincipals = @()
            ManagedIdentities = @()
            EnterpriseApplications = @()
            DirectorySettings = @{}
            NamedLocations = @()
            AuthenticationMethods = @()
            SecurityDefaults = @{}
            Error = $null
        }
        
        $headers = if ($AccessTokenGraph) {
            @{
                'Authorization' = "Bearer $AccessTokenGraph"
                'Content-Type' = 'application/json'
            }
        } else {
            @{}
        }
        
        # Get Conditional Access Policies
        try {
            $caUrl = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
            
            if ($AccessTokenGraph) {
                $caPolicies = Invoke-RestMethod -Uri $caUrl -Headers $headers -Method GET
            } else {
                $caPolicies = Invoke-GraphRequest -Uri $caUrl
            }
            
            if ($caPolicies -and $caPolicies.value) {
                $aadDetails.ConditionalAccessPolicies = $caPolicies.value | ForEach-Object {
                    @{
                        Id = $_.id
                        DisplayName = $_.displayName
                        State = $_.state
                        CreatedDateTime = $_.createdDateTime
                        ModifiedDateTime = $_.modifiedDateTime
                        Conditions = @{
                            Applications = @{
                                IncludeApplications = $_.conditions.applications.includeApplications -join ", "
                                ExcludeApplications = $_.conditions.applications.excludeApplications -join ", "
                            }
                            Users = @{
                                IncludeUsers = $_.conditions.users.includeUsers -join ", "
                                ExcludeUsers = $_.conditions.users.excludeUsers -join ", "
                                IncludeGroups = $_.conditions.users.includeGroups -join ", "
                                ExcludeGroups = $_.conditions.users.excludeGroups -join ", "
                            }
                            Platforms = @{
                                IncludePlatforms = $_.conditions.platforms.includePlatforms -join ", "
                                ExcludePlatforms = $_.conditions.platforms.excludePlatforms -join ", "
                            }
                            Locations = @{
                                IncludeLocations = $_.conditions.locations.includeLocations -join ", "
                                ExcludeLocations = $_.conditions.locations.excludeLocations -join ", "
                            }
                            ClientAppTypes = $_.conditions.clientAppTypes -join ", "
                            SignInRiskLevels = $_.conditions.signInRiskLevels -join ", "
                            UserRiskLevels = $_.conditions.userRiskLevels -join ", "
                        }
                        GrantControls = @{
                            Operator = $_.grantControls.operator
                            BuiltInControls = $_.grantControls.builtInControls -join ", "
                            CustomAuthenticationFactors = $_.grantControls.customAuthenticationFactors -join ", "
                        }
                        SessionControls = if ($_.sessionControls) {
                            @{
                                ApplicationEnforcedRestrictions = $_.sessionControls.applicationEnforcedRestrictions.isEnabled
                                CloudAppSecurity = $_.sessionControls.cloudAppSecurity.isEnabled
                                PersistentBrowser = $_.sessionControls.persistentBrowser.isEnabled
                                SignInFrequency = $_.sessionControls.signInFrequency.isEnabled
                            }
                        } else { @{} }
                    }
                }
            }
        } catch {
            Write-Debug "Could not retrieve conditional access policies: $($_.Exception.Message)"
        }
        
        # Get Service Principals
        try {
            $spUrl = "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,appId,displayName,servicePrincipalType,accountEnabled,createdDateTime,tags,publisherName&`$top=999"
            
            if ($AccessTokenGraph) {
                $servicePrincipals = Invoke-RestMethod -Uri $spUrl -Headers $headers -Method GET
            } else {
                $servicePrincipals = Invoke-GraphRequest -Uri $spUrl
            }
            
            if ($servicePrincipals -and $servicePrincipals.value) {
                $aadDetails.ServicePrincipals = $servicePrincipals.value | ForEach-Object {
                    @{
                        Id = $_.id
                        AppId = $_.appId
                        DisplayName = $_.displayName
                        ServicePrincipalType = $_.servicePrincipalType
                        AccountEnabled = $_.accountEnabled
                        CreatedDateTime = $_.createdDateTime
                        Tags = $_.tags -join ", "
                        PublisherName = $_.publisherName
                        IsManagedIdentity = ($_.tags -contains "ManagedIdentityType")
                    }
                }
                
                # Separate managed identities
                $aadDetails.ManagedIdentities = $aadDetails.ServicePrincipals | Where-Object { $_.IsManagedIdentity }
                $aadDetails.EnterpriseApplications = $aadDetails.ServicePrincipals | Where-Object { -not $_.IsManagedIdentity -and $_.ServicePrincipalType -eq "Application" }
            }
        } catch {
            Write-Debug "Could not retrieve service principals: $($_.Exception.Message)"
        }
        
        # Get Named Locations
        try {
            $nlUrl = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
            
            if ($AccessTokenGraph) {
                $namedLocations = Invoke-RestMethod -Uri $nlUrl -Headers $headers -Method GET
            } else {
                $namedLocations = Invoke-GraphRequest -Uri $nlUrl
            }
            
            if ($namedLocations -and $namedLocations.value) {
                $aadDetails.NamedLocations = $namedLocations.value | ForEach-Object {
                    @{
                        Id = $_.id
                        DisplayName = $_.displayName
                        CreatedDateTime = $_.createdDateTime
                        ModifiedDateTime = $_.modifiedDateTime
                        IsTrusted = $_.isTrusted
                        Type = $_.'@odata.type'
                        CountriesAndRegions = if ($_.countriesAndRegions) { $_.countriesAndRegions -join ", " } else { "N/A" }
                        IpRanges = if ($_.ipRanges) { 
                            ($_.ipRanges | ForEach-Object { $_.cidrAddress }) -join ", " 
                        } else { "N/A" }
                    }
                }
            }
        } catch {
            Write-Debug "Could not retrieve named locations: $($_.Exception.Message)"
        }
        
        # Get Directory Settings
        try {
            $dsUrl = "https://graph.microsoft.com/v1.0/directorySettingTemplates"
            
            if ($AccessTokenGraph) {
                $directorySettings = Invoke-RestMethod -Uri $dsUrl -Headers $headers -Method GET
            } else {
                $directorySettings = Invoke-GraphRequest -Uri $dsUrl
            }
            
            if ($directorySettings -and $directorySettings.value) {
                $aadDetails.DirectorySettings = @{
                    AvailableTemplates = $directorySettings.value | ForEach-Object {
                        @{
                            Id = $_.id
                            DisplayName = $_.displayName
                            Description = $_.description
                        }
                    }
                }
            }
        } catch {
            Write-Debug "Could not retrieve directory settings: $($_.Exception.Message)"
        }
        
        # Get Authentication Methods Policy
        try {
            $amUrl = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
            
            if ($AccessTokenGraph) {
                $authMethods = Invoke-RestMethod -Uri $amUrl -Headers $headers -Method GET
            } else {
                $authMethods = Invoke-GraphRequest -Uri $amUrl
            }
            
            if ($authMethods) {
                $aadDetails.AuthenticationMethods = @{
                    PolicyVersion = $authMethods.policyVersion
                    ReconfirmationInDays = $authMethods.reconfirmationInDays
                    RegistrationEnforcement = @{
                        AuthenticationMethodsRegistrationCampaign = $authMethods.registrationEnforcement.authenticationMethodsRegistrationCampaign.state
                    }
                    SystemCredentialPreferences = @{
                        State = $authMethods.systemCredentialPreferences.state
                        ExcludeTargets = if ($authMethods.systemCredentialPreferences.excludeTargets) {
                            $authMethods.systemCredentialPreferences.excludeTargets | ForEach-Object { $_.id }
                        } else { @() }
                        IncludeTargets = if ($authMethods.systemCredentialPreferences.includeTargets) {
                            $authMethods.systemCredentialPreferences.includeTargets | ForEach-Object { $_.id }
                        } else { @() }
                    }
                }
            }
        } catch {
            Write-Debug "Could not retrieve authentication methods policy: $($_.Exception.Message)"
        }
        
        # Analyze AAD Security Posture
        $aadDetails.SecurityAnalysis = @{
            TotalConditionalAccessPolicies = $aadDetails.ConditionalAccessPolicies.Count
            EnabledConditionalAccessPolicies = ($aadDetails.ConditionalAccessPolicies | Where-Object { $_.State -eq "enabled" }).Count
            TotalServicePrincipals = $aadDetails.ServicePrincipals.Count
            ManagedIdentitiesCount = $aadDetails.ManagedIdentities.Count
            EnterpriseApplicationsCount = $aadDetails.EnterpriseApplications.Count
            NamedLocationsCount = $aadDetails.NamedLocations.Count
            TrustedNamedLocationsCount = ($aadDetails.NamedLocations | Where-Object { $_.IsTrusted }).Count
            HasBlockLegacyAuthPolicies = ($aadDetails.ConditionalAccessPolicies | Where-Object { 
                $_.Conditions.ClientAppTypes -like "*legacyAuthentication*" -and $_.State -eq "enabled" 
            }).Count -gt 0
            RequiresMFAPolicies = ($aadDetails.ConditionalAccessPolicies | Where-Object { 
                $_.GrantControls.BuiltInControls -like "*mfa*" -and $_.State -eq "enabled" 
            }).Count -gt 0
        }
        
        return $aadDetails
        
    } catch {
        Write-Warning "Failed to get Azure AD details: $($_.Exception.Message)"
        return @{
            Error = "Failed to retrieve Azure AD details: $($_.Exception.Message)"
        }
    }
}

function Get-TenantInformation {
    <#
    .SYNOPSIS
        Retrieves comprehensive tenant organization information and configuration.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Retrieving tenant organization details..."
        
        # Get organization details
        $orgUri = "https://graph.microsoft.com/v1.0/organization"
        $orgResponse = Invoke-RestMethod -Uri $orgUri -Headers $Script:GraphHeaders -Method Get -ErrorAction SilentlyContinue
        
        if ($orgResponse -and $orgResponse.value) {
            $org = $orgResponse.value[0]
            
            return @{
                Id = $org.id
                DisplayName = $org.displayName
                VerifiedDomains = $org.verifiedDomains
                TechnicalNotificationMails = $org.technicalNotificationMails
                CountryLetterCode = $org.countryLetterCode
                SecurityComplianceNotificationMails = $org.securityComplianceNotificationMails
                MarketingNotificationEmails = $org.marketingNotificationEmails
                OnPremisesSyncEnabled = $org.onPremisesSyncEnabled
                CreatedDateTime = $org.createdDateTime
                AssignedPlans = $org.assignedPlans
                BusinessPhones = $org.businessPhones
                City = $org.city
                Country = $org.country
                PostalCode = $org.postalCode
                State = $org.state
                Street = $org.street
                Error = $null
            }
        } else {
            return @{ Error = "No organization data found or insufficient permissions" }
        }
    } catch {
        return @{ ErrorMessage = "Failed to retrieve tenant information: $($_.Exception.Message)" }
    }
}

function Get-DirectoryRoles {
    <#
    .SYNOPSIS
        Retrieves directory roles and role assignments.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Retrieving directory roles and assignments..."
        
        # Get directory roles
        $rolesUri = "https://graph.microsoft.com/v1.0/directoryRoles"
        $rolesResponse = Invoke-RestMethod -Uri $rolesUri -Headers $Script:GraphHeaders -Method Get -ErrorAction SilentlyContinue
        
        $roleAssignments = @()
        $roles = @()
        
        if ($rolesResponse -and $rolesResponse.value) {
            $roles = $rolesResponse.value
            
            # Get role assignments for each role
            foreach ($role in $roles) {
                try {
                    $membersUri = "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members"
                    $membersResponse = Invoke-RestMethod -Uri $membersUri -Headers $Script:GraphHeaders -Method Get -ErrorAction SilentlyContinue
                    
                    if ($membersResponse -and $membersResponse.value) {
                        foreach ($member in $membersResponse.value) {
                            $roleAssignments += @{
                                RoleId = $role.id
                                RoleName = $role.displayName
                                RoleDescription = $role.description
                                PrincipalId = $member.id
                                PrincipalName = $member.displayName
                                PrincipalType = $member.'@odata.type'
                                UserPrincipalName = $member.userPrincipalName
                            }
                        }
                    }
                } catch {
                    Write-Verbose "Could not retrieve members for role: $($role.displayName)"
                }
            }
        }
        
        return @{
            Roles = $roles
            RoleAssignments = $roleAssignments
            Error = $null
        }
    } catch {
        return @{ ErrorMessage = "Failed to retrieve directory roles: $($_.Exception.Message)" }
    }
}

function Get-TenantUsers {
    <#
    .SYNOPSIS
        Retrieves all users in the tenant with analysis.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Retrieving all tenant users..."
        
        $users = @()
        $usersUri = "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity,assignedLicenses&`$top=999"
        
        do {
            try {
                $response = Invoke-RestMethod -Uri $usersUri -Headers $Script:GraphHeaders -Method Get -ErrorAction Stop
                if ($response -and $response.value) {
                    $users += $response.value
                    $usersUri = $response.'@odata.nextLink'
                } else {
                    $usersUri = $null
                }
            } catch {
                if ($_.Exception.Message -match "Forbidden|Unauthorized|Insufficient|Permission" -or
                    ($_.Exception -is [System.Net.WebException] -and $_.Exception.Response.StatusCode -in @(401, 403))) {
                    Write-Warning "Failed to retrieve tenant users due to insufficient permissions"
                    Show-GraphPermissionGuidance -MissingPermission "User.Read.All or Directory.Read.All" -ErrorContext "Tenant users enumeration (/users endpoint)"
                    throw "Insufficient permissions for user enumeration: $($_.Exception.Message)"
                } else {
                    Write-Warning "Failed to retrieve users: $($_.Exception.Message)"
                    throw
                }
            }
        } while ($usersUri)
        
        # Analyze user data
        $analysis = @{
            TotalUsers = $users.Count
            EnabledUsers = ($users | Where-Object { $_.accountEnabled -eq $true }).Count
            DisabledUsers = ($users | Where-Object { $_.accountEnabled -eq $false }).Count
            GuestUsers = ($users | Where-Object { $_.userType -eq "Guest" }).Count
            MemberUsers = ($users | Where-Object { $_.userType -eq "Member" }).Count
            LicensedUsers = ($users | Where-Object { $_.assignedLicenses -and $_.assignedLicenses.Count -gt 0 }).Count
            EnabledUsersCount = ($users | Where-Object { $_.accountEnabled -eq $true }).Count
            GuestUsersCount = ($users | Where-Object { $_.userType -eq "Guest" }).Count
        }
        
        return @{
            Users = $users
            Analysis = $analysis
            Error = $null
        }
    } catch {
        return @{ ErrorMessage = "Failed to retrieve tenant users: $($_.Exception.Message)" }
    }
}

function Get-TenantGroups {
    <#
    .SYNOPSIS
        Retrieves all groups in the tenant with analysis.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Retrieving all tenant groups..."
        
        $groups = @()
        $groupsUri = "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName,description,groupTypes,securityEnabled,mailEnabled,createdDateTime&`$top=999"
        
        do {
            try {
                $response = Invoke-RestMethod -Uri $groupsUri -Headers $Script:GraphHeaders -Method Get -ErrorAction Stop
                if ($response -and $response.value) {
                    $groups += $response.value
                    $groupsUri = $response.'@odata.nextLink'
                } else {
                    $groupsUri = $null
                }
            } catch {
                if ($_.Exception.Message -match "Forbidden|Unauthorized|Insufficient|Permission" -or
                    ($_.Exception -is [System.Net.WebException] -and $_.Exception.Response.StatusCode -in @(401, 403))) {
                    Write-Warning "Failed to retrieve tenant groups due to insufficient permissions"
                    Show-GraphPermissionGuidance -MissingPermission "Group.Read.All or Directory.Read.All" -ErrorContext "Tenant groups enumeration (/groups endpoint)"
                    throw "Insufficient permissions for group enumeration: $($_.Exception.Message)"
                } else {
                    Write-Warning "Failed to retrieve groups: $($_.Exception.Message)"
                    throw
                }
            }
        } while ($groupsUri)
        
        # Analyze group data
        $analysis = @{
            TotalGroups = $groups.Count
            SecurityGroups = ($groups | Where-Object { $_.securityEnabled -eq $true }).Count
            DistributionGroups = ($groups | Where-Object { $_.mailEnabled -eq $true -and $_.securityEnabled -eq $false }).Count
            Office365Groups = ($groups | Where-Object { $_.groupTypes -contains "Unified" }).Count
            SecurityGroupsCount = ($groups | Where-Object { $_.securityEnabled -eq $true }).Count
            DistributionGroupsCount = ($groups | Where-Object { $_.mailEnabled -eq $true -and $_.securityEnabled -eq $false }).Count
        }
        
        return @{
            Groups = $groups
            Analysis = $analysis
            Error = $null
        }
    } catch {
        return @{ ErrorMessage = "Failed to retrieve tenant groups: $($_.Exception.Message)" }
    }
}

function Get-TenantApplications {
    <#
    .SYNOPSIS
        Retrieves all applications and service principals from the tenant via Microsoft Graph API.
    #>
    [CmdletBinding()]
    param(
        [array]$OwnedApplications = @()
    )
    
    try {
        Write-Verbose "Retrieving tenant applications and service principals..."
        
        $applications = @()
        $servicePrincipals = @()
        
        # Get applications
        try {
            if ($AccessTokenGraph) {
                $headers = @{
                    'Authorization' = "Bearer $AccessTokenGraph"
                    'Content-Type' = 'application/json'
                }
                
                # Get applications with key properties
                $appUri = "https://graph.microsoft.com/v1.0/applications?`$select=id,appId,displayName,createdDateTime,publisherDomain,signInAudience,web,spa,requiredResourceAccess,passwordCredentials,keyCredentials&`$top=999"
                try {
                    $response = Invoke-RestMethod -Uri $appUri -Headers $headers -Method GET -ErrorAction Stop
                } catch {
                    if ($_.Exception.Message -match "Forbidden|Unauthorized|Insufficient|Permission" -or
                        ($_.Exception -is [System.Net.WebException] -and $_.Exception.Response.StatusCode -in @(401, 403))) {
                        Write-Warning "Failed to retrieve applications due to insufficient permissions"
                        Show-GraphPermissionGuidance -MissingPermission "Application.Read.All or Directory.Read.All" -ErrorContext "Applications enumeration (/applications endpoint)"
                        throw "Insufficient permissions for applications enumeration: $($_.Exception.Message)"
                    } else {
                        throw
                    }
                }
                
                if ($response -and $response.value) {
                    foreach ($app in $response.value) {
                        $isOwned = Test-ApplicationOwnership -ApplicationId $app.appId -OwnedApplications $OwnedApplications
                        $applications += [PSCustomObject]@{
                            Id = $app.id
                            AppId = $app.appId
                            DisplayName = $app.displayName
                            CreatedDateTime = $app.createdDateTime
                            PublisherDomain = $app.publisherDomain
                            SignInAudience = $app.signInAudience
                            WebRedirectUris = if ($app.web -and $app.web.redirectUris) { $app.web.redirectUris -join "; " } else { "" }
                            SpaRedirectUris = if ($app.spa -and $app.spa.redirectUris) { $app.spa.redirectUris -join "; " } else { "" }
                            RequiredResourceAccess = if ($app.requiredResourceAccess) { $app.requiredResourceAccess.Count } else { 0 }
                            PasswordCredentials = if ($app.passwordCredentials) { $app.passwordCredentials.Count } else { 0 }
                            KeyCredentials = if ($app.keyCredentials) { $app.keyCredentials.Count } else { 0 }
                            HasSecrets = (($app.passwordCredentials -and $app.passwordCredentials.Count -gt 0) -or ($app.keyCredentials -and $app.keyCredentials.Count -gt 0))
                            IsOwned = $isOwned
                            OwnershipStatus = if ($isOwned) { "OWNED - PRIVILEGE ESCALATION OPPORTUNITY!" } else { "Not Owned" }
                        }
                    }
                    Write-Verbose "Retrieved $($applications.Count) applications"
                }
            } else {
                # Try using Graph PowerShell cmdlets
                $mgApps = Get-MgApplication -All -Property "Id,AppId,DisplayName,CreatedDateTime,PublisherDomain,SignInAudience" -ErrorAction Stop
                foreach ($app in $mgApps) {
                    $isOwned = Test-ApplicationOwnership -ApplicationId $app.AppId -OwnedApplications $OwnedApplications
                    $applications += [PSCustomObject]@{
                        Id = $app.Id
                        AppId = $app.AppId
                        DisplayName = $app.DisplayName
                        CreatedDateTime = $app.CreatedDateTime
                        PublisherDomain = $app.PublisherDomain
                        SignInAudience = $app.SignInAudience
                        WebRedirectUris = ""
                        SpaRedirectUris = ""
                        RequiredResourceAccess = 0
                        PasswordCredentials = 0
                        KeyCredentials = 0
                        HasSecrets = $false
                        IsOwned = $isOwned
                        OwnershipStatus = if ($isOwned) { "OWNED - PRIVILEGE ESCALATION OPPORTUNITY!" } else { "Not Owned" }
                    }
                }
            }
        } catch {
            Write-Verbose "Failed to retrieve applications: $($_.Exception.Message)"
        }
        
        # Get service principals
        try {
            if ($AccessTokenGraph) {
                $spUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,appId,displayName,servicePrincipalType,createdDateTime,publisherName,appDisplayName,passwordCredentials,keyCredentials&`$top=999"
                $response = Invoke-RestMethod -Uri $spUri -Headers $headers -Method GET
                
                if ($response -and $response.value) {
                    foreach ($sp in $response.value) {
                        $servicePrincipals += [PSCustomObject]@{
                            Id = $sp.id
                            AppId = $sp.appId
                            DisplayName = $sp.displayName
                            ServicePrincipalType = $sp.servicePrincipalType
                            CreatedDateTime = $sp.createdDateTime
                            PublisherName = $sp.publisherName
                            AppDisplayName = $sp.appDisplayName
                            PasswordCredentials = if ($sp.passwordCredentials) { $sp.passwordCredentials.Count } else { 0 }
                            KeyCredentials = if ($sp.keyCredentials) { $sp.keyCredentials.Count } else { 0 }
                            HasSecrets = (($sp.passwordCredentials -and $sp.passwordCredentials.Count -gt 0) -or ($sp.keyCredentials -and $sp.keyCredentials.Count -gt 0))
                        }
                    }
                    Write-Verbose "Retrieved $($servicePrincipals.Count) service principals"
                }
            } else {
                # Try using Graph PowerShell cmdlets
                $mgSPs = Get-MgServicePrincipal -All -Property "Id,AppId,DisplayName,ServicePrincipalType,CreatedDateTime" -ErrorAction Stop
                foreach ($sp in $mgSPs) {
                    $servicePrincipals += [PSCustomObject]@{
                        Id = $sp.Id
                        AppId = $sp.AppId
                        DisplayName = $sp.DisplayName
                        ServicePrincipalType = $sp.ServicePrincipalType
                        CreatedDateTime = $sp.CreatedDateTime
                        PublisherName = ""
                        AppDisplayName = ""
                        PasswordCredentials = 0
                        KeyCredentials = 0
                        HasSecrets = $false
                    }
                }
            }
        } catch {
            Write-Verbose "Failed to retrieve service principals: $($_.Exception.Message)"
        }
        
        # Analyze the applications and service principals
        $analysis = @{
            ApplicationsWithSecrets = ($applications | Where-Object { $_.HasSecrets }).Count
            ServicePrincipalsWithSecrets = ($servicePrincipals | Where-Object { $_.HasSecrets }).Count
            ManagedIdentities = ($servicePrincipals | Where-Object { $_.ServicePrincipalType -eq "ManagedIdentity" }).Count
            ApplicationServicePrincipals = ($servicePrincipals | Where-Object { $_.ServicePrincipalType -eq "Application" }).Count
            TotalCredentials = ($applications | Measure-Object -Property PasswordCredentials -Sum).Sum + ($applications | Measure-Object -Property KeyCredentials -Sum).Sum
        }
        
        return @{
            Applications = $applications
            ServicePrincipals = $servicePrincipals
            Analysis = $analysis
            ErrorMessage = $null
        }
    } catch {
        return @{ ErrorMessage = "Failed to retrieve tenant applications: $($_.Exception.Message)" }
    }
}

function Test-GraphApiPermissions {
    <#
    .SYNOPSIS
        Tests available Graph API permissions and returns enumeration capabilities.
    #>
    [CmdletBinding()]
    param()
    
    $permissions = @{
        CanReadUsers = $false
        CanReadGroups = $false
        CanReadApplications = $false
        CanReadDirectoryRoles = $false
        CanReadOrganization = $false
        CanReadConditionalAccess = $false
        CanReadAuditLogs = $false
        AvailableEndpoints = @()
        PermissionErrors = @()
    }
    
    # Test endpoints to determine available permissions
    $testEndpoints = @(
        @{ Name = "Users"; Endpoint = "https://graph.microsoft.com/v1.0/users?`$top=1"; Property = "CanReadUsers" }
        @{ Name = "Groups"; Endpoint = "https://graph.microsoft.com/v1.0/groups?`$top=1"; Property = "CanReadGroups" }
        @{ Name = "Applications"; Endpoint = "https://graph.microsoft.com/v1.0/applications?`$top=1"; Property = "CanReadApplications" }
        @{ Name = "Directory Roles"; Endpoint = "https://graph.microsoft.com/v1.0/directoryRoles?`$top=1"; Property = "CanReadDirectoryRoles" }
        @{ Name = "Organization"; Endpoint = "https://graph.microsoft.com/v1.0/organization"; Property = "CanReadOrganization" }
        @{ Name = "Conditional Access"; Endpoint = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$top=1"; Property = "CanReadConditionalAccess" }
        @{ Name = "Audit Logs"; Endpoint = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1"; Property = "CanReadAuditLogs" }
    )
    
    foreach ($test in $testEndpoints) {
        try {
            $response = Invoke-RestMethod -Uri $test.Endpoint -Headers $Script:GraphHeaders -Method Get -ErrorAction Stop
            if ($response) {
                $permissions[$test.Property] = $true
                $permissions.AvailableEndpoints += $test.Name
            }
        } catch {
            $permissions.PermissionErrors += @{
                Endpoint = $test.Name
                Error = $_.Exception.Message
                StatusCode = $_.Exception.Response.StatusCode.value__
            }
        }
    }
    
    # Add comprehensive permission guidance
    if ($permissions.PermissionErrors.Count -gt 0) {
        Write-Output "`nGraph API Permission Issues Detected"
        Write-Output "The current Graph token has limited permissions. Here's what's missing:"
        
        $permissionMappings = @{
            "Users" = "User.Read.All or Directory.Read.All"
            "Groups" = "Group.Read.All or Directory.Read.All" 
            "Applications" = "Application.Read.All or Directory.Read.All"
            "Directory Roles" = "RoleManagement.Read.Directory or Directory.Read.All"
            "Organization" = "Organization.Read.All or Directory.Read.All"
            "Conditional Access" = "Policy.Read.All or Directory.Read.All"
            "Audit Logs" = "AuditLog.Read.All or Directory.Read.All"
        }
        
        foreach ($permerror in $permissions.PermissionErrors) {
            $requiredPermission = $permissionMappings[$permerror.Endpoint]
            Write-Output "  - $($permerror.Endpoint): Missing '$requiredPermission' permission"
        }
        
        Write-Output "`nTo get comprehensive Azure AD enumeration, try these options:"
        Write-Output "  1. Get a token with Directory.Read.All permission (covers all endpoints)"
        Write-Output "  2. Use Azure CLI with proper permissions: az login --allow-no-subscriptions"
        Write-Output "  3. Use PowerShell: Connect-MgGraph -Scopes 'Directory.Read.All'"
        Write-Output "  4. For service principal: Grant 'Directory.Read.All' application permission in Azure AD"
        Write-Output ""
        Write-Output "Service Principal Permission Grant Commands:"
        Write-Output "  az ad app permission add --id <app-id> --api 00000003-0000-0000-c000-000000000000 --api-permissions 7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role"
        Write-Output "  az ad app permission grant --id <app-id> --api 00000003-0000-0000-c000-000000000000"
        Write-Output "  az ad app permission admin-consent --id <app-id>"
    }
    
    return $permissions
}

function Initialize-AzureCLI {
    <#
    .SYNOPSIS
        Initializes Azure CLI authentication with service principal.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId,
        
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalSecret,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )
    
    try {
        # Check if Azure CLI is installed
        $azCli = Get-Command az -ErrorAction SilentlyContinue
        if (-not $azCli) {
            return @{
                Success = $false
                Error = "Azure CLI (az) is not installed or not available in PATH"
                AuthenticationDetails = $null
            }
        }
        
        Write-Verbose "Authenticating with Azure CLI using service principal..."
        
        # Login with service principal
        $loginCmd = "az login --service-principal --username '$ServicePrincipalId' --password '$ServicePrincipalSecret' --tenant '$TenantId' --allow-no-subscriptions"
        $loginResult = Invoke-Expression $loginCmd 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            return @{
                Success = $false
                Error = "Azure CLI login failed: $loginResult"
                AuthenticationDetails = $null
            }
        }
        
        # Get account details
        $accountInfo = az account show --output json 2>&1 | ConvertFrom-Json -ErrorAction SilentlyContinue
        
        return @{
            Success = $true
            Error = $null
            AuthenticationDetails = @{
                TenantId = $accountInfo.tenantId
                ServicePrincipalId = $accountInfo.user.name
                AuthenticationMethod = "ServicePrincipal"
                HasSubscriptions = $null -ne $accountInfo.id
            }
        }
        
    } catch {
        return @{
            Success = $false
            Error = "Failed to initialize Azure CLI: $($_.Exception.Message)"
            AuthenticationDetails = $null
        }
    }
}

function Initialize-AzServicePrincipal {
    <#
    .SYNOPSIS
        Initializes Azure PowerShell authentication using service principal credentials.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApplicationId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )
    
    try {
        # Check if Az.Accounts module is available
        $azAccountsModule = Get-Module Az.Accounts -ListAvailable -ErrorAction SilentlyContinue
        if (-not $azAccountsModule) {
            return @{
                Success = $false
                Error = "Az.Accounts module is not installed. Please run: Install-Module Az.Accounts -Force"
                AuthenticationDetails = $null
            }
        }
        
        # Import Az.Accounts module if not already loaded
        if (-not (Get-Module Az.Accounts)) {
            Write-Verbose "Importing Az.Accounts module..."
            Import-Module Az.Accounts -Force -ErrorAction Stop
        }
        
        Write-Verbose "Authenticating with Azure PowerShell using service principal..."
        
        # Create PSCredential object
        $secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($ApplicationId, $secureSecret)
        
        # Connect to Azure with service principal
        try {
            # First try standard connection
            $connectResult = Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant $TenantId -ErrorAction Stop
            Write-Verbose "Standard Azure PowerShell connection successful"
        } catch {
            # Try with SkipContextPopulation for tenant-only scenarios
            Write-Verbose "Standard connection failed, attempting tenant-only connection..."
            try {
                $connectResult = Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant $TenantId -SkipContextPopulation -ErrorAction Stop
                Write-Verbose "Tenant-only connection succeeded"
            } catch {
                # Try with -Force to bypass subscription issues
                Write-Verbose "Tenant-only connection failed, attempting forced connection..."
                try {
                    $connectResult = Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant $TenantId -Force -ErrorAction Stop
                    Write-Verbose "Forced connection succeeded"
                } catch {
                    return @{
                        Success = $false
                        Error = "All Connect-AzAccount attempts failed. Last error: $($_.Exception.Message). This may indicate the service principal credentials are invalid or the service principal lacks necessary permissions in tenant $TenantId"
                        AuthenticationDetails = $null
                    }
                }
            }
        }
        
        if (-not $connectResult) {
            return @{
                Success = $false
                Error = "Connect-AzAccount returned null result"
                AuthenticationDetails = $null
            }
        }
        
        # Get current context to verify authentication
        $context = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $context) {
            return @{
                Success = $false
                Error = "Failed to obtain Azure context after authentication"
                AuthenticationDetails = $null
            }
        }
        
        # Check if service principal has any subscription access
        $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue
        
        return @{
            Success = $true
            Error = $null
            AuthenticationDetails = @{
                TenantId = $context.Tenant.Id
                ApplicationId = $context.Account.Id
                AuthenticationMethod = "ServicePrincipal"
                HasSubscriptions = ($subscriptions.Count -gt 0)
                SubscriptionCount = $subscriptions.Count
                TenantDisplayName = $context.Tenant.Name
            }
        }
        
    } catch {
        return @{
            Success = $false
            Error = "Failed to authenticate with service principal: $($_.Exception.Message)"
            AuthenticationDetails = $null
        }
    }
}

function Get-AzAccessTokensFromServicePrincipal {
    <#
    .SYNOPSIS
        Extracts ARM and Graph access tokens from Azure PowerShell service principal context.
    #>
    [CmdletBinding()]
    param()
    
    try {
        $result = @{
            Success = $false
            ARMToken = $null
            GraphToken = $null
            KeyVaultToken = $null
            Error = $null
        }
        
        # Get ARM token
        try {
            Write-Verbose "Acquiring ARM access token..."
            $armTokenResult = Get-AzAccessToken -ResourceUrl "https://management.azure.com" -ErrorAction Stop
            if ($armTokenResult -and $armTokenResult.Token) {
                # Convert SecureString to plain text if needed
                if ($armTokenResult.Token -is [System.Security.SecureString]) {
                    $result.ARMToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($armTokenResult.Token))
                } else {
                    $result.ARMToken = $armTokenResult.Token
                }
                Write-Verbose "ARM token acquired successfully"
            }
        } catch {
            Write-Warning "Failed to acquire ARM token: $($_.Exception.Message)"
        }
        
        # Get Graph token
        try {
            Write-Verbose "Acquiring Graph access token..."
            $graphTokenResult = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
            if ($graphTokenResult -and $graphTokenResult.Token) {
                # Convert SecureString to plain text if needed
                if ($graphTokenResult.Token -is [System.Security.SecureString]) {
                    $result.GraphToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($graphTokenResult.Token))
                } else {
                    $result.GraphToken = $graphTokenResult.Token
                }
                Write-Verbose "Graph token acquired successfully"
            }
        } catch {
            Write-Warning "Failed to acquire Graph token: $($_.Exception.Message)"
        }
        
        # Get Key Vault token (optional, for enhanced Key Vault access)
        try {
            Write-Verbose "Acquiring Key Vault access token..."
            $kvTokenResult = Get-AzAccessToken -ResourceUrl "https://vault.azure.net" -ErrorAction Stop
            if ($kvTokenResult -and $kvTokenResult.Token) {
                # Convert SecureString to plain text if needed
                if ($kvTokenResult.Token -is [System.Security.SecureString]) {
                    $result.KeyVaultToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($kvTokenResult.Token))
                } else {
                    $result.KeyVaultToken = $kvTokenResult.Token
                }
                Write-Verbose "Key Vault token acquired successfully"
            }
        } catch {
            Write-Verbose "Key Vault token acquisition failed (this is optional): $($_.Exception.Message)"
        }
        
        # Check if we got at least one token
        if ($result.ARMToken -or $result.GraphToken) {
            $result.Success = $true
            Write-Verbose "Token acquisition completed successfully"
        } else {
            $result.Error = "Failed to acquire any access tokens"
            Write-Warning $result.Error
        }
        
        return $result
        
    } catch {
        return @{
            Success = $false
            ARMToken = $null
            GraphToken = $null
            KeyVaultToken = $null
            Error = "Failed to acquire access tokens: $($_.Exception.Message)"
        }
    }
}

function Test-AzureCLICapabilities {
    <#
    .SYNOPSIS
        Tests Azure CLI capabilities and available commands.
    #>
    [CmdletBinding()]
    param()
    
    $capabilities = @{
        CanListUsers = $false
        CanListGroups = $false
        CanListApps = $false
        CanListRoles = $false
        CanListTenantDetails = $false
        CanListSubscriptions = $false
        CanListOwnedObjects = $false
        AvailableCommands = @()
        CommandErrors = @()
    }
    
    # Test various CLI commands
    $testCommands = @(
        @{ Name = "Users"; Command = "az ad user list --top 1"; Property = "CanListUsers" }
        @{ Name = "Groups"; Command = "az ad group list --top 1"; Property = "CanListGroups" }
        @{ Name = "Applications"; Command = "az ad app list --top 1"; Property = "CanListApps" }
        @{ Name = "Roles"; Command = "az role assignment list --all --max-items 1"; Property = "CanListRoles" }
        @{ Name = "Tenant"; Command = "az account tenant list"; Property = "CanListTenantDetails" }
        @{ Name = "Subscriptions"; Command = "az account subscription list --max-items 1"; Property = "CanListSubscriptions" }
        @{ Name = "OwnedObjects"; Command = "az ad signed-in-user list-owned-objects"; Property = "CanListOwnedObjects" }
    )
    
    foreach ($test in $testCommands) {
        try {
            $result = Invoke-Expression "$($test.Command) --output json" 2>&1
            if ($LASTEXITCODE -eq 0) {
                $capabilities[$test.Property] = $true
                $capabilities.AvailableCommands += $test.Name
            } else {
                $capabilities.CommandErrors += @{
                    Command = $test.Name
                    Error = $result
                    ExitCode = $LASTEXITCODE
                }
            }
        } catch {
            $capabilities.CommandErrors += @{
                Command = $test.Name
                Error = $_.Exception.Message
                ExitCode = "Exception"
            }
        }
    }
    
    return $capabilities
}

function Get-TenantDetailsViaCLI {
    <#
    .SYNOPSIS
        Retrieves tenant details using Azure CLI.
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Get tenant information
        $tenantResult = az account tenant list --output json 2>&1
        if ($LASTEXITCODE -eq 0) {
            $tenants = $tenantResult | ConvertFrom-Json -ErrorAction SilentlyContinue
            
            # Get current account info
            $accountResult = az account show --output json 2>&1
            $currentAccount = if ($LASTEXITCODE -eq 0) { $accountResult | ConvertFrom-Json -ErrorAction SilentlyContinue } else { $null }
            
            return @{
                Tenants = $tenants
                CurrentAccount = $currentAccount
                Error = $null
            }
        } else {
            return @{ ErrorMessage = "Failed to retrieve tenant details via CLI: $tenantResult" }
        }
    } catch {
        return @{ ErrorMessage = "Failed to retrieve tenant details via CLI: $($_.Exception.Message)" }
    }
}

function Get-UsersViaCLI {
    <#
    .SYNOPSIS
        Retrieves users using Azure CLI.
    #>
    [CmdletBinding()]
    param()
    
    try {
        $usersResult = az ad user list --output json 2>&1
        if ($LASTEXITCODE -eq 0) {
            $users = $usersResult | ConvertFrom-Json -ErrorAction SilentlyContinue
            
            if ($users) {
                # Analyze user data
                $analysis = @{
                    TotalUsers = $users.Count
                    EnabledUsers = ($users | Where-Object { $_.accountEnabled -eq $true }).Count
                    DisabledUsers = ($users | Where-Object { $_.accountEnabled -eq $false }).Count
                    GuestUsers = ($users | Where-Object { $_.userType -eq "Guest" }).Count
                    MemberUsers = ($users | Where-Object { $_.userType -eq "Member" }).Count
                }
                
                return @{
                    Users = $users
                    Analysis = $analysis
                    Error = $null
                }
            } else {
                return @{ ErrorMessage = "No users found or failed to parse CLI response" }
            }
        } else {
            return @{ ErrorMessage = "Failed to retrieve users via CLI: $usersResult" }
        }
    } catch {
        return @{ ErrorMessage = "Failed to retrieve users via CLI: $($_.Exception.Message)" }
    }
}

function Get-GroupsViaCLI {
    <#
    .SYNOPSIS
        Retrieves groups using Azure CLI.
    #>
    [CmdletBinding()]
    param()
    
    try {
        $groupsResult = az ad group list --output json 2>&1
        if ($LASTEXITCODE -eq 0) {
            $groups = $groupsResult | ConvertFrom-Json -ErrorAction SilentlyContinue
            
            if ($groups) {
                # Analyze group data
                $analysis = @{
                    TotalGroups = $groups.Count
                    SecurityGroups = ($groups | Where-Object { $_.securityEnabled -eq $true }).Count
                    DistributionGroups = ($groups | Where-Object { $_.mailEnabled -eq $true -and $_.securityEnabled -eq $false }).Count
                }
                
                return @{
                    Groups = $groups
                    Analysis = $analysis
                    Error = $null
                }
            } else {
                return @{ ErrorMessage = "No groups found or failed to parse CLI response" }
            }
        } else {
            return @{ ErrorMessage = "Failed to retrieve groups via CLI: $groupsResult" }
        }
    } catch {
        return @{ ErrorMessage = "Failed to retrieve groups via CLI: $($_.Exception.Message)" }
    }
}

function Get-ApplicationsViaCLI {
    <#
    .SYNOPSIS
        Retrieves applications using Azure CLI.
    #>
    [CmdletBinding()]
    param(
        [array]$OwnedApplications = @()
    )
    
    try {
        $appsResult = az ad app list --output json 2>&1
        if ($LASTEXITCODE -eq 0) {
            $applications = $appsResult | ConvertFrom-Json -ErrorAction SilentlyContinue
            
            if ($applications) {
                # Enhance applications with ownership information
                $enhancedApplications = @()
                foreach ($app in $applications) {
                    $isOwned = Test-ApplicationOwnership -ApplicationId $app.appId -OwnedApplications $OwnedApplications
                    $enhancedApp = $app | Add-Member -NotePropertyName "IsOwned" -NotePropertyValue $isOwned -PassThru
                    $enhancedApp = $enhancedApp | Add-Member -NotePropertyName "OwnershipStatus" -NotePropertyValue $(if ($isOwned) { "OWNED - PRIVILEGE ESCALATION OPPORTUNITY!" } else { "Not Owned" }) -PassThru
                    $enhancedApplications += $enhancedApp
                }
                
                # Get service principals
                $spResult = az ad sp list --all --output json 2>&1
                $servicePrincipals = if ($LASTEXITCODE -eq 0) { $spResult | ConvertFrom-Json -ErrorAction SilentlyContinue } else { @() }
                
                # Analyze application data including ownership
                $ownedAppsCount = ($enhancedApplications | Where-Object { $_.IsOwned -eq $true }).Count
                $analysis = @{
                    TotalApplications = $enhancedApplications.Count
                    ApplicationsWithCredentials = ($enhancedApplications | Where-Object { $_.passwordCredentials -or $_.keyCredentials }).Count
                    ServicePrincipalsCount = $servicePrincipals.Count
                    OwnedApplications = $ownedAppsCount
                    PrivilegeEscalationOpportunities = $ownedAppsCount
                }
                
                return @{
                    Applications = $enhancedApplications
                    ServicePrincipals = $servicePrincipals
                    Analysis = $analysis
                    Error = $null
                }
            } else {
                return @{ Error = "No applications found or failed to parse CLI response" }
            }
        } else {
            return @{ Error = "Failed to retrieve applications via CLI: $appsResult" }
        }
    } catch {
        return @{ Error = "Failed to retrieve applications via CLI: $($_.Exception.Message)" }
    }
}

function Get-RoleAssignmentsViaCLI {
    <#
    .SYNOPSIS
        Retrieves role assignments using Azure CLI.
    #>
    [CmdletBinding()]
    param()
    
    try {
        $roleResult = az role assignment list --all --output json 2>&1
        if ($LASTEXITCODE -eq 0) {
            $roleAssignments = $roleResult | ConvertFrom-Json -ErrorAction SilentlyContinue
            
            if ($roleAssignments) {
                # Analyze role assignments
                $analysis = @{
                    TotalRoleAssignments = $roleAssignments.Count
                    UniqueRoles = ($roleAssignments | Select-Object -ExpandProperty roleDefinitionName -Unique).Count
                    UniquePrincipals = ($roleAssignments | Select-Object -ExpandProperty principalId -Unique).Count
                }
                
                return @{
                    RoleAssignments = $roleAssignments
                    Analysis = $analysis
                    Error = $null
                }
            } else {
                return @{ Error = "No role assignments found or failed to parse CLI response" }
            }
        } else {
            return @{ Error = "Failed to retrieve role assignments via CLI: $roleResult" }
        }
    } catch {
        return @{ Error = "Failed to retrieve role assignments via CLI: $($_.Exception.Message)" }
    }
}

function Get-OwnedObjectsViaCLI {
    <#
    .SYNOPSIS
        Retrieves objects owned by the current signed-in user using Azure CLI.
    .DESCRIPTION
        Uses 'az ad signed-in-user list-owned-objects' to get all objects owned by the current user.
        This is crucial for privilege escalation scenarios, especially for applications where the user
        can create new secrets to authenticate as the application.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Retrieving objects owned by current user via Azure CLI..."
        
        # Get owned objects using Azure CLI
        $ownedResult = az ad signed-in-user list-owned-objects --output json 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            $ownedObjects = $ownedResult | ConvertFrom-Json -ErrorAction SilentlyContinue
            
            if ($ownedObjects) {
                # Categorize owned objects by type
                $applications = $ownedObjects | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.application' }
                $servicePrincipals = $ownedObjects | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' }
                $groups = $ownedObjects | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' }
                $devices = $ownedObjects | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.device' }
                $others = $ownedObjects | Where-Object { $_.'@odata.type' -notin @('#microsoft.graph.application', '#microsoft.graph.servicePrincipal', '#microsoft.graph.group', '#microsoft.graph.device') }
                
                # Create analysis summary
                $analysis = @{
                    TotalOwnedObjects = $ownedObjects.Count
                    OwnedApplications = $applications.Count
                    OwnedServicePrincipals = $servicePrincipals.Count
                    OwnedGroups = $groups.Count
                    OwnedDevices = $devices.Count
                    OtherOwnedObjects = $others.Count
                    PrivilegeEscalationOpportunities = $applications.Count # Applications are key for privilege escalation
                }
                
                Write-Verbose "Found $($ownedObjects.Count) owned objects: $($applications.Count) apps, $($servicePrincipals.Count) SPs, $($groups.Count) groups"
                
                return @{
                    OwnedObjects = $ownedObjects
                    Applications = $applications
                    ServicePrincipals = $servicePrincipals
                    Groups = $groups
                    Devices = $devices
                    Others = $others
                    Analysis = $analysis
                    Error = $null
                }
            } else {
                return @{ 
                    OwnedObjects = @()
                    Applications = @()
                    ServicePrincipals = @()
                    Groups = @()
                    Devices = @()
                    Others = @()
                    Analysis = @{ TotalOwnedObjects = 0; OwnedApplications = 0; OwnedServicePrincipals = 0; OwnedGroups = 0; OwnedDevices = 0; OtherOwnedObjects = 0; PrivilegeEscalationOpportunities = 0 }
                    Error = $null
                }
            }
        } else {
            return @{ Error = "Failed to retrieve owned objects via CLI: $ownedResult" }
        }
    } catch {
        return @{ Error = "Failed to retrieve owned objects via CLI: $($_.Exception.Message)" }
    }
}

function Get-OwnedObjectsViaGraph {
    <#
    .SYNOPSIS
        Retrieves objects owned by the current signed-in user using Graph API directly.
    .DESCRIPTION
        Uses Graph API '/me/ownedObjects' endpoint to get all objects owned by the current user.
        This provides the same functionality as Azure CLI but using the Graph token directly.
    #>
    [CmdletBinding()]
    param(
        [string]$AccessToken
    )
    
    try {
        Write-Verbose "Retrieving objects owned by current user via Graph API..."
        
        # Set up headers for Graph API call
        $headers = @{
            'Authorization' = "Bearer $AccessToken"
            'Content-Type' = 'application/json'
        }
        
        # Get owned objects using Graph API
        $allOwnedObjects = @()
        $nextLink = "https://graph.microsoft.com/v1.0/me/ownedObjects"
        
        do {
            $response = Invoke-RestMethod -Uri $nextLink -Headers $headers -Method GET
            
            if ($response.value) {
                $allOwnedObjects += $response.value
            }
            
            $nextLink = $response.'@odata.nextLink'
        } while ($nextLink)
        
        if ($allOwnedObjects) {
            # Debug: Show what object types we actually received
            Write-Verbose "DEBUG: Raw owned objects received:"
            foreach ($obj in $allOwnedObjects) {
                Write-Verbose "  Object: $($obj.displayName), Type: $($obj.'@odata.type'), ID: $($obj.id)"
            }
            
            # Categorize owned objects by type
            $applications = $allOwnedObjects | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.application' }
            $servicePrincipals = $allOwnedObjects | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' }
            $groups = $allOwnedObjects | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' }
            $devices = $allOwnedObjects | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.device' }
            $others = $allOwnedObjects | Where-Object { $_.'@odata.type' -notin @('#microsoft.graph.application', '#microsoft.graph.servicePrincipal', '#microsoft.graph.group', '#microsoft.graph.device') }
            
            # Debug: Show categorization results
            Write-Verbose "DEBUG: Categorization results:"
            Write-Verbose "  Applications: $(@($applications).Count) objects"
            Write-Verbose "  Service Principals: $(@($servicePrincipals).Count) objects"
            Write-Verbose "  Groups: $(@($groups).Count) objects"
            Write-Verbose "  Devices: $(@($devices).Count) objects"
            Write-Verbose "  Others: $(@($others).Count) objects"
            
            # Create analysis summary with robust counting (handles single objects and arrays)
            $appCount = if ($applications) { @($applications).Count } else { 0 }
            $spCount = if ($servicePrincipals) { @($servicePrincipals).Count } else { 0 }
            $groupCount = if ($groups) { @($groups).Count } else { 0 }
            $deviceCount = if ($devices) { @($devices).Count } else { 0 }
            $otherCount = if ($others) { @($others).Count } else { 0 }
            
            $analysis = @{
                TotalOwnedObjects = $allOwnedObjects.Count
                OwnedApplications = $appCount
                OwnedServicePrincipals = $spCount
                OwnedGroups = $groupCount
                OwnedDevices = $deviceCount
                OtherOwnedObjects = $otherCount
                PrivilegeEscalationOpportunities = $appCount # Applications are key for privilege escalation
            }
            
            Write-Verbose "Found $(@($allOwnedObjects).Count) owned objects via Graph API: $appCount apps, $spCount SPs, $groupCount groups"
            
            return @{
                OwnedObjects = $allOwnedObjects
                Applications = $applications
                ServicePrincipals = $servicePrincipals
                Groups = $groups
                Devices = $devices
                Others = $others
                Analysis = $analysis
                Error = $null
            }
        } else {
            return @{ 
                OwnedObjects = @()
                Applications = @()
                ServicePrincipals = @()
                Groups = @()
                Devices = @()
                Others = @()
                Analysis = @{ TotalOwnedObjects = 0; OwnedApplications = 0; OwnedServicePrincipals = 0; OwnedGroups = 0; OwnedDevices = 0; OtherOwnedObjects = 0; PrivilegeEscalationOpportunities = 0 }
                Error = $null
            }
        }
    } catch {
        return @{ Error = "Failed to retrieve owned objects via Graph API: $($_.Exception.Message)" }
    }
}

function Test-ApplicationOwnership {
    <#
    .SYNOPSIS
        Checks if a given application ID is in the list of owned applications.
    #>
    [CmdletBinding()]
    param(
        [string]$ApplicationId,
        [array]$OwnedApplications
    )
    
    if (-not $OwnedApplications -or $OwnedApplications.Count -eq 0) {
        return $false
    }
    
    # Check by AppId (client ID) or object ID
    foreach ($ownedApp in $OwnedApplications) {
        if ($ownedApp.appId -eq $ApplicationId -or $ownedApp.id -eq $ApplicationId) {
            return $true
        }
    }
    
    return $false
}

function Get-MonitoringAndLoggingDetails {
    <#
    .SYNOPSIS
        Retrieves comprehensive monitoring and logging configuration including Log Analytics, Application Insights, and diagnostic settings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Resources
    )
    
    try {
        Write-Debug "Getting monitoring and logging details"
        
        $monitoringDetails = @{
            LogAnalyticsWorkspaces = @()
            ApplicationInsights = @()
            DiagnosticSettings = @()
            ActionGroups = @()
            AlertRules = @()
            Error = $null
        }
        
        # Get Log Analytics Workspaces
        $logAnalyticsResources = $Resources | Where-Object { $_.type -eq "Microsoft.OperationalInsights/workspaces" }
        foreach ($laResource in $logAnalyticsResources) {
            try {
                $laInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($laResource.id)?api-version=2022-10-01" -SuppressWarnings $true
                if ($laInfo) {
                    $laDetail = @{
                        Name = $laInfo.name
                        Location = $laInfo.location
                        ResourceGroup = ($laInfo.id -split '/')[4]
                        WorkspaceId = $laInfo.properties.customerId
                        Sku = $laInfo.properties.sku.name
                        RetentionInDays = $laInfo.properties.retentionInDays
                        DailyQuotaGb = $laInfo.properties.workspaceCapping.dailyQuotaGb
                        PublicNetworkAccessForIngestion = $laInfo.properties.publicNetworkAccessForIngestion
                        PublicNetworkAccessForQuery = $laInfo.properties.publicNetworkAccessForQuery
                        DataSources = @()
                        ConnectedSources = @()
                    }
                    
                    # Get data sources
                    try {
                        $dataSourcesInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($laResource.id)/dataSources?api-version=2020-08-01" -SuppressWarnings $true
                        if ($dataSourcesInfo -and $dataSourcesInfo.value) {
                            $laDetail.DataSources = $dataSourcesInfo.value | ForEach-Object {
                                @{
                                    Name = $_.name
                                    Kind = $_.kind
                                    Properties = $_.properties
                                }
                            }
                        }
                    } catch {
                        Write-Debug "Could not retrieve data sources for workspace $($laResource.name): $($_.Exception.Message)"
                    }
                    
                    $monitoringDetails.LogAnalyticsWorkspaces += $laDetail
                }
            } catch {
                Write-Debug "Could not retrieve Log Analytics workspace details for $($laResource.name): $($_.Exception.Message)"
            }
        }
        
        # Get Application Insights
        $appInsightsResources = $Resources | Where-Object { $_.type -eq "Microsoft.Insights/components" }
        foreach ($aiResource in $appInsightsResources) {
            try {
                $aiInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($aiResource.id)?api-version=2020-02-02" -SuppressWarnings $true
                if ($aiInfo) {
                    $aiDetail = @{
                        Name = $aiInfo.name
                        Location = $aiInfo.location
                        ResourceGroup = ($aiInfo.id -split '/')[4]
                        ApplicationId = $aiInfo.properties.AppId
                        InstrumentationKey = $aiInfo.properties.InstrumentationKey
                        ConnectionString = $aiInfo.properties.ConnectionString
                        ApplicationType = $aiInfo.properties.Application_Type
                        FlowType = $aiInfo.properties.Flow_Type
                        RequestSource = $aiInfo.properties.Request_Source
                        WorkspaceResourceId = $aiInfo.properties.WorkspaceResourceId
                        SamplingPercentage = $aiInfo.properties.SamplingPercentage
                        RetentionInDays = $aiInfo.properties.RetentionInDays
                        DisableIpMasking = $aiInfo.properties.DisableIpMasking
                        ImmediatePurgeDataOn30Days = $aiInfo.properties.ImmediatePurgeDataOn30Days
                    }
                    
                    $monitoringDetails.ApplicationInsights += $aiDetail
                }
            } catch {
                Write-Debug "Could not retrieve Application Insights details for $($aiResource.name): $($_.Exception.Message)"
            }
        }
        
        # Get Action Groups
        $actionGroupResources = $Resources | Where-Object { $_.type -eq "Microsoft.Insights/actionGroups" }
        foreach ($agResource in $actionGroupResources) {
            try {
                $agInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($agResource.id)?api-version=2022-06-01" -SuppressWarnings $true
                if ($agInfo) {
                    $agDetail = @{
                        Name = $agInfo.name
                        Location = $agInfo.location
                        ResourceGroup = ($agInfo.id -split '/')[4]
                        GroupShortName = $agInfo.properties.groupShortName
                        Enabled = $agInfo.properties.enabled
                        EmailReceivers = if ($agInfo.properties.emailReceivers) { $agInfo.properties.emailReceivers.Count } else { 0 }
                        SmsReceivers = if ($agInfo.properties.smsReceivers) { $agInfo.properties.smsReceivers.Count } else { 0 }
                        WebhookReceivers = if ($agInfo.properties.webhookReceivers) { $agInfo.properties.webhookReceivers.Count } else { 0 }
                        AzureAppPushReceivers = if ($agInfo.properties.azureAppPushReceivers) { $agInfo.properties.azureAppPushReceivers.Count } else { 0 }
                        AutomationRunbookReceivers = if ($agInfo.properties.automationRunbookReceivers) { $agInfo.properties.automationRunbookReceivers.Count } else { 0 }
                        LogicAppReceivers = if ($agInfo.properties.logicAppReceivers) { $agInfo.properties.logicAppReceivers.Count } else { 0 }
                        AzureFunctionReceivers = if ($agInfo.properties.azureFunctionReceivers) { $agInfo.properties.azureFunctionReceivers.Count } else { 0 }
                    }
                    
                    $monitoringDetails.ActionGroups += $agDetail
                }
            } catch {
                Write-Debug "Could not retrieve Action Group details for $($agResource.name): $($_.Exception.Message)"
            }
        }
        
        # Get Alert Rules (both classic and new)
        $alertResources = $Resources | Where-Object { 
            $_.type -in @("Microsoft.Insights/alertrules", "Microsoft.Insights/metricalerts", "Microsoft.Insights/activityLogAlerts", "Microsoft.Insights/scheduledQueryRules") 
        }
        foreach ($alertResource in $alertResources) {
            try {
                $alertInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($alertResource.id)?api-version=2018-03-01" -SuppressWarnings $true
                if ($alertInfo) {
                    $alertDetail = @{
                        Name = $alertInfo.name
                        Type = $alertInfo.type
                        Location = $alertInfo.location
                        ResourceGroup = ($alertInfo.id -split '/')[4]
                        Enabled = $alertInfo.properties.enabled
                        Severity = $alertInfo.properties.severity
                        Description = $alertInfo.properties.description
                        Actions = if ($alertInfo.properties.actions) { $alertInfo.properties.actions.Count } else { 0 }
                        Criteria = if ($alertInfo.properties.criteria -and $alertInfo.properties.criteria.allOf) { $alertInfo.properties.criteria.allOf.Count } else { 0 }
                        EvaluationFrequency = $alertInfo.properties.evaluationFrequency
                        WindowSize = $alertInfo.properties.windowSize
                        TargetResourceType = $alertInfo.properties.targetResourceType
                        Scopes = if ($alertInfo.properties.scopes) { $alertInfo.properties.scopes.Count } else { 0 }
                    }
                    
                    $monitoringDetails.AlertRules += $alertDetail
                }
            } catch {
                Write-Debug "Could not retrieve Alert Rule details for $($alertResource.name): $($_.Exception.Message)"
            }
        }
        
        # Get diagnostic settings for key resources
        $keyResourceTypes = @(
            "Microsoft.Compute/virtualMachines",
            "Microsoft.KeyVault/vaults", 
            "Microsoft.Storage/storageAccounts",
            "Microsoft.Sql/servers",
            "Microsoft.Network/networkSecurityGroups",
            "Microsoft.Web/sites"
        )
        
        $keyResources = $Resources | Where-Object { $_.type -in $keyResourceTypes }
        foreach ($resource in $keyResources | Select-Object -First 10) { # Limit to first 10 to avoid too many API calls
            try {
                $diagnosticInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($resource.id)/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview" -SuppressWarnings $true
                if ($diagnosticInfo -and $diagnosticInfo.value) {
                    foreach ($diagSetting in $diagnosticInfo.value) {
                        $diagDetail = @{
                            ResourceName = $resource.name
                            ResourceType = $resource.type
                            DiagnosticSettingName = $diagSetting.name
                            StorageAccountId = $diagSetting.properties.storageAccountId
                            WorkspaceId = $diagSetting.properties.workspaceId
                            EventHubName = $diagSetting.properties.eventHubName
                            LogsEnabled = if ($diagSetting.properties.logs) { $diagSetting.properties.logs.Count } else { 0 }
                            MetricsEnabled = if ($diagSetting.properties.metrics) { $diagSetting.properties.metrics.Count } else { 0 }
                            LogAnalyticsDestinationType = $diagSetting.properties.logAnalyticsDestinationType
                        }
                        
                        $monitoringDetails.DiagnosticSettings += $diagDetail
                    }
                }
            } catch {
                Write-Debug "Could not retrieve diagnostic settings for $($resource.name): $($_.Exception.Message)"
            }
        }
        
        # Analyze monitoring coverage
        $monitoringDetails.MonitoringAnalysis = @{
            LogAnalyticsWorkspaceCount = $monitoringDetails.LogAnalyticsWorkspaces.Count
            ApplicationInsightsCount = $monitoringDetails.ApplicationInsights.Count
            ActionGroupCount = $monitoringDetails.ActionGroups.Count
            AlertRuleCount = $monitoringDetails.AlertRules.Count
            DiagnosticSettingsCount = $monitoringDetails.DiagnosticSettings.Count
            EnabledAlertRules = ($monitoringDetails.AlertRules | Where-Object { $_.Enabled }).Count
            ResourcesWithDiagnostics = ($monitoringDetails.DiagnosticSettings | Select-Object ResourceName -Unique).Count
            TotalActionGroupReceivers = ($monitoringDetails.ActionGroups | ForEach-Object { 
                $_.EmailReceivers + $_.SmsReceivers + $_.WebhookReceivers + $_.AzureAppPushReceivers + $_.AutomationRunbookReceivers + $_.LogicAppReceivers + $_.AzureFunctionReceivers 
            } | Measure-Object -Sum).Sum
            HasCentralizedLogging = $monitoringDetails.LogAnalyticsWorkspaces.Count -gt 0
            HasApplicationMonitoring = $monitoringDetails.ApplicationInsights.Count -gt 0
        }
        
        return $monitoringDetails
        
    } catch {
        Write-Warning "Failed to get monitoring and logging details: $($_.Exception.Message)"
        return @{
            Error = "Failed to retrieve monitoring details: $($_.Exception.Message)"
        }
    }
}

function Get-AzureVMUserData {
    <#
    .SYNOPSIS
        Attempts to retrieve Azure VM user data from instance metadata service.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Debug "Attempting to retrieve Azure VM user data..."
        
        $uri = "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text"
        $headers = @{ "Metadata" = "true" }
        
        # Short timeout as this only works from within Azure VMs
        $userData = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -TimeoutSec 3 -ErrorAction Stop
        
        if ($userData) {
            Write-Debug "User data retrieved successfully"
            # userData comes Base64 encoded; decode to UTF8 string
            try {
                $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($userData))
                return $decoded
            } catch {
                Write-Warning "Failed to decode user data: $($_.Exception.Message)"
                return $userData  # Return raw if decode fails
            }
        } else {
            Write-Debug "No user data present"
            return $null
        }
    } catch [System.Net.WebException] {
        Write-Debug "Not running in Azure VM or metadata service unavailable"
        return $null
    } catch {
        Write-Warning "Failed to retrieve VM userData: $($_.Exception.Message)"
        return $null
    }
}

function Initialize-Authentication {
    <#
    .SYNOPSIS
        Initializes authentication for Azure ARM and Microsoft Graph APIs.
    #>
    [CmdletBinding()]
    param()
    
    Write-Output "Initializing authentication..."
    
    # Validate provided tokens before proceeding with authentication
    if ((-not $UseCurrentUser) -and (-not $UseAzureCLI) -and ($AccessTokenARM -or $AccessTokenGraph)) {
        Write-Output "`nValidating provided tokens..."
        
        $tokenValidationErrors = @()
        $currentUtc = [DateTime]::UtcNow
        
        # Validate ARM token
        if ($AccessTokenARM) {
            try {
                Write-Output "  Checking ARM token..."
                
                # Decode JWT token to check expiration and audience
                $tokenParts = $AccessTokenARM.Split('.')
                if ($tokenParts.Length -ge 2) {
                    # Handle URL-safe Base64 encoding and padding for JWT tokens
                    $payload = $tokenParts[1]
                    
                    # Convert URL-safe Base64 to standard Base64
                    $payload = $payload.Replace('-', '+').Replace('_', '/')
                    
                    # Add padding if needed for base64 decoding
                    $paddingNeeded = 4 - ($payload.Length % 4)
                    if ($paddingNeeded -ne 4) {
                        $payload += "=" * $paddingNeeded
                    }
                    
                    try {
                        $payloadBytes = [System.Convert]::FromBase64String($payload)
                        $decodedPayload = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
                    } catch {
                        # Fallback: try without padding (some JWT implementations vary)
                        $originalPayload = $tokenParts[1].Replace('-', '+').Replace('_', '/')
                        $payloadBytes = [System.Convert]::FromBase64String($originalPayload)
                        $decodedPayload = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
                    }
                    $claims = $decodedPayload | ConvertFrom-Json
                    
                    # Check expiration
                    if ($claims.exp) {
                        $expirationUtc = [DateTimeOffset]::FromUnixTimeSeconds($claims.exp).UtcDateTime
                        
                        if ($expirationUtc -le $currentUtc) {
                            Write-Host "    ARM Token Expiration: $($expirationUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC" -NoNewline
                            Write-Host " [EXPIRED]" -ForegroundColor Red
                            $tokenValidationErrors += "ARM token has EXPIRED (expired at $($expirationUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC, current time is $($currentUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC)"
                        } else {
                            Write-Output "    ARM Token Expiration: $($expirationUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
                            $timeRemaining = $expirationUtc - $currentUtc
                            Write-Output "    ARM Token Status: Valid (expires in $([math]::Round($timeRemaining.TotalMinutes, 1)) minutes)"
                        }
                    }
                    
                    # Check audience (should be Azure Resource Manager)
                    if ($claims.aud) {
                        Write-Output "    ARM Token Audience: $($claims.aud)"
                        $validArmAudiences = @(
                            "https://management.azure.com/",
                            "https://management.core.windows.net/",
                            "https://management.azure.com"
                        )
                        
                        if ($claims.aud -notin $validArmAudiences) {
                            $tokenValidationErrors += "ARM token has INVALID AUDIENCE '$($claims.aud)'. Expected one of: $($validArmAudiences -join ', ')"
                        } else {
                            Write-Output "    ARM Token Audience: Valid"
                        }
                    }
                    
                    # Show tenant info
                    if ($claims.tid) {
                        $Script:ARMTokenTenant = $claims.tid
                        Write-Output "    ARM Token Tenant: $($claims.tid)"
                    }
                }
            } catch {
                $tokenValidationErrors += "Failed to parse ARM token: $($_.Exception.Message)"
            }
        }
        
        # Validate Graph token  
        if ($AccessTokenGraph) {
            try {
                Write-Output "  Checking Graph token..."
                
                # Decode JWT token to check expiration and audience
                $tokenParts = $AccessTokenGraph.Split('.')
                if ($tokenParts.Length -ne 3) {
                    $tokenValidationErrors += "Graph token format invalid: JWT tokens must have 3 parts (header.payload.signature), found $($tokenParts.Length) parts"
                    throw "Invalid JWT token format"
                }
                
                try {
                    # Add padding if needed for base64 decoding
                    $payload = $tokenParts[1]
                    $paddingNeeded = 4 - ($payload.Length % 4)
                    if ($paddingNeeded -ne 4) {
                        $payload += "=" * $paddingNeeded
                    }
                    
                    $decodedPayload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))
                    $claims = $decodedPayload | ConvertFrom-Json
                } catch {
                    $tokenValidationErrors += "Graph token payload invalid: Unable to decode JWT payload - $($_.Exception.Message)"
                    throw "Failed to decode JWT payload"
                }
                    
                    # Check expiration
                    if ($claims.exp) {
                        $expirationUtc = [DateTimeOffset]::FromUnixTimeSeconds($claims.exp).UtcDateTime
                        
                        if ($expirationUtc -le $currentUtc) {
                            Write-Host "    Graph Token Expiration: $($expirationUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC" -NoNewline
                            Write-Host " [EXPIRED]" -ForegroundColor Red
                            $tokenValidationErrors += "Graph token has EXPIRED (expired at $($expirationUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC, current time is $($currentUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC)"
                        } else {
                            Write-Output "    Graph Token Expiration: $($expirationUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
                            $timeRemaining = $expirationUtc - $currentUtc
                            Write-Output "    Graph Token Status: Valid (expires in $([math]::Round($timeRemaining.TotalMinutes, 1)) minutes)"
                        }
                    }
                    
                    # Check audience (should be Microsoft Graph)
                    if ($claims.aud) {
                        Write-Output "    Graph Token Audience: $($claims.aud)"
                        $validGraphAudiences = @(
                            "00000003-0000-0000-c000-000000000000",
                            "https://graph.microsoft.com",
                            "https://graph.microsoft.com/"
                        )
                        
                        if ($claims.aud -notin $validGraphAudiences) {
                            $tokenValidationErrors += "Graph token has INVALID AUDIENCE '$($claims.aud)'. Expected one of: $($validGraphAudiences -join ', ')"
                        } else {
                            Write-Output "    Graph Token Audience: Valid"
                        }
                    }
                    
                    # Check scopes and roles (comprehensive permission analysis)
                    $tokenScopes = @()
                    $tokenRoles = @()
                    $permissionIssues = @()
                    
                    # Check delegated permissions (scopes) - for user tokens
                    if ($claims.scp) {
                        $tokenScopes = $claims.scp -split ' '
                        Write-Output "    Graph Token Scopes (Delegated): $($claims.scp)"
                    }
                    
                    # Check application permissions (roles) - for app-only tokens
                    if ($claims.roles) {
                        $tokenRoles = $claims.roles
                        Write-Output "    Graph Token Roles (Application): $($claims.roles -join ', ')"
                    }
                    
                    # Analyze permission coverage
                    $permissionIssues = @()  # Initialize array for tracking permission issues
                    $basicScopes = @('User.Read', 'User.ReadBasic.All')
                    $advancedScopes = @('User.Read.All', 'Directory.Read.All', 'Group.Read.All', 'Application.Read.All')
                    
                    # Check for basic read permissions (including advanced scopes that provide basic read)
                    $basicScopeFound = ($tokenScopes | Where-Object { $_ -in $basicScopes }).Count -gt 0
                    $advancedUserRead = ($tokenScopes | Where-Object { $_ -in @('User.Read.All', 'Directory.Read.All') }).Count -gt 0
                    $hasBasicRead = $basicScopeFound -or $advancedUserRead
                    
                    $hasAdvancedRead = ($tokenScopes | Where-Object { $_ -in $advancedScopes }).Count -gt 0
                    $hasAppPermissions = $tokenRoles.Count -gt 0
                    
                    Write-Output "    Permission Analysis:"
                    if ($hasBasicRead) {
                        if ($advancedUserRead) {
                            $providingScopes = $tokenScopes | Where-Object { $_ -in @('User.Read.All', 'Directory.Read.All') }
                            Write-Output "      Basic User Read: Available (via $($providingScopes -join ', '))"
                        } else {
                            Write-Output "      Basic User Read: Available"
                        }
                    } else {
                        Write-Output "      Basic User Read: MISSING (User.Read, User.ReadBasic.All, User.Read.All, or Directory.Read.All required)"
                        $permissionIssues += "Missing basic user read permission"
                    }
                    
                    if ($hasAdvancedRead) {
                        Write-Output "      Advanced Directory Read: Available"
                    } else {
                        Write-Output "      Advanced Directory Read: MISSING (Directory.Read.All recommended)"
                        $permissionIssues += "Missing advanced directory read permissions"
                    }
                    
                    if ($hasAppPermissions) {
                        Write-Output "      Application Permissions: Available ($($tokenRoles.Count) roles)"
                    } else {
                        Write-Output "      Application Permissions: None (delegated token)"
                    }
                    
            # Add specific permission errors if basic read is missing
            if (-not $hasBasicRead -and -not $hasAppPermissions) {
                $tokenValidationErrors += "Graph token lacks basic permissions. No User.Read scope or application roles found."
                
                # Show permission guidance immediately for permission issues
                Write-Output ""
                Write-Warning "CRITICAL: Graph token has insufficient permissions for basic operations"
                Show-GraphPermissionGuidance -MissingPermission "Basic permissions" -ErrorContext "Token validation - missing User.Read or application roles"
            } elseif ($hasBasicRead -and $hasAdvancedRead -and $tokenRoles.Count -eq 0) {
                # Token has good delegated permissions - this is fine for interactive flows
                Write-Output ""
                Write-Output "NOTE: Token uses delegated permissions (interactive/user context)."
                Write-Output "This is normal for user-interactive authentication flows."
            } elseif ($permissionIssues.Count -gt 0) {
                # Show guidance for missing advanced permissions
                Write-Output ""
                Write-Warning "Graph token has limited permissions - some operations may fail"
                Write-Output "Permission issues detected:"
                foreach ($issue in $permissionIssues) {
                    Write-Output "  - $issue"
                }
                Write-Output ""
                Write-Output "For comprehensive enumeration, consider obtaining a token with additional permissions."
                Write-Output "Run this command to see detailed guidance:"
                Write-Output "  Show-GraphPermissionGuidance -MissingPermission 'Advanced permissions' -ErrorContext 'Enhanced enumeration'"
            }
            
            # Store permission analysis for later use
            $Script:GraphTokenPermissions = @{
                Scopes = $tokenScopes
                Roles = $tokenRoles
                HasBasicRead = $hasBasicRead
                HasAdvancedRead = $hasAdvancedRead
                HasAppPermissions = $hasAppPermissions
                Issues = $permissionIssues
            }
            
            # Show tenant info
            if ($claims.tid) {
                $Script:GraphTokenTenant = $claims.tid
                Write-Output "    Graph Token Tenant: $($claims.tid)"
            }
        } catch {
                $tokenValidationErrors += "Failed to parse Graph token: $($_.Exception.Message)"
            }
        }
        
        # Analyze validation errors to determine if we can proceed
        if ($tokenValidationErrors.Count -gt 0) {
            Write-Output "`nTOKEN VALIDATION ISSUES DETECTED:"
            foreach ($validationerror in $tokenValidationErrors) {
                Write-Output "  ERROR: $validationerror"
            }
            
            # Check if we can proceed with Graph-only mode
            $armTokenErrors = $tokenValidationErrors | Where-Object { $_ -like "*ARM token*" }
            $graphTokenErrors = $tokenValidationErrors | Where-Object { $_ -like "*Graph token*" }
            
            $canProceedWithGraphOnly = ($AccessTokenGraph -and $graphTokenErrors.Count -eq 0 -and $armTokenErrors.Count -gt 0)
            
            if ($canProceedWithGraphOnly) {
                Write-Output "`nGRAPH-ONLY MODE AVAILABLE:"
                Write-Output "  Your Graph token is valid and can be used for Azure AD enumeration."
                Write-Output "  ARM token issues will prevent Azure resource enumeration."
                Write-Output ""
                Write-Output "OPTIONS:"
                Write-Output "  1. Continue with Graph-only enumeration (Azure AD users, groups, apps)"
                Write-Output "  2. Get a fresh ARM token for full enumeration"
                Write-Output "  3. Add -GraphOnly parameter to skip this prompt in future"
                Write-Output ""
                
                # Check if GraphOnly parameter was specified
                if ($GraphOnly) {
                    Write-Output "GraphOnly parameter specified - proceeding with Graph-only enumeration..."
                    # Clear ARM token to prevent further ARM attempts
                    $Script:AccessTokenARM = $null
                    $Script:PerformARMChecks = $false
                    return
                }
                
                # Check if user wants to proceed (in interactive mode) or auto-proceed in non-interactive
                if ([Environment]::UserInteractive -and -not $env:CI) {
                    $response = Read-Host "Continue with Graph-only enumeration? (Y/N)"
                    if ($response -match '^[Yy]') {
                        Write-Output "Proceeding with Graph-only enumeration..."
                        # Clear ARM token to prevent further ARM attempts
                        $Script:AccessTokenARM = $null
                        $Script:PerformARMChecks = $false
                        return
                    } else {
                        Write-Output "User chose to abort. Please update your ARM token and try again."
                    }
                } else {
                    # Non-interactive mode - auto-proceed with Graph-only
                    Write-Output "Auto-proceeding with Graph-only enumeration (non-interactive mode)..."
                    # Clear ARM token to prevent further ARM attempts
                    $Script:AccessTokenARM = $null
                    $Script:PerformARMChecks = $false
                    return
                }
            }
            
            Write-Output "`nRESOLUTION STEPS:"
            Write-Output "  1. Get fresh tokens that haven't expired"
            Write-Output "  2. Ensure ARM token audience is: https://management.azure.com/"
            Write-Output "  3. Ensure Graph token audience is: 00000003-0000-0000-c000-000000000000"
            Write-Output "  4. Use PowerShell to get valid tokens:"
            Write-Output "     Connect-AzAccount"
            Write-Output "     Connect-MgGraph -Scopes 'User.Read','Directory.Read.All'"
            Write-Output "  5. Or use Azure CLI: az login --allow-no-subscriptions"
            Write-Output ""
            
            throw "Token validation failed. Please update your tokens and try again."
        }
        
        Write-Output "  Token validation completed successfully."
        
        # Check for tenant mismatches after successful token validation
        Test-TenantMismatch
    }
    
    if ($UseCurrentUser) {
        Write-Verbose "Using current user authentication"

        
        # Initialize Azure context
        try {
            $context = Get-AzContext -ErrorAction SilentlyContinue
            if (-not $context) {
                Write-Output "No Azure context found. Attempting to connect..."
                Connect-AzAccount -ErrorAction Stop | Out-Null
                Write-Output "Successfully connected to Azure"
            } else {
                Write-Verbose "Using existing Azure context: $($context.Account.Id)"
            }
            
            # Get ARM token
            $token = Get-AzAccessTokenFromContext
            if ($token) {
                $Script:AccessTokenARM = $token
                $Script:AuthenticationStatus.AzContext = $true
                $Script:AuthenticationStatus.ARMToken = $true
                Write-Verbose "ARM access token acquired successfully"
            } else {
                Write-Warning "Could not acquire ARM access token from current Az context."
                
                # Offer to fix authentication automatically (if interactive mode is enabled)
                if (-not $NoInteractiveAuth) {
                    $fixResult = Invoke-AuthenticationFix -FixType "ARM" -Interactive
                if ($fixResult.Success -and $fixResult.ARMFixed) {
                    # Try to get the token again after successful authentication
                    try {
                        $tokenRetry = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop
                        if ($tokenRetry -and $tokenRetry.Token) {
                            if ($tokenRetry.Token -is [System.Security.SecureString]) {
                                $plainToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenRetry.Token))
                                $AccessTokenARM = $plainToken
                            } else {
                                $AccessTokenARM = $tokenRetry.Token
                            }
                            $Script:AuthenticationStatus.AzContext = $true
                            $Script:AuthenticationStatus.ARMToken = $true
                            Write-Host "✅ ARM access token successfully retrieved after authentication fix!" -ForegroundColor Green
                        }
                    } catch {
                        Write-Verbose "Could not retrieve ARM token even after authentication fix: $($_.Exception.Message)"
                    }
                }
                }
            }
            
        } catch {
            Write-Warning "Failed to initialize Azure context: $($_.Exception.Message)"
        }
        
        # Initialize Microsoft Graph context
        try {
            if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
                $contextMg = Get-MgContext -ErrorAction SilentlyContinue
                if ($contextMg) {
                    $Script:AuthenticationStatus.GraphContext = $true
                    $Script:AuthenticationStatus.GraphToken = $true
                    Write-Verbose "Using existing Microsoft Graph context"
                } else {
                    # Try to connect using current user credentials
                    Write-Verbose "Attempting to connect to Microsoft Graph..."
                    try {
                        Connect-MgGraph -Scopes "User.Read", "Directory.Read.All" -NoWelcome -ErrorAction Stop | Out-Null
                        $contextMg = Get-MgContext -ErrorAction SilentlyContinue
                        if ($contextMg) {
                            $Script:AuthenticationStatus.GraphContext = $true
                            $Script:AuthenticationStatus.GraphToken = $true
                            Write-Verbose "Successfully connected to Microsoft Graph"
                        }
                    } catch {
                        Write-Verbose "Could not connect to Microsoft Graph: $($_.Exception.Message)"
                        Write-Verbose "Graph features will be limited to ARM API calls only."
                        
                        # Offer to fix Microsoft Graph authentication (if interactive mode is enabled)
                        if (-not $NoInteractiveAuth) {
                            $graphFixResult = Invoke-AuthenticationFix -FixType "Graph" -Interactive
                            if ($graphFixResult.Success -and $graphFixResult.GraphFixed) {
                            # Check if connection is now available
                            $contextMgRetry = Get-MgContext -ErrorAction SilentlyContinue
                            if ($contextMgRetry) {
                                $Script:AuthenticationStatus.GraphContext = $true
                                $Script:AuthenticationStatus.GraphToken = $true
                                Write-Host "✅ Microsoft Graph connection successfully established after authentication fix!" -ForegroundColor Green
                            }
                        }
                        }
                    }
                }
            } else {
                Write-Verbose "Microsoft Graph module not available. Graph features will be limited."
            }
        } catch {
            Write-Warning "Failed to initialize Microsoft Graph context: $($_.Exception.Message)"
        }
        
        # Check Azure CLI availability for additional capabilities (like owned objects)
        try {
            $azVersion = az version 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Verbose "Azure CLI is available for additional capabilities"
                
                # Check if user is already logged in
                try {
                    $accountShow = az account show --output json 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        $accountInfo = $accountShow | ConvertFrom-Json -ErrorAction SilentlyContinue
                        if ($accountInfo -and $accountInfo.id) {
                            Write-Verbose "Azure CLI user is authenticated: $($accountInfo.user.name)"
                            # Set Azure CLI as available since user is authenticated
                            $Script:AuthenticationStatus.AzureCLI = $true
                            Write-Verbose "Azure CLI authentication status set to true"
                        } else {
                            Write-Verbose "Azure CLI available but authentication check failed"
                        }
                    } else {
                        Write-Verbose "Azure CLI available but user may need to authenticate"
                    }
                } catch {
                    Write-Verbose "Azure CLI available but user authentication check failed: $($_.Exception.Message)"
                }
            } else {
                Write-Verbose "Azure CLI version check failed"
            }
        } catch {
            Write-Verbose "Azure CLI not available: $($_.Exception.Message)"
        }
        
    } else {
        Write-Verbose "Using token-based authentication"
        
        # Validate and set ARM token
        if ($AccessTokenARM) {
            $Script:AuthenticationStatus.ARMToken = $true
            Write-Verbose "ARM token provided"
            
            # Try to connect Az context with token
            try {
                if ($AccessTokenGraph -and $Script:PerformGraphChecks) {
                    Connect-AzAccount -AccessToken $AccessTokenARM -MicrosoftGraphAccessToken $AccessTokenGraph -AccountId $AccountId -ErrorAction Stop | Out-Null
                    $Script:AuthenticationStatus.AzContext = $true
                    $Script:AuthenticationStatus.GraphContext = $true
                    $Script:AuthenticationStatus.GraphToken = $true
                    Write-Verbose "Connected with both ARM and Graph tokens"
                } else {
                    Connect-AzAccount -AccessToken $AccessTokenARM -AccountId $AccountId -ErrorAction Stop | Out-Null
                    $Script:AuthenticationStatus.AzContext = $true
                    Write-Verbose "Connected with ARM token only"
                }
            } catch {
                Write-Warning "Failed to establish Az context with provided tokens: $($_.Exception.Message)"
                # Even if Az context fails, we can still use the token for direct API calls
                Write-Verbose "Will attempt direct ARM API calls with provided token"
            }
        }
        
        # Automatically attempt to retrieve resource-specific tokens for enhanced functionality
        if ($Script:AuthenticationStatus.AzContext -or $AccessTokenARM) {
            Write-Verbose "Attempting to retrieve resource-specific tokens (Storage & Key Vault)..."
            try {
                $resourceTokens = Get-ResourceSpecificTokens -TokenType "Both"
                if ($resourceTokens.StorageToken) {
                    Write-Verbose "Storage token retrieved successfully - enhanced blob download capabilities available"
                }
                if ($resourceTokens.KeyVaultToken) {
                    Write-Verbose "Key Vault token retrieved successfully - enhanced secret access capabilities available"
                }
            } catch {
                Write-Verbose "Resource-specific token retrieval failed (non-critical): $($_.Exception.Message)"
            }
        }
        
        # Set Graph token if provided separately
        if ($AccessTokenGraph -and -not $Script:AuthenticationStatus.GraphToken -and $Script:PerformGraphChecks) {
            try {
                # Try connecting to Graph directly
                if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
                    Connect-MgGraph -AccessToken ($AccessTokenGraph | ConvertTo-SecureString -AsPlainText -Force) -ErrorAction Stop
                    $Script:AuthenticationStatus.GraphContext = $true
                    $Script:AuthenticationStatus.GraphToken = $true
                    Write-Verbose "Connected to Microsoft Graph with provided token"
                }
            } catch {
                Write-Warning "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
                # Still set the token for direct API calls
                $Script:AuthenticationStatus.GraphToken = $true
                Write-Verbose "Will use Graph token for direct API calls"
            }
        } elseif ($AccessTokenGraph -and -not $Script:PerformGraphChecks) {
            # Graph token provided but not needed
            $Script:AuthenticationStatus.GraphToken = $true
            Write-Verbose "Graph token provided but Graph checks not requested"
        }
    }
    
    if ($Script:UseAzureCLI) {
        Write-Verbose "Using Azure CLI authentication"
        
        # Initialize Azure CLI with service principal
        $cliAuth = Initialize-AzureCLI -ServicePrincipalId $ServicePrincipalId -ServicePrincipalSecret $ServicePrincipalSecret -TenantId $TenantId
        
        if ($cliAuth.Success) {
            Write-Output "Successfully authenticated via Azure CLI"
            Write-Output "  Tenant: $($cliAuth.AuthenticationDetails.TenantId)"
            Write-Output "  Service Principal: $($cliAuth.AuthenticationDetails.ServicePrincipalId)"
            Write-Output "  Has Subscriptions: $($cliAuth.AuthenticationDetails.HasSubscriptions)"
            
            # Acquire access tokens from Azure CLI
            Write-Verbose "Acquiring access tokens from Azure CLI..."
            $tokenResult = Get-AccessTokenFromAzureCLI -TokenType "Both"
            
            if ($tokenResult.Success) {
                if ($tokenResult.ARMToken) {
                    $Script:AccessTokenARM = $tokenResult.ARMToken
                    $Script:AuthenticationStatus.ARMToken = $true
                    Write-Verbose "ARM access token acquired from Azure CLI"
                }
                
                if ($tokenResult.GraphToken) {
                    $Script:AccessTokenGraph = $tokenResult.GraphToken
                    $Script:AuthenticationStatus.GraphToken = $true
                    Write-Verbose "Graph access token acquired from Azure CLI"
                }
                
                $Script:AuthenticationStatus.AzureCLI = $true
                Write-Verbose "Azure CLI tokens acquired successfully"
                
                # Check if service principal has subscription access
                Write-Verbose "Checking subscription access..."
                $subscriptionCheck = az account show --query "name" --output tsv 2>&1
                if ($LASTEXITCODE -ne 0 -or $subscriptionCheck -eq "N/A(tenant level account)") {
                    Write-Warning "Service principal has tenant-level access but no subscription permissions."
                    Write-Warning "ARM enumeration will fail with 401 Unauthorized errors."
                    Write-Warning ""
                    Write-Warning "To fix this:"
                    Write-Warning "1. Grant the service principal Reader role on target subscription(s)"
                    Write-Warning "2. Use Azure Portal: Subscriptions > Access control (IAM) > Add role assignment"
                    Write-Warning "3. Or use CLI: az role assignment create --role Reader --assignee $ServicePrincipalId --scope /subscriptions/SUBSCRIPTION_ID"
                    Write-Warning ""
                    
                    # Test Graph API permissions
                    $graphPermTest = az rest --method GET --url "https://graph.microsoft.com/v1.0/users?`$top=1" 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        Write-Verbose "Graph API test failed: $graphPermTest"
                        Write-Warning "Graph API also requires application permissions:"
                        Write-Warning "1. Go to Azure AD > App registrations > find your app"
                        Write-Warning "2. Add API permissions > Microsoft Graph > Application permissions"
                        Write-Warning "3. Add: Directory.Read.All, User.Read.All, Group.Read.All"
                        Write-Warning "4. Grant admin consent"
                        Write-Warning ""
                    }
                }
            } else {
                Write-Warning "Failed to acquire tokens from Azure CLI: $($tokenResult.Error)"
                # Still mark as successful if CLI auth worked, tokens might be retrieved later
                $Script:AuthenticationStatus.AzureCLI = $true
            }
        } else {
            throw "Azure CLI authentication failed: $($cliAuth.Error)"
        }
    }
    
    if ($Script:ServicePrincipalMode) {
        Write-Verbose "Using Azure PowerShell Service Principal authentication"
        
        # Initialize Azure PowerShell with service principal
        $spAuth = Initialize-AzServicePrincipal -ApplicationId $ApplicationId -ClientSecret $ClientSecret -TenantId $TenantId
        
        if ($spAuth.Success) {
            Write-Output "Successfully authenticated via Azure PowerShell Service Principal"
            Write-Output "  Tenant: $($spAuth.AuthenticationDetails.TenantId) ($($spAuth.AuthenticationDetails.TenantDisplayName))"
            Write-Output "  Application: $($spAuth.AuthenticationDetails.ApplicationId)"
            Write-Output "  Has Subscriptions: $($spAuth.AuthenticationDetails.HasSubscriptions) ($($spAuth.AuthenticationDetails.SubscriptionCount) subscriptions)"
            
            # Mark Azure context as available
            $Script:AuthenticationStatus.AzContext = $true
            
            # Acquire access tokens from Azure PowerShell
            Write-Verbose "Acquiring access tokens from Azure PowerShell..."
            $tokenResult = Get-AzAccessTokensFromServicePrincipal
            
            if ($tokenResult.Success) {
                if ($tokenResult.ARMToken) {
                    $Script:AccessTokenARM = $tokenResult.ARMToken
                    $Script:AuthenticationStatus.ARMToken = $true
                    Write-Verbose "ARM access token acquired from Azure PowerShell"
                }
                
                if ($tokenResult.GraphToken) {
                    $Script:AccessTokenGraph = $tokenResult.GraphToken
                    $Script:AuthenticationStatus.GraphToken = $true
                    Write-Verbose "Graph access token acquired from Azure PowerShell"
                }
                
                # Store Key Vault token for enhanced Key Vault access
                if ($tokenResult.KeyVaultToken) {
                    $Script:KeyVaultToken = $tokenResult.KeyVaultToken
                    Write-Verbose "Key Vault access token acquired from Azure PowerShell"
                }
                
                Write-Verbose "Azure PowerShell Service Principal tokens acquired successfully"
                
                # Provide guidance if no subscription access
                if (-not $spAuth.AuthenticationDetails.HasSubscriptions) {
                    Write-Warning "Service principal has no subscription access."
                    Write-Warning "ARM enumeration will be limited to tenant-level resources only."
                    Write-Warning ""
                    Write-Warning "To enable subscription enumeration:"
                    Write-Warning "1. Grant the service principal Reader role on target subscription(s)"
                    Write-Warning "2. Use Azure Portal: Subscriptions > Access control (IAM) > Add role assignment"
                    Write-Warning "3. Or use PowerShell: New-AzRoleAssignment -RoleDefinitionName Reader -ServicePrincipalName $ApplicationId -Scope /subscriptions/SUBSCRIPTION_ID"
                    Write-Warning ""
                }
                
                # Test Graph API permissions
                if ($tokenResult.GraphToken) {
                    try {
                        $testUrl = "https://graph.microsoft.com/v1.0/organization"
                        $testHeaders = @{ Authorization = "Bearer $($tokenResult.GraphToken)" }
                        $testResult = Invoke-RestMethod -Uri $testUrl -Headers $testHeaders -Method Get -ErrorAction Stop
                        Write-Verbose "Graph API test successful - service principal has Graph permissions (found $($testResult.value.Count) organizations)"
                    } catch {
                        Write-Warning "Graph API test failed: $($_.Exception.Message)"
                        Write-Warning "Service principal may need additional Graph API permissions:"
                        Write-Warning "1. Go to Azure AD > App registrations > find your application"
                        Write-Warning "2. Add API permissions > Microsoft Graph > Application permissions"
                        Write-Warning "3. Add: Directory.Read.All, User.Read.All, Group.Read.All, Application.Read.All"
                        Write-Warning "4. Grant admin consent for these permissions"
                        Write-Warning ""
                    }
                }
            } else {
                Write-Warning "Failed to acquire tokens from Azure PowerShell: $($tokenResult.Error)"
                # Authentication context is still valid even if token extraction failed
                Write-Verbose "Azure PowerShell context is established but token extraction failed"
            }
        } else {
            throw "Azure PowerShell Service Principal authentication failed: $($spAuth.Error)"
        }
    }
    
    # Report authentication status
    Write-Output "Authentication Status:"
    Write-Output "  Azure ARM API: $($Script:AuthenticationStatus.ARMToken)"
    Write-Output "  Microsoft Graph API: $($Script:AuthenticationStatus.GraphToken)"
    Write-Output "  Azure Context: $($Script:AuthenticationStatus.AzContext)"
    Write-Output "  Graph Context: $($Script:AuthenticationStatus.GraphContext)"
    
    # Run Graph diagnostics if Graph checks are enabled and there are authentication issues
    if ($Script:PerformGraphChecks -and $VerbosePreference -eq 'Continue') {
        Test-GraphAccess
    }
    
    # Validate that required authentication is available for requested checks
    $authenticationErrors = @()
    
    # For ARM checks, if using CurrentUser mode and ARM isn't available, just disable ARM checks
    if ($Script:PerformARMChecks -and -not $Script:AuthenticationStatus.ARMToken) {
        if ($UseCurrentUser) {
            Write-Warning "ARM authentication not available in current user mode. ARM resource enumeration will be skipped."
            $Script:PerformARMChecks = $false
        } else {
            $authenticationErrors += "ARM token required for ARM resource enumeration but not available."
        }
    }
    
    # For Graph checks, if using CurrentUser mode and Graph isn't available, just disable Graph checks
    if ($Script:PerformGraphChecks -and -not $Script:AuthenticationStatus.GraphToken) {
        if ($UseCurrentUser) {
            Write-Warning "Graph authentication not available in current user mode. Graph enumeration will be skipped."
            $Script:PerformGraphChecks = $false
        } else {
            $authenticationErrors += "Graph token required for Graph user enumeration but not available."
        }
    }
    
    if ($authenticationErrors.Count -gt 0) {
        $errorMessage = "Authentication validation failed:`n" + ($authenticationErrors -join "`n")
        throw $errorMessage
    }
    
    # Check if we have at least one working authentication method
    if (-not $Script:AuthenticationStatus.ARMToken -and -not $Script:AuthenticationStatus.GraphToken) {
        if ($UseCurrentUser) {
            $errorMessage = @"
No valid authentication method available in current user mode.

Possible solutions:
1. Connect to Azure PowerShell: Connect-AzAccount
2. Connect to Microsoft Graph: Connect-MgGraph -Scopes 'User.Read','Directory.Read.All'
3. Use Azure CLI: az login
4. Use token-based authentication instead:
   .\Enum-AzureARM.ps1 -AccessTokenARM `"<arm-token>`" -AccessTokenGraph `"<graph-token>`" -AccountId `"<account-id>`"
5. Use service principal authentication:
   .\Enum-AzureARM.ps1 -UseServicePrincipal -ApplicationId `"<app-id>`" -ClientSecret `"<secret>`" -TenantId `"<tenant-id>`"
"@
            throw $errorMessage
        } else {
            throw "No valid authentication method available. Cannot proceed with enumeration."
        }
    }
}

#endregion

#region Main Execution

try {
    Initialize-Authentication
} catch {
    Write-Error "Authentication failed: $($_.Exception.Message)"
    exit 1
}

# Initialize output object
$output = [ordered]@{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
    ScriptVersion = "2.0"
    AuthenticationMethod = if ($UseCurrentUser) { "CurrentUser" } else { "Token" }
}

# Try to retrieve Azure VM User Data (only works when running inside Azure VM)
Write-Output "`nChecking for Azure VM User Data..."
try {
    $userDataDecoded = Get-AzureVMUserData
    if ($userDataDecoded) {
        Write-Output "Azure VM User Data Found:"
        Write-Output $userDataDecoded
        $output.UserData = $userDataDecoded
    } else {
        Write-Output "No Azure VM User Data found or not running in Azure VM."
    }
} catch {
    Write-Debug "Error retrieving VM user data: $($_.Exception.Message)"
    Write-Output "Unable to retrieve Azure VM User Data (not running in Azure VM)."
}

# Retrieve user details from Microsoft Graph
# Enhanced Graph API enumeration - attempt even with limited authentication
if ($Script:PerformGraphChecks -or $AccessTokenGraph) {
    Write-Output "`nRetrieving user details from Microsoft Graph..."
    try {
        # Try using Microsoft Graph PowerShell cmdlets first (more reliable)
        $userDetails = $null
        if (Get-Command Get-MgUser -ErrorAction SilentlyContinue) {
            try {
                $mgUser = Get-MgUser -UserId "me" -Property "Id,DisplayName,UserPrincipalName,Mail,JobTitle,Department" -ErrorAction Stop
                if ($mgUser) {
                    $userDetails = @{
                        id = $mgUser.Id
                        displayName = $mgUser.DisplayName
                        userPrincipalName = $mgUser.UserPrincipalName
                        mail = $mgUser.Mail
                        jobTitle = $mgUser.JobTitle
                        department = $mgUser.Department
                    }
                    Write-Verbose "Retrieved user details using Get-MgUser cmdlet"
                }
            } catch {
                Write-Verbose "Get-MgUser failed: $($_.Exception.Message)"
            }
        }
        
        # Fallback to REST API if cmdlet failed
        if (-not $userDetails) {
            if ($AccessTokenGraph) {
                # Use direct REST API call with provided Graph token
                try {
                    Write-Verbose "Attempting Graph API call with provided token"
                    $headers = @{
                        'Authorization' = "Bearer $AccessTokenGraph"
                        'Content-Type' = 'application/json'
                    }
                    $userDetails = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers -Method GET
                    Write-Verbose "Successfully retrieved user details via direct Graph API call"
                } catch {
                    Write-Verbose "Direct Graph API call failed: $($_.Exception.Message)"
                    Write-Output "Failed to retrieve user details via Graph API: $($_.Exception.Message)"
                }
            } else {
                # Try using the Graph request function
                try {
                    $userDetails = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/me"
                } catch {
                    Write-Verbose "Graph request function failed: $($_.Exception.Message)"
                    Write-Output "Failed to retrieve user details via Graph request function: $($_.Exception.Message)"
                }
            }
        }
        
        if ($userDetails) {
            Write-Output "User Details Retrieved: $($userDetails.displayName) ($($userDetails.userPrincipalName))"
            $output.UserDetails = $userDetails
            
            # Extract additional information from the Graph token itself
            if ($AccessTokenGraph) {
                try {
                    Write-Output "`nAnalyzing Graph token claims and permissions..."
                    
                    # Decode the JWT token to extract claims
                    $tokenParts = $AccessTokenGraph.Split('.')
                    if ($tokenParts.Length -ge 2) {
                        # Add padding if needed for base64 decoding
                        $payload = $tokenParts[1]
                        $paddingNeeded = 4 - ($payload.Length % 4)
                        if ($paddingNeeded -ne 4) {
                            $payload += "=" * $paddingNeeded
                        }
                        
                        $decodedPayload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))
                        $tokenClaims = $decodedPayload | ConvertFrom-Json
                        
                        # Extract useful token information
                        $tokenAnalysis = @{
                            Audience = $tokenClaims.aud
                            Issuer = $tokenClaims.iss
                            TenantId = $tokenClaims.tid
                            AppId = $tokenClaims.appid
                            Scopes = if ($tokenClaims.scp) { $tokenClaims.scp } else { "Not specified" }
                            Roles = if ($tokenClaims.roles) { $tokenClaims.roles } else { @() }
                            IssuedAt = if ($tokenClaims.iat) { [DateTimeOffset]::FromUnixTimeSeconds($tokenClaims.iat).ToString() } else { "Unknown" }
                            ExpiresAt = if ($tokenClaims.exp) { [DateTimeOffset]::FromUnixTimeSeconds($tokenClaims.exp).ToString() } else { "Unknown" }
                            Subject = $tokenClaims.sub
                            AuthenticationMethod = $tokenClaims.amr
                        }
                        
                        $output.GraphTokenAnalysis = $tokenAnalysis
                        
                        Write-Output "  Token Audience: $($tokenAnalysis.Audience)"
                        Write-Output "  Token Tenant ID: $($tokenAnalysis.TenantId)"
                        Write-Output "  Token App ID: $($tokenAnalysis.AppId)"
                        Write-Output "  Token Scopes: $($tokenAnalysis.Scopes)"
                        Write-Output "  Token Expires: $($tokenAnalysis.ExpiresAt)"
                        
                        if ($tokenAnalysis.Roles -and $tokenAnalysis.Roles.Count -gt 0) {
                            Write-Output "  Token Roles: $($tokenAnalysis.Roles -join ', ')"
                        }
                        
                        # Try some alternative Graph API calls that might work with limited permissions
                        Write-Output "`nTrying alternative Graph API endpoints with current permissions..."
                        
                        # Try to get current user's photo/profile picture
                        try {
                            $photoResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/photo" -Headers $headers -Method GET
                            if ($photoResponse) {
                                Write-Output "  User photo metadata accessible"
                                $output.UserDetails | Add-Member -NotePropertyName "HasPhoto" -NotePropertyValue $true -Force
                            }
                        } catch {
                            Write-Verbose "  User photo not accessible: $($_.Exception.Message)"
                        }
                        
                        # Try to get user's OneDrive information
                        try {
                            $driveResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/drive" -Headers $headers -Method GET
                            if ($driveResponse) {
                                Write-Output "  OneDrive information accessible"
                                $output.UserDetails | Add-Member -NotePropertyName "OneDriveInfo" -NotePropertyValue @{
                                    Id = $driveResponse.id
                                    DriveType = $driveResponse.driveType
                                    Owner = $driveResponse.owner.user.displayName
                                } -Force
                            }
                        } catch {
                            Write-Verbose "  OneDrive not accessible: $($_.Exception.Message)"
                        }
                        
                        # Try to get user's recent activities
                        try {
                            $activitiesResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/activities/recent" -Headers $headers -Method GET
                            if ($activitiesResponse -and $activitiesResponse.value) {
                                Write-Output "  Recent activities accessible ($($activitiesResponse.value.Count) activities)"
                                $output.UserDetails | Add-Member -NotePropertyName "RecentActivitiesCount" -NotePropertyValue $activitiesResponse.value.Count -Force
                            }
                        } catch {
                            Write-Verbose "  Recent activities not accessible: $($_.Exception.Message)"
                        }
                        
                        # Try to get user's calendar events
                        try {
                            $calendarResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/events?`$top=5" -Headers $headers -Method GET
                            if ($calendarResponse -and $calendarResponse.value) {
                                Write-Output "  Calendar events accessible ($($calendarResponse.value.Count) recent events)"
                                $output.UserDetails | Add-Member -NotePropertyName "CalendarEventsCount" -NotePropertyValue $calendarResponse.value.Count -Force
                            }
                        } catch {
                            Write-Verbose "  Calendar events not accessible: $($_.Exception.Message)"
                        }
                        
                        # Try to get user's messages
                        try {
                            $messagesResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/messages?`$top=5&`$select=id,subject,from,receivedDateTime" -Headers $headers -Method GET
                            if ($messagesResponse -and $messagesResponse.value) {
                                Write-Output "  Email messages accessible ($($messagesResponse.value.Count) recent messages)"
                                $output.UserDetails | Add-Member -NotePropertyName "EmailMessagesCount" -NotePropertyValue $messagesResponse.value.Count -Force
                            }
                        } catch {
                            Write-Verbose "  Email messages not accessible: $($_.Exception.Message)"
                        }
                        
                    }
                } catch {
                    Write-Verbose "Failed to analyze Graph token: $($_.Exception.Message)"
                }
            }
            
            # Update filename if it was set to pending and we now have UPN
            if ($OutputFile -like "*pending_*_AzureResources.json") {
                $timestamp = Get-Date -Format "yyyyMMddHHmmss"
                $upn = $userDetails.userPrincipalName -replace '[\\/:*?"<>|]', '_'  # Sanitize filename
                $newFilename = "${upn}_${timestamp}_AzureResources.json"
                $OutputFile = Join-Path "Results" $newFilename
                Write-Verbose "Updated filename with UPN: $OutputFile"
            }
            
            # Try to gather additional Graph API information
            Write-Output "`nGathering additional information from Microsoft Graph..."
            
            # Get tenant information
            try {
                if ($AccessTokenGraph) {
                    $headers = @{
                        'Authorization' = "Bearer $AccessTokenGraph"
                        'Content-Type' = 'application/json'
                    }
                    $tenantInfo = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/organization" -Headers $headers -Method GET
                } else {
                    $tenantInfo = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/organization"
                }
                if ($tenantInfo -and $tenantInfo.value -and $tenantInfo.value.Count -gt 0) {
                    $orgInfo = $tenantInfo.value[0]
                    $output.OrganizationDetails = @{
                        DisplayName = $orgInfo.displayName
                        Id = $orgInfo.id
                        TenantType = $orgInfo.tenantType
                        VerifiedDomains = $orgInfo.verifiedDomains
                        Country = $orgInfo.countryLetterCode
                        CreatedDateTime = $orgInfo.createdDateTime
                    }
                    Write-Verbose "Retrieved organization details: $($orgInfo.displayName)"
                }
            }
            catch {
                Write-Verbose "Could not retrieve organization details: $($_.Exception.Message)"
            }
            
            # Get user's group memberships
            try {
                if ($AccessTokenGraph) {
                    $headers = @{
                        'Authorization' = "Bearer $AccessTokenGraph"
                        'Content-Type' = 'application/json'
                    }
                    $groups = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/memberOf" -Headers $headers -Method GET
                } else {
                    $groups = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/me/memberOf"
                }
                if ($groups -and $groups.value) {
                    $output.UserGroups = $groups.value | ForEach-Object {
                        @{
                            Id = $_.id
                            DisplayName = $_.displayName
                            ObjectType = $_.'@odata.type'
                            Description = $_.description
                        }
                    }
                    Write-Verbose "Found $($output.UserGroups.Count) group memberships"
                }
            }
            catch {
                Write-Verbose "Could not retrieve group memberships: $($_.Exception.Message)"
            }
            
            # Get directory roles (if user has any)
            try {
                if ($AccessTokenGraph) {
                    $headers = @{
                        'Authorization' = "Bearer $AccessTokenGraph"
                        'Content-Type' = 'application/json'
                    }
                    $directoryRoles = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/memberOf/microsoft.graph.directoryRole" -Headers $headers -Method GET
                } else {
                    $directoryRoles = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/me/memberOf/microsoft.graph.directoryRole"
                }
                if ($directoryRoles -and $directoryRoles.value) {
                    $output.DirectoryRoles = $directoryRoles.value | ForEach-Object {
                        @{
                            Id = $_.id
                            DisplayName = $_.displayName
                            Description = $_.description
                            RoleTemplateId = $_.roleTemplateId
                        }
                    }
                    Write-Verbose "Found $($output.DirectoryRoles.Count) directory roles"
                }
            }
            catch {
                Write-Verbose "Could not retrieve directory roles: $($_.Exception.Message)"
            }
            
            # Try to get accessible applications (if permissions allow)
            try {
                if ($AccessTokenGraph) {
                    $headers = @{
                        'Authorization' = "Bearer $AccessTokenGraph"
                        'Content-Type' = 'application/json'
                    }
                    $applications = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications?`$top=100" -Headers $headers -Method GET
                } else {
                    $applications = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/applications?`$top=100"
                }
                
                if ($applications -and $applications.value) {
                    Write-Output "  Found $($applications.value.Count) applications. Retrieving comprehensive details..."
                    
                    $output.Applications = @()
                    $appCount = 0
                    
                    foreach ($app in $applications.value) {
                        $appCount++
                        Write-Progress -Activity "Processing Applications" -Status "Processing application: $($app.displayName) ($appCount/$($applications.value.Count))" -PercentComplete (($appCount / $applications.value.Count) * 100)
                        
                        try {
                            Write-Debug "Getting detailed information for application: $($app.displayName) (ID: $($app.id))"
                            $detailedAppInfo = Get-ApplicationDetails -ApplicationId $app.id -AccessTokenGraph $AccessTokenGraph
                            $output.Applications += $detailedAppInfo
                        } catch {
                            Write-Warning "Failed to get detailed info for application $($app.displayName): $($_.Exception.Message)"
                            # Fall back to basic info if detailed retrieval fails
                            $output.Applications += @{
                                Id = $app.id
                                AppId = $app.appId
                                DisplayName = $app.displayName
                                PublisherDomain = $app.publisherDomain
                                CreatedDateTime = $app.createdDateTime
                                Error = "Failed to retrieve detailed info: $($_.Exception.Message)"
                            }
                        }
                    }
                    
                    Write-Progress -Activity "Processing Applications" -Completed
                    Write-Output "  Application enumeration completed. Retrieved detailed information for $($output.Applications.Count) applications."
                }
            }
            catch {
                Write-Verbose "Could not retrieve applications (insufficient permissions): $($_.Exception.Message)"
            }
            
            Write-Output "Microsoft Graph enumeration completed successfully."
            
            # Get detailed Azure AD information
            Write-Output "`nRetrieving comprehensive Azure Active Directory details..."
            try {
                $aadDetails = Get-AzureADDetails -AccessTokenGraph $AccessTokenGraph
                if ($aadDetails -and -not $aadDetails.Error) {
                    $output.AzureADDetails = $aadDetails
                    Write-Output "  Conditional Access Policies: $($aadDetails.ConditionalAccessPolicies.Count) ($($aadDetails.SecurityAnalysis.EnabledConditionalAccessPolicies) enabled)"
                    Write-Output "  Service Principals: $($aadDetails.ServicePrincipals.Count) (including $($aadDetails.ManagedIdentities.Count) managed identities)"
                    Write-Output "  Enterprise Applications: $($aadDetails.EnterpriseApplications.Count)"
                    Write-Output "  Named Locations: $($aadDetails.NamedLocations.Count) ($($aadDetails.SecurityAnalysis.TrustedNamedLocationsCount) trusted)"
                    if ($aadDetails.SecurityAnalysis.RequiresMFAPolicies) {
                        Write-Host "  Security: MFA policies detected" -ForegroundColor Green
                    } else {
                        Write-Host "  Security: No MFA policies found" -ForegroundColor Yellow
                    }
                    if ($aadDetails.SecurityAnalysis.HasBlockLegacyAuthPolicies) {
                        Write-Host "  Security: Legacy auth blocking detected" -ForegroundColor Green
                    } else {
                        Write-Host "  Security: No legacy auth blocking found" -ForegroundColor Yellow
                    }
                } else {
                    Write-Warning "Could not retrieve Azure AD details: $($aadDetails.Error)"
                }
            } catch {
                Write-Warning "Failed to retrieve Azure AD details: $($_.Exception.Message)"
            }
        } else {
            Write-Output "`nCould not retrieve basic user details from Microsoft Graph."
            Write-Output "This usually indicates:"
            Write-Output "  - The Graph token has expired or is invalid"
            Write-Output "  - The token doesn't have 'User.Read' permission"
            Write-Output "  - The token audience is incorrect (should be 00000003-0000-0000-c000-000000000000)"
            Write-Output ""
            Write-Output "To get a proper Graph token:"
            Write-Output "  1. PowerShell: Connect-MgGraph -Scopes 'User.Read','Directory.Read.All'"
            Write-Output "  2. Azure CLI: az login --allow-no-subscriptions"
            Write-Output "  3. Get new token with: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        }
    } catch {
        Write-Warning "Failed to retrieve user details: $($_.Exception.Message)"
        Write-Verbose "You may need to run 'Connect-MgGraph -Scopes User.Read' manually before running the script."
        
        # Even if Graph enumeration fails, try to extract basic tenant info from tokens
        Write-Output "`nAttempting to extract tenant information from available tokens..."
        if ($AccessTokenARM -and $output.TenantId -eq "Unknown") {
            try {
                # Try to extract tenant ID from ARM token
                $tokenParts = $AccessTokenARM.Split('.')
                if ($tokenParts.Length -ge 2) {
                    # Decode the payload (with padding fix)
                    $payload = $tokenParts[1]
                    $payloadLength = $payload.Length
                    $paddingNeeded = 4 - ($payloadLength % 4)
                    if ($paddingNeeded -ne 4) {
                        $payload += "=" * $paddingNeeded
                    }
                    $decodedBytes = [System.Convert]::FromBase64String($payload)
                    $decodedJson = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
                    $claims = $decodedJson | ConvertFrom-Json
                    
                    if ($claims.tid) {
                        $output.TenantId = $claims.tid
                        Write-Output "Extracted tenant ID from ARM token: $($claims.tid)"
                        
                        # Also try to get tenant name/issuer
                        if ($claims.iss) {
                            $output.TenantIssuer = $claims.iss
                            Write-Verbose "Tenant issuer: $($claims.iss)"
                        }
                    }
                }
            } catch {
                Write-Verbose "Could not extract tenant information from ARM token: $($_.Exception.Message)"
            }
        }
        
        if ($AccessTokenGraph -and -not $output.UserDetails) {
            try {
                # Try to extract basic user info from Graph token
                $tokenParts = $AccessTokenGraph.Split('.')
                if ($tokenParts.Length -ge 2) {
                    $payload = $tokenParts[1]
                    $payloadLength = $payload.Length
                    $paddingNeeded = 4 - ($payloadLength % 4)
                    if ($paddingNeeded -ne 4) {
                        $payload += "=" * $paddingNeeded
                    }
                    $decodedBytes = [System.Convert]::FromBase64String($payload)
                    $decodedJson = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
                    $claims = $decodedJson | ConvertFrom-Json
                    
                    if ($claims.upn -or $claims.unique_name -or $claims.preferred_username) {
                        # Use PowerShell 5.1 compatible null coalescing logic
                        $userPrincipal = if ($claims.upn) { $claims.upn } elseif ($claims.unique_name) { $claims.unique_name } else { $claims.preferred_username }
                        
                        $extractedUserInfo = @{
                            upn = $userPrincipal
                            name = $claims.name
                            tid = $claims.tid
                            source = "JWT Claims"
                        }
                        $output.ExtractedUserInfo = $extractedUserInfo
                        Write-Output "Extracted user info from Graph token: $($extractedUserInfo.upn)"
                        
                        # Update tenant ID if we got it from Graph token
                        if ($claims.tid -and $output.TenantId -eq "Unknown") {
                            $output.TenantId = $claims.tid
                        }
                    }
                }
            } catch {
                Write-Verbose "Could not extract user information from Graph token: $($_.Exception.Message)"
            }
        }
    }
} elseif ($Script:PerformGraphChecks) {
    Write-Output "Microsoft Graph checks requested but Graph access not available - user details will be limited."
    
    # Still try to extract information from tokens even without Graph API access
    Write-Output "`nAttempting to extract available information from tokens..."
    if ($AccessTokenARM) {
        try {
            $tokenParts = $AccessTokenARM.Split('.')
            if ($tokenParts.Length -ge 2) {
                $payload = $tokenParts[1]
                $payloadLength = $payload.Length
                $paddingNeeded = 4 - ($payloadLength % 4)
                if ($paddingNeeded -ne 4) {
                    $payload += "=" * $paddingNeeded
                }
                $decodedBytes = [System.Convert]::FromBase64String($payload)
                $decodedJson = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
                $claims = $decodedJson | ConvertFrom-Json
                
                # Use PowerShell 5.1 compatible null coalescing logic
                $userPrincipal = if ($claims.upn) { $claims.upn } elseif ($claims.unique_name) { $claims.unique_name } else { $claims.preferred_username }
                
                $extractedInfo = @{
                    TenantId = $claims.tid
                    Upn = $userPrincipal
                    Name = $claims.name
                    AppId = $claims.appid
                    Issuer = $claims.iss
                    Source = "ARM Token Claims"
                }
                $output.ExtractedTokenInfo = $extractedInfo
                
                if ($claims.tid) {
                    $output.TenantId = $claims.tid
                    Write-Output "Extracted tenant ID: $($claims.tid)"
                }
                if ($extractedInfo.Upn) {
                    Write-Output "Extracted UPN: $($extractedInfo.Upn)"
                }
            }
        } catch {
            Write-Verbose "Could not extract token information: $($_.Exception.Message)"
        }
    }
} else {
    Write-Output "Microsoft Graph checks not requested - skipping user details retrieval."
}

# Main Azure resource enumeration
if ($Script:PerformARMChecks -and $Script:AuthenticationStatus.ARMToken) {
    $separator = "=" * 60
    Write-Output ""
    Write-Output $separator
    Write-Output "STARTING AZURE RESOURCE ENUMERATION"
    Write-Output $separator
    
    try {
        $context = Get-AzContext -ErrorAction SilentlyContinue
        $tenantId = $null
        $subscriptionId = $null
        $subscriptionName = $null
        $subscriptionSelected = $false
        
        # Check if there's an existing valid context that user might want to keep
        if ($null -ne $context -and $context.Subscription -and $context.Subscription.Id) {
            $tenantId = $context.Tenant.Id
            $subscriptionId = $context.Subscription.Id
            $subscriptionName = $context.Subscription.Name
            
            # Check if this might be an unexpected/test context
            $isTestSubscription = $subscriptionName -like "*test*" -or $subscriptionName -like "*demo*" -or $subscriptionName -like "*trial*"
            
            if ($isTestSubscription -and -not $NoInteractiveAuth) {
                Write-Warning "Current Azure context is using subscription '$subscriptionName' - this appears to be a test/demo subscription"
                Write-Output "Tenant ID: $tenantId"
                Write-Output "Subscription: $subscriptionName ($subscriptionId)"
                Write-Output ""
                
                $continueWithCurrent = Request-UserConfirmation -Message "Do you want to continue with this subscription?"
                if (-not $continueWithCurrent) {
                    Write-Host "🔄 Let's select a different subscription..." -ForegroundColor Cyan
                    $context = $null  # Force subscription selection
                }
            } elseif ($isTestSubscription -and $NoInteractiveAuth) {
                Write-Warning "Using test/demo subscription '$subscriptionName' in non-interactive mode"
                Write-Output "Use -AllowNoSubscription to bypass subscription selection, or run interactively to choose a different subscription"
                Write-Output "Tenant ID: $tenantId"
                Write-Output "Subscription: $subscriptionName ($subscriptionId)"
            } else {
                Write-Output "Using Azure PowerShell Context:"
                Write-Output "Tenant ID: $tenantId"
                Write-Output "Subscription: $subscriptionName ($subscriptionId)"
            }
            $subscriptionSelected = $true
        }
        
        # If no valid context or user chose to select different subscription
        if ($null -eq $context -or -not $subscriptionSelected) {
            Write-Host "🔍 No valid Azure subscription context found or subscription change requested..." -ForegroundColor Yellow
            
            # Use the subscription selection function
            $selectionResult = Select-AzureSubscription -AccessToken $Script:AccessTokenARM -AllowNoSubscription:$AllowNoSubscription -NonInteractive:$NoInteractiveAuth
            
            if ($selectionResult.UserCancelled) {
                Write-Host "❌ Operation cancelled by user. Exiting..." -ForegroundColor Red
                return
            }
            
            if (-not $selectionResult.Success -and -not $AllowNoSubscription) {
                Write-Host "❌ No subscription selected and -AllowNoSubscription not specified. Exiting..." -ForegroundColor Red
                Write-Host "Use -AllowNoSubscription to continue with Graph-only enumeration." -ForegroundColor Gray
                return
            }
            
            if ($selectionResult.SubscriptionId) {
                $tenantId = $selectionResult.TenantId
                $subscriptionId = $selectionResult.SubscriptionId
                $subscriptionName = $selectionResult.SubscriptionName
                
                Write-Output ""
                Write-Output "Selected subscription details:"
                Write-Output "Tenant ID: $tenantId"
                Write-Output "Subscription: $subscriptionName ($subscriptionId)"
                
                # Try to set the context for future operations
                try {
                    Set-AzContext -SubscriptionId $subscriptionId -TenantId $tenantId -ErrorAction SilentlyContinue | Out-Null
                    Write-Verbose "Successfully set Azure context to selected subscription"
                } catch {
                    Write-Verbose "Could not set Azure context, but will continue with selected subscription info"
                }
            } else {
                # No subscription selected - Graph-only mode
                Write-Output "Continuing with Graph-only enumeration (no Azure subscription access)"
                
                # Try to get tenant from token claims
                try {
                    $tokenPayload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($accessToken.Split('.')[1]))
                    $claims = $tokenPayload | ConvertFrom-Json
                    $tenantId = $claims.tid
                    Write-Output "Tenant ID: $tenantId (from token)"
                } catch {
                    $tenantId = "Unknown"
                    Write-Output "Tenant ID: Unknown"
                }
                
                $subscriptionId = "None"
                $subscriptionName = "Graph-Only Mode"
            }
        }
        
        # Set output properties
        $output.TenantId = $tenantId
        $output.SubscriptionId = $subscriptionId
        $output.SubscriptionName = $subscriptionName
        
        # Continue with enumeration if we have valid identifiers
        if ($subscriptionId -and $subscriptionId -ne "None") {
            # First, test subscription access before attempting full enumeration
            Write-Output "`nTesting subscription access..."
            Write-Verbose "Testing access to subscription: $subscriptionId"
            $testUri = "https://management.azure.com/subscriptions/$subscriptionId" + "?api-version=2022-12-01"
            Write-Verbose "Test URI: $testUri"
            try {
                $accessTest = Invoke-ARMRequest -Uri $testUri
                if ($accessTest -and $accessTest.subscriptionId) {
                    Write-Output "Subscription access confirmed: $($accessTest.displayName)"
                } else {
                    throw "Unable to access subscription information"
                }
            } catch {
                if ($_.Exception.Message -like "*401*" -or $_.Exception.Message -like "*Unauthorized*") {
                    Write-Warning "ACCESS DENIED: No permissions to access subscription '$subscriptionName' ($subscriptionId)"
                    Write-Warning "This may be a cached context from a previous session. Consider running:"
                    Write-Warning "  Clear-AzContext -Force"
                    Write-Warning "  Set-AzContext -SubscriptionId <your-target-subscription>"
                    Write-Warning "Skipping ARM resource enumeration due to access restrictions."
                    $Script:PerformARMChecks = $false
                    return
                } else {
                    Write-Warning "Failed to test subscription access: $($_.Exception.Message)"
                    Write-Warning "Continuing with limited enumeration..."
                }
            }
            
            # Enumerate resources using Azure Resource Graph API (advanced query)
            Write-Output "`nRetrieving resources via Azure Resource Graph API..."
            $batchRequestBody = @{
                requests = @(
                    @{
                        content = @{
                            query = "resources|project id,name,type,kind,location,subscriptionId,resourceGroup,tags,extendedLocation|sort by (tolower(tostring(name))) asc"
                            options = @{
                                "`$top" = 1000
                                "`$skip" = 0
                                "`$skipToken" = ""
                                "resultFormat" = "table"
                            }
                            subscriptions = @($subscriptionId)
                        }
                        httpMethod = "POST"
                        requestHeaderDetails = @{
                            commandName = "fx.All.initial load"
                        }
                        url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
                    }
                )
            }
            
            $resourceGraphResponse = Invoke-ARMRequest -Uri "https://management.azure.com/batch?api-version=2020-06-01" -Method "POST" -Body $batchRequestBody
            
            $resources = $null
            if ($resourceGraphResponse -and $resourceGraphResponse.responses -and $resourceGraphResponse.responses.Count -gt 0) {
                $rgResponse = $resourceGraphResponse.responses[0]
                if ($rgResponse.content -and $rgResponse.content.data) {
                    Write-Output "Successfully retrieved resources via Resource Graph API"
                    
                    # Convert Resource Graph table format to standard ARM format
                    $resources = @{ value = @() }
                    $columns = $rgResponse.content.data.columns
                    $rows = $rgResponse.content.data.rows
                    
                    foreach ($row in $rows) {
                        $resourceObj = @{}
                        for ($i = 0; $i -lt $columns.Count; $i++) {
                            $resourceObj[$columns[$i].name] = $row[$i]
                        }
                        $resources.value += [PSCustomObject]$resourceObj
                    }
                    
                    Write-Output "Resource Graph returned $($resources.value.Count) resources with enhanced metadata"
                } else {
                    Write-Warning "Resource Graph API returned empty or invalid response"
                }
            } else {
                Write-Warning "Resource Graph API call failed, falling back to standard ARM API"
            }
            
            # Fallback to standard ARM API if Resource Graph failed
            if (-not $resources) {
                Write-Output "`nFalling back to standard ARM resources API..."
                $resources = Invoke-ARMRequest -Uri "https://management.azure.com/subscriptions/$subscriptionId/resources?api-version=2021-04-01"
            }
            
            if ($resources -and $resources.value) {
                $output.Resources = $resources.value
                $resourceCount = $resources.value.Count
                Write-Output "Successfully retrieved $resourceCount resources"
                
                # Display resource summary
                $resourceSummary = $resources.value | Group-Object type | Sort-Object Count -Descending | Select-Object Name, Count
                Write-Output "`nResource Summary:"
                $resourceSummary | Format-Table -AutoSize | Out-String | Write-Output
            } else {
                Write-Warning "No resources found or failed to retrieve resources"
                $output.Resources = @()
            }
            
            # Enumerate resource groups
            Write-Output "`nRetrieving resource groups..."
            $rgs = Invoke-ARMRequest -Uri "https://management.azure.com/subscriptions/$subscriptionId/resourcegroups?api-version=2021-04-01"
            $output.ResourceGroups = @()
            
            if ($rgs -and $rgs.value) {
                $rgCount = $rgs.value.Count
                Write-Output "Found $rgCount resource groups"
                
                # Process each resource group
                $rgProgress = 0
                foreach ($rg in $rgs.value) {
                    $rgProgress++
                    Write-Progress -Activity "Processing Resource Groups" -Status "Processing $($rg.name) ($rgProgress/$rgCount)" -PercentComplete (($rgProgress / $rgCount) * 100)
                    
                    Write-Verbose "Processing resource group: $($rg.name)"
                    
                    # Get deployments for this resource group
                    $deployments = Invoke-ARMRequest -Uri "https://management.azure.com$($rg.id)/providers/Microsoft.Resources/deployments?api-version=2021-04-01"
                    $deploymentsSimple = @()
                    
                    if ($deployments -and $deployments.value) {
                        Write-Debug "Found $($deployments.value.Count) deployments in $($rg.name)"
                        foreach ($d in $deployments.value) {
                            $deploymentDetails = [pscustomobject]@{
                                Name = $d.name
                                Timestamp = $d.properties.timestamp
                                Status = $d.properties.provisioningState
                                Parameters = @{}
                                ParametersExtracted = $false
                                ParameterExtractionError = $null
                            }
                            
                            # Try to extract deployment parameters using Azure PowerShell cmdlet
                            if ($Script:AuthenticationStatus.AzContext) {
                                try {
                                    Write-Verbose "Extracting parameters for deployment: $($d.name)"
                                    $azDeployment = Get-AzResourceGroupDeployment -ResourceGroupName $rg.name -Name $d.name -ErrorAction SilentlyContinue
                                    if ($azDeployment -and $azDeployment.Parameters) {
                                        $extractedParams = @{}
                                        $azDeployment.Parameters.GetEnumerator() | ForEach-Object {
                                            $extractedParams[$_.Key] = $_.Value.Value
                                        }
                                        $deploymentDetails.Parameters = $extractedParams
                                        $deploymentDetails.ParametersExtracted = $true
                                        Write-Debug "Successfully extracted $($extractedParams.Keys.Count) parameters from deployment $($d.name)"
                                    }
                                } catch {
                                    $deploymentDetails.ParameterExtractionError = $_.Exception.Message
                                    Write-Verbose "Failed to extract parameters for deployment $($d.name): $($_.Exception.Message)"
                                }
                            }
                            
                            $deploymentsSimple += $deploymentDetails
                        }
                    }

                    # Get role assignments for this resource group
                    $roles = Invoke-ARMRequest -Uri "https://management.azure.com$($rg.id)/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
                    $rolesSimple = @()
                    
                    if ($roles -and $roles.value) {
                        Write-Debug "Found $($roles.value.Count) role assignments in $($rg.name)"
                        foreach ($r in $roles.value) {
                            $roleName = Get-RoleDefinitionName -RoleDefinitionId $r.properties.roleDefinitionId
                            $principalName = Get-PrincipalName -PrincipalId $r.properties.principalId
                            
                            $rolesSimple += [pscustomobject]@{
                                PrincipalId = $r.properties.principalId
                                PrincipalName = $principalName
                                RoleDefinitionId = $r.properties.roleDefinitionId
                                RoleName = $roleName
                                Scope = $r.properties.scope
                            }
                        }
                    }

                    # Add resource group to output
                    $output.ResourceGroups += [pscustomobject]@{
                        Name = $rg.name
                        Location = $rg.location
                        ProvisioningState = $rg.properties.provisioningState
                        DeploymentCount = $deploymentsSimple.Count
                        RoleAssignmentCount = $rolesSimple.Count
                        Deployments = $deploymentsSimple
                        RoleAssignments = $rolesSimple
                    }
                }
                
                Write-Progress -Activity "Processing Resource Groups" -Completed
                Write-Output "Processed $rgCount resource groups successfully"
            } else {
                Write-Warning "No resource groups found"
            }

            
            # Get subscription-level role assignments
            Write-Output "`nRetrieving subscription role assignments..."
            $subsRoles = Invoke-ARMRequest -Uri "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
            $subsRolesSimple = @()
            
            if ($subsRoles -and $subsRoles.value) {
                Write-Output "Found $($subsRoles.value.Count) subscription role assignments"
                
                foreach ($r in $subsRoles.value) {
                    $roleName = Get-RoleDefinitionName -RoleDefinitionId $r.properties.roleDefinitionId
                    $principalName = Get-PrincipalName -PrincipalId $r.properties.principalId
                    
                    $subsRolesSimple += [pscustomobject]@{
                        PrincipalId = $r.properties.principalId
                        PrincipalName = $principalName
                        RoleDefinitionId = $r.properties.roleDefinitionId
                        RoleName = $roleName
                        Scope = $r.properties.scope
                    }
                }
            } else {
                Write-Warning "No subscription role assignments found or access denied"
            }
            
            # Check if there were principal lookup issues
            $failedPrincipalLookups = $subsRolesSimple | Where-Object { 
                $_.PrincipalName -in @("No Graph Access", "Principal Not Found", "Lookup Failed", "Error Retrieving Principal") 
            }
            
            if ($failedPrincipalLookups.Count -gt 0) {
                Write-Warning "`nPrincipal Lookup Issues Detected:"
                Write-Host "  - $($failedPrincipalLookups.Count) principals could not be resolved to display names" -ForegroundColor Yellow
                Write-Host "  - This is usually due to insufficient Microsoft Graph permissions" -ForegroundColor Yellow
                Write-Host "`nTo resolve these issues:" -ForegroundColor Cyan
                Write-Host "  1. Ensure you have a valid Microsoft Graph token with 'Directory.Read.All' permission" -ForegroundColor Gray
                Write-Host "  2. Run: Connect-MgGraph -Scopes 'User.Read','Directory.Read.All'" -ForegroundColor Gray
                Write-Host "  3. Or provide a Graph token with: -AccessTokenGraph `$graphToken" -ForegroundColor Gray
                Write-Host "  4. Use -Verbose flag for detailed Graph authentication diagnostics`n" -ForegroundColor Gray
            }
            
            $output.SubscriptionRoleAssignments = $subsRolesSimple

            
            # Initialize detailed resource collections
            $vmDetails = @()
            $publicIpDetails = @()
            $functionDetails = @()
            $webAppDetails = @()
            $storageDetails = @()
            $kvDetails = @()
            $automationDetails = @()
            $cosmosDetails = @()
            $appConfigDetails = @()
            $nsgDetails = @()
            $vnetDetails = @()
            $sqlServerDetails = @()
            $blueprintDetails = @()

            # Process detailed resource information
            if ($resources -and $resources.value -and $resources.value.Count -gt 0) {
                Write-Output "`nRetrieving detailed resource information..."
                $resourceProgress = 0
                $totalResources = $resources.value.Count
                
                foreach ($r in $resources.value) {
                    $resourceProgress++
                    if ($resourceProgress % 10 -eq 0 -or $resourceProgress -eq $totalResources) {
                        Write-Progress -Activity "Processing Resource Details" -Status "Processing $($r.name) ($resourceProgress/$totalResources)" -PercentComplete (($resourceProgress / $totalResources) * 100)
                    }
                    
                    try {
                        switch -Wildcard ($r.type) {
                            "Microsoft.Network/networkSecurityGroups" {
                                Write-Debug "Processing NSG: $($r.name)"
                                $nsgInfo = Get-NetworkSecurityGroupDetails -NsgId $r.id -NsgName $r.name
                                if ($nsgInfo -and -not $nsgInfo.Error) {
                                    $nsgDetails += $nsgInfo
                                    Write-Output "  Found NSG: $($r.name) with $($nsgInfo.SecurityRules.Count) custom rules and $($nsgInfo.SecurityAnalysis.RulesOpenToInternet) rules open to internet"
                                }
                            }
                            "Microsoft.Network/virtualNetworks" {
                                Write-Debug "Processing VNet: $($r.name)"
                                $vnetInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($r.id)?api-version=2022-07-01"
                                if ($vnetInfo) {
                                    $vnetDetail = [pscustomobject]@{
                                        Name = $vnetInfo.name
                                        Location = $vnetInfo.location
                                        ResourceGroup = ($vnetInfo.id -split '/')[4]
                                        AddressSpace = $vnetInfo.properties.addressSpace.addressPrefixes -join ", "
                                        SubnetCount = if ($vnetInfo.properties.subnets) { $vnetInfo.properties.subnets.Count } else { 0 }
                                        Subnets = @()
                                        Peerings = @()
                                        DnsServers = $vnetInfo.properties.dhcpOptions.dnsServers -join ", "
                                    }
                                    
                                    # Get subnet details
                                    if ($vnetInfo.properties.subnets) {
                                        $vnetDetail.Subnets = $vnetInfo.properties.subnets | ForEach-Object {
                                            @{
                                                Name = $_.name
                                                AddressPrefix = $_.properties.addressPrefix
                                                AvailableIPs = if ($_.properties.availableIpAddressCount) { $_.properties.availableIpAddressCount } else { "Unknown" }
                                                NSG = if ($_.properties.networkSecurityGroup) { ($_.properties.networkSecurityGroup.id -split '/')[-1] } else { "None" }
                                                RouteTable = if ($_.properties.routeTable) { ($_.properties.routeTable.id -split '/')[-1] } else { "None" }
                                            }
                                        }
                                    }
                                    
                                    # Get peering details
                                    if ($vnetInfo.properties.virtualNetworkPeerings) {
                                        $vnetDetail.Peerings = $vnetInfo.properties.virtualNetworkPeerings | ForEach-Object {
                                            @{
                                                Name = $_.name
                                                PeeringState = $_.properties.peeringState
                                                RemoteVirtualNetwork = ($_.properties.remoteVirtualNetwork.id -split '/')[-1]
                                                AllowVirtualNetworkAccess = $_.properties.allowVirtualNetworkAccess
                                                AllowForwardedTraffic = $_.properties.allowForwardedTraffic
                                                AllowGatewayTransit = $_.properties.allowGatewayTransit
                                                UseRemoteGateways = $_.properties.useRemoteGateways
                                            }
                                        }
                                    }
                                    
                                    $vnetDetails += $vnetDetail
                                }
                            }
                            "Microsoft.Sql/servers" {
                                Write-Debug "Processing SQL Server: $($r.name)"
                                $sqlInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($r.id)?api-version=2022-05-01-preview"
                                if ($sqlInfo) {
                                    $sqlDetail = [pscustomobject]@{
                                        Name = $sqlInfo.name
                                        Location = $sqlInfo.location
                                        ResourceGroup = ($sqlInfo.id -split '/')[4]
                                        Version = $sqlInfo.properties.version
                                        State = $sqlInfo.properties.state
                                        FullyQualifiedDomainName = $sqlInfo.properties.fullyQualifiedDomainName
                                        AdminLogin = $sqlInfo.properties.administratorLogin
                                        PublicNetworkAccess = $sqlInfo.properties.publicNetworkAccess
                                        Databases = @()
                                        FirewallRules = @()
                                        AuditingEnabled = $false
                                        ThreatDetectionEnabled = $false
                                    }
                                    
                                    # Get databases
                                    try {
                                        $dbsInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($r.id)/databases?api-version=2022-05-01-preview" -SuppressWarnings $true
                                        if ($dbsInfo -and $dbsInfo.value) {
                                            $sqlDetail.Databases = $dbsInfo.value | Where-Object { $_.name -ne "master" } | ForEach-Object {
                                                @{
                                                    Name = $_.name
                                                    Edition = $_.properties.edition
                                                    ServiceTier = $_.properties.requestedServiceObjectiveName
                                                    MaxSizeBytes = $_.properties.maxSizeBytes
                                                    Status = $_.properties.status
                                                    Collation = $_.properties.collation
                                                    CreationDate = $_.properties.creationDate
                                                }
                                            }
                                        }
                                    } catch {
                                        Write-Debug "Could not retrieve databases for SQL server $($r.name): $($_.Exception.Message)"
                                    }
                                    
                                    # Get firewall rules
                                    try {
                                        $fwRulesInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($r.id)/firewallRules?api-version=2022-05-01-preview" -SuppressWarnings $true
                                        if ($fwRulesInfo -and $fwRulesInfo.value) {
                                            $sqlDetail.FirewallRules = $fwRulesInfo.value | ForEach-Object {
                                                @{
                                                    Name = $_.name
                                                    StartIpAddress = $_.properties.startIpAddress
                                                    EndIpAddress = $_.properties.endIpAddress
                                                    IsAzureServiceRule = ($_.properties.startIpAddress -eq "0.0.0.0" -and $_.properties.endIpAddress -eq "0.0.0.0")
                                                }
                                            }
                                        }
                                    } catch {
                                        Write-Debug "Could not retrieve firewall rules for SQL server $($r.name): $($_.Exception.Message)"
                                    }
                                    
                                    $sqlServerDetails += $sqlDetail
                                }
                            }
                            "Microsoft.Compute/virtualMachines" {
                                Write-Debug "Processing VM: $($r.name)"
                                $vmInfo = Get-VirtualMachineDetails -VmId $r.id -VmName $r.name
                                if ($vmInfo -and -not $vmInfo.Error) {
                                    $vmDetails += $vmInfo
                                    Write-Output "  Found VM: $($r.name) ($($vmInfo.OsType)) with $($vmInfo.Extensions.Count) extensions and $($vmInfo.NetworkInterfaces.Count) NICs"
                                }
                            }
                            "Microsoft.Network/publicIPAddresses" {
                                Write-Debug "Processing Public IP: $($r.name)"
                                $ipInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($r.id)?api-version=2022-05-01"
                                if ($ipInfo) {
                                    $publicIpDetails += [pscustomobject]@{
                                        Name = $ipInfo.name
                                        IpAddress = $ipInfo.properties.ipAddress
                                        Location = $ipInfo.location
                                        AllocationMethod = $ipInfo.properties.publicIPAllocationMethod
                                        ResourceGroup = ($ipInfo.id -split '/')[4]
                                    }
                                }
                            }
                            "Microsoft.Web/sites" {
                                Write-Debug "Processing Web App: $($r.name)"
                                $webAppInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($r.id)?api-version=2021-02-01"
                                if ($webAppInfo) {
                                    $webAppDetail = [pscustomobject]@{
                                        Name = $webAppInfo.name
                                        Location = $webAppInfo.location
                                        State = $webAppInfo.properties.state
                                        HostNames = ($webAppInfo.properties.hostNames -join ", ")
                                        Kind = $webAppInfo.kind
                                        DefaultHostName = $webAppInfo.properties.defaultHostName
                                        ResourceGroup = ($webAppInfo.id -split '/')[4]
                                    }
                                    
                                    $webAppDetails += $webAppDetail
                                    
                                    # Check if it's a Function App
                                    if ($webAppInfo.kind -like "*functionapp*") {
                                        $functionDetails += $webAppDetail
                                    }
                                }
                            }
                            "Microsoft.Storage/storageAccounts" {
                                Write-Debug "Processing Storage Account: $($r.name)"
                                $storageInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($r.id)?api-version=2022-05-01"
                                if ($storageInfo) {
                                    # Get basic storage info
                                    $basicStorageInfo = [pscustomobject]@{
                                        Name = $storageInfo.name
                                        Location = $storageInfo.location
                                        Kind = $storageInfo.kind
                                        Sku = $storageInfo.sku.name
                                        AccessTier = $storageInfo.properties.accessTier
                                        AllowBlobPublicAccess = $storageInfo.properties.allowBlobPublicAccess
                                        ResourceGroup = ($storageInfo.id -split '/')[4]
                                    }
                                    
                                    # Get comprehensive storage details
                                    Write-Output "  Enumerating detailed storage account information for: $($r.name)"
                                    $detailedStorageInfo = Get-StorageAccountDetails -StorageAccountId $r.id -StorageAccountName $r.name
                                    
                                    # Display container information and stats
                                    if ($detailedStorageInfo -and $detailedStorageInfo.Containers) {
                                        $totalContainers = @($detailedStorageInfo.Containers).Count
                                        $accessibleContainers = @($detailedStorageInfo.Containers | Where-Object { $_.Blobs -and $_.Blobs.Count -gt 0 -and $_.Blobs[0] -is [hashtable] }).Count
                                        $failedEnumerationContainers = @($detailedStorageInfo.Containers | Where-Object { $_.Blobs -and $_.Blobs.Count -gt 0 -and $_.Blobs[0] -is [string] }).Count
                                        $totalBlobs = 0
                                        $containerNames = @()
                                        
                                        foreach ($container in $detailedStorageInfo.Containers) {
                                            $containerNames += $container.name
                                            if ($container.Blobs -and $container.Blobs.Count -gt 0 -and $container.Blobs[0] -is [hashtable]) {
                                                $totalBlobs += $container.Blobs.Count
                                            }
                                        }
                                        
                                        Write-Output "    Storage Account Summary:"
                                        Write-Output "      Total Containers: $totalContainers"
                                        Write-Output "      Accessible Containers (blob enum success): $accessibleContainers"
                                        Write-Output "      Failed Enumeration Containers (will use blind download): $failedEnumerationContainers"
                                        Write-Output "      Total Blobs Found: $totalBlobs"
                                        Write-Output "      Container Names: $($containerNames -join ', ')"
                                        
                                        if ($detailedStorageInfo.StorageAccountKey) {
                                            Write-Output "      Storage Key Access: Available"
                                        } else {
                                            Write-Output "      Storage Key Access: Not Available (will use alternative auth methods)"
                                        }
                                        
                                        if ($failedEnumerationContainers -gt 0) {
                                            Write-Output "      Note: $failedEnumerationContainers containers will be processed using blind download (common file name attempts)"
                                        }
                                    }
                                    
                                    # Always attempt file download, even if container listing failed
                                    try {
                                        Write-Output "  Initiating comprehensive file download for Storage Account: $($r.name)"
                                        
                                        # Process existing containers and add blind download containers for failed enumerations
                                        $containersToProcess = @()
                                        $hasFailedEnumerations = $false
                                        
                                        # First, process any existing containers
                                        if ($detailedStorageInfo.Containers -and $detailedStorageInfo.Containers.Count -gt 0) {
                                            foreach ($container in $detailedStorageInfo.Containers) {
                                                # Check if blob enumeration failed (blobs are error messages)
                                                if ($container.Blobs -and $container.Blobs.Count -gt 0 -and $container.Blobs[0] -is [string]) {
                                                    Write-Output "    Container '$($container.name)' found but blob enumeration failed - enabling blind download"
                                                    # Convert failed enumeration to blind download container
                                                    $blindContainer = @{
                                                        name = $container.name
                                                        Blobs = @(@{ Name = "test"; Size = 0; LastModified = ""; ContentType = ""; ETag = ""; BlobType = "" })
                                                        PublicAccess = $container.PublicAccess
                                                        BlobCount = "Unknown"
                                                        Error = "Attempting blind download - blob listing permissions insufficient"
                                                    }
                                                    $containersToProcess += $blindContainer
                                                    $hasFailedEnumerations = $true
                                                } else {
                                                    # Container with successful blob enumeration
                                                    $containersToProcess += $container
                                                }
                                            }
                                        }
                                        
                                        # If no containers found at all, try common container names
                                        if ($containersToProcess.Count -eq 0) {
                                            Write-Output "    No containers enumerated - attempting common container names"
                                            $commonContainerNames = @('$web', '$root', 'data', 'files', 'documents', 'images', 'backup', 'logs', 'temp', 'public', 'private', 'content', 'assets', 'uploads')
                                            
                                            foreach ($containerName in $commonContainerNames) {
                                                $containersToProcess += @{
                                                    name = $containerName
                                                    Blobs = @(@{ Name = "test"; Size = 0; LastModified = ""; ContentType = ""; ETag = ""; BlobType = "" })
                                                    PublicAccess = "Unknown"
                                                    BlobCount = "Unknown"
                                                    Error = "Attempting blind download - no listing permissions"
                                                }
                                            }
                                            
                                            Write-Output "    Attempting blind download from $($commonContainerNames.Count) common container names"
                                            $hasFailedEnumerations = $true
                                        }
                                        
                                        if ($hasFailedEnumerations) {
                                            # Ask user permission before starting blind download mode
                                            Write-Host "`n    WARNING: Blind download mode will attempt to guess common file names." -ForegroundColor Yellow
                                            Write-Host "    This process can take 15-30 minutes to complete and may generate many 404 errors." -ForegroundColor Yellow
                                            Write-Host "    Do you want to proceed with blind download enumeration? (y/N) " -ForegroundColor Cyan -NoNewline
                                            
                                            # 10-second timeout with default to NO
                                            $timeout = 10
                                            $userInput = $null
                                            
                                            # Interactive countdown with proper timeout
                                            $Host.UI.RawUI.FlushInputBuffer()
                                            $startTime = Get-Date
                                            $inputBuffer = ""
                                            $lastCountdown = -1
                                            
                                            do {
                                                $elapsed = (Get-Date) - $startTime
                                                $remaining = $timeout - [int]$elapsed.TotalSeconds
                                                
                                                # Update countdown display if changed
                                                if ($remaining -ne $lastCountdown -and $remaining -ge 0) {
                                                    if ($lastCountdown -ne -1) {
                                                        # Move cursor back and clear the line properly
                                                        $pos = $Host.UI.RawUI.CursorPosition
                                                        $pos.X = 0
                                                        $Host.UI.RawUI.CursorPosition = $pos
                                                        Write-Host "    Do you want to proceed with blind download enumeration? (y/N) " -ForegroundColor Cyan -NoNewline
                                                    }
                                                    Write-Host "($remaining seconds) " -ForegroundColor Yellow -NoNewline
                                                    $lastCountdown = $remaining
                                                }
                                                
                                                Start-Sleep -Milliseconds 200
                                                
                                                if ($Host.UI.RawUI.KeyAvailable) {
                                                    $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                                                    if ($key.VirtualKeyCode -eq 13) { # Enter key
                                                        $userInput = $inputBuffer
                                                        break
                                                    } elseif ($key.VirtualKeyCode -eq 8) { # Backspace
                                                        if ($inputBuffer.Length -gt 0) {
                                                            $inputBuffer = $inputBuffer.Substring(0, $inputBuffer.Length - 1)
                                                            Write-Host "`b `b" -NoNewline
                                                        }
                                                    } elseif ($key.Character -match '[ynYN]') {
                                                        # Clear countdown and show user input
                                                        $pos = $Host.UI.RawUI.CursorPosition
                                                        $pos.X = 0
                                                        $Host.UI.RawUI.CursorPosition = $pos
                                                        Write-Host "    Do you want to proceed with blind download enumeration? (y/N) " -ForegroundColor Cyan -NoNewline
                                                        
                                                        $inputBuffer = $key.Character
                                                        Write-Host $key.Character -NoNewline
                                                        $userInput = $inputBuffer
                                                        break
                                                    }
                                                }
                                            } while ((Get-Date) - $startTime -lt (New-TimeSpan -Seconds $timeout))
                                            
                                            if (-not $userInput) {
                                                # Clear countdown and show timeout message
                                                $pos = $Host.UI.RawUI.CursorPosition
                                                $pos.X = 0
                                                $Host.UI.RawUI.CursorPosition = $pos
                                                Write-Host "    Do you want to proceed with blind download enumeration? (y/N) " -ForegroundColor Cyan -NoNewline
                                                Write-Host "N (timeout - defaulting to NO)" -ForegroundColor Red
                                            } else {
                                                Write-Host ""
                                            }
                                            
                                            $proceedWithBlindDownload = $false
                                            if ($userInput -and ($userInput.ToLower() -eq 'y' -or $userInput.ToLower() -eq 'yes')) {
                                                $proceedWithBlindDownload = $true
                                                Write-Host "    User chose to proceed with blind download mode." -ForegroundColor Green
                                                Write-Output "    Blind download mode activated - will attempt common file names in containers with failed blob enumeration (this step takes 15-30 minutes to complete, be patient)..."
                                            } else {
                                                Write-Host "    User chose to skip blind download mode. Continuing with available data only." -ForegroundColor Yellow
                                                # Clear the containers that would require blind download
                                                $containersToProcess = $containersToProcess | Where-Object { -not ($_.Error -and $_.Error -like "*blind download*") }
                                            }
                                        }
                                        
                                        # Only attempt download if we have containers to process
                                        if ($containersToProcess -and $containersToProcess.Count -gt 0) {
                                            $downloadResult = Get-StorageAccountFiles -StorageAccountName $r.name -StorageAccountKey $detailedStorageInfo.StorageAccountKey -ContainerDetails $containersToProcess -AccountId $script:currentUser -StorageContext $detailedStorageInfo.StorageContext
                                        } else {
                                            Write-Output "    No containers available for download (blind download was declined or no accessible containers found)"
                                            $downloadResult = @{
                                                StorageAccountName = $r.name
                                                TotalContainers = 0
                                                ProcessedContainers = 0
                                                SuccessfulDownloads = 0
                                                FailedDownloads = 0
                                                TotalFilesProcessed = 0
                                                BlindDownloadAttempts = 0
                                                BlindDownloadSuccesses = 0
                                                DownloadFolders = @()
                                                Errors = @("No containers available - blind download declined or no accessible containers found")
                                            }
                                        }
                                        
                                        # Add download summary to detailed info
                                        $detailedStorageInfo | Add-Member -NotePropertyName "FileDownloadSummary" -NotePropertyValue $downloadResult -Force
                                        
                                        # Display detailed download statistics
                                        Write-Output "    Storage Account Download Results:"
                                        Write-Output "      Total Files Processed: $($downloadResult.TotalFilesProcessed)"
                                        Write-Output "      Successful Downloads: $($downloadResult.SuccessfulDownloads)"
                                        Write-Output "      Failed Downloads: $($downloadResult.FailedDownloads)"
                                        
                                        if ($downloadResult.TotalFilesProcessed -gt 0) {
                                            $successRate = [math]::Round(($downloadResult.SuccessfulDownloads / $downloadResult.TotalFilesProcessed) * 100, 1)
                                            Write-Output "      Success Rate: $successRate%"
                                        }
                                        
                                        # Show blind download statistics if applicable
                                        if ($downloadResult.BlindDownloadAttempts -gt 0) {
                                            Write-Output "      Blind Download Attempts: $($downloadResult.BlindDownloadAttempts)"
                                            Write-Output "      Blind Download Successes: $($downloadResult.BlindDownloadSuccesses)"
                                            if ($downloadResult.BlindDownloadAttempts -gt 0) {
                                                $blindSuccessRate = [math]::Round(($downloadResult.BlindDownloadSuccesses / $downloadResult.BlindDownloadAttempts) * 100, 1)
                                                Write-Output "      Blind Success Rate: $blindSuccessRate%"
                                            }
                                            Write-Output "      Note: Blind downloads attempted common file names when container listing permissions were unavailable"
                                        }
                                        
                                        if ($downloadResult.DownloadFolders -and $downloadResult.DownloadFolders.Count -gt 0) {
                                            Write-Output "      Download Folders Created: $($downloadResult.DownloadFolders.Count)"
                                            Write-Output "      Folder Names: $($downloadResult.DownloadFolders -join ', ')"
                                        }
                                        
                                        if ($downloadResult.Errors -and $downloadResult.Errors.Count -gt 0) {
                                            Write-Output "      Errors Encountered: $($downloadResult.Errors.Count) (see detailed logs for specifics)"
                                            
                                            # Check if errors indicate permission issues and provide guidance
                                            $hasPermissionErrors = $downloadResult.Errors | Where-Object { $_ -match "(permission denied|required permissions|Storage Blob Data|auth-mode.*key)" }
                                            if ($hasPermissionErrors) {
                                                Write-Output ""
                                                Write-Output "      PERMISSION ISSUE DETECTED:"
                                                Write-Output "      The current user lacks Azure RBAC permissions for blob storage access."
                                                Write-Output "      Solutions:"
                                                Write-Output "        1. Request 'Storage Blob Data Reader' role assignment on this storage account"
                                                Write-Output "        2. Use storage account key if available: --auth-mode key"
                                                Write-Output "        3. Access via Azure Portal (uses different permission model)"
                                                Write-Output "        4. Use service principal with proper storage permissions"
                                            }
                                        }
                                        
                                    } catch {
                                        Write-Warning "  Failed to download files from Storage Account $($r.name): $($_.Exception.Message)"
                                        $detailedStorageInfo | Add-Member -NotePropertyName "FileDownloadError" -NotePropertyValue $_.Exception.Message -Force
                                    }
                                    
                                    # Combine basic and detailed info
                                    $basicStorageInfo | Add-Member -NotePropertyName "DetailedInfo" -NotePropertyValue $detailedStorageInfo -Force
                                    $storageDetails += $basicStorageInfo
                                }
                            }
                            "Microsoft.Automation/automationAccounts" {
                                Write-Debug "Processing Automation Account: $($r.name)"
                                $automationInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($r.id)?api-version=2020-01-13-preview"
                                if ($automationInfo) {
                                    # Get basic automation info
                                    $basicAutomationInfo = [pscustomobject]@{
                                        Name = $automationInfo.name
                                        Location = $automationInfo.location
                                        State = $automationInfo.properties.state
                                        CreationTime = $automationInfo.properties.creationTime
                                        LastModifiedTime = $automationInfo.properties.lastModifiedTime
                                        Description = $automationInfo.properties.description
                                        ResourceGroup = ($automationInfo.id -split '/')[4]
                                    }
                                    
                                    # Get comprehensive automation details
                                    Write-Output "  Enumerating detailed automation account information for: $($r.name)"
                                    $detailedAutomationInfo = Get-AutomationAccountDetails -AutomationAccountId $r.id -AutomationAccountName $r.name
                                    
                                    # Combine basic and detailed info
                                    $basicAutomationInfo | Add-Member -NotePropertyName "DetailedInfo" -NotePropertyValue $detailedAutomationInfo -Force
                                    $automationDetails += $basicAutomationInfo
                                }
                            }
                            "Microsoft.DocumentDB/databaseAccounts" {
                                Write-Debug "Processing Cosmos DB Account: $($r.name)"
                                $cosmosInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($r.id)?api-version=2023-04-15"
                                if ($cosmosInfo) {
                                    # Get basic Cosmos DB info
                                    $basicCosmosInfo = [pscustomobject]@{
                                        Name = $cosmosInfo.name
                                        Location = $cosmosInfo.location
                                        Kind = $cosmosInfo.kind
                                        DocumentEndpoint = $cosmosInfo.properties.documentEndpoint
                                        ProvisioningState = $cosmosInfo.properties.provisioningState
                                        DatabaseAccountOfferType = $cosmosInfo.properties.databaseAccountOfferType
                                        ConsistencyPolicy = $cosmosInfo.properties.consistencyPolicy
                                        Locations = $cosmosInfo.properties.locations
                                        Tags = $cosmosInfo.tags
                                        ResourceGroup = ($cosmosInfo.id -split '/')[4]
                                    }
                                    
                                    # Get comprehensive Cosmos DB details
                                    Write-Output "  Enumerating detailed Cosmos DB information for: $($r.name)"
                                    $detailedCosmosInfo = Get-CosmosDbAccountDetails -CosmosDbAccountId $r.id -AccessToken $accessToken
                                    
                                    # Combine basic and detailed info
                                    $basicCosmosInfo | Add-Member -NotePropertyName "DetailedInfo" -NotePropertyValue $detailedCosmosInfo -Force
                                    $cosmosDetails += $basicCosmosInfo
                                }
                            }
                            "Microsoft.KeyVault/vaults" {
                                Write-Debug "Processing Key Vault: $($r.name)"
                                $kvInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($r.id)?api-version=2022-07-01"
                                if ($kvInfo) {
                                    $kvProperties = $kvInfo.properties
                                    
                                    # Get basic Key Vault info
                                    $basicKvInfo = [pscustomobject]@{
                                        Name = $kvInfo.name
                                        Location = $kvInfo.location
                                        EnabledForDeployment = $kvProperties.enabledForDeployment
                                        EnabledForDiskEncryption = $kvProperties.enabledForDiskEncryption
                                        EnabledForTemplateDeployment = $kvProperties.enabledForTemplateDeployment
                                        TenantId = $kvProperties.tenantId
                                        SoftDeleteRetentionInDays = $kvProperties.softDeleteRetentionInDays
                                        VaultUri = $kvProperties.vaultUri
                                        ResourceGroup = ($kvInfo.id -split '/')[4]
                                    }
                                    
                                    # Attempt to retrieve secrets from the Key Vault
                                    try {
                                        Write-Output "  Attempting to retrieve secrets from Key Vault: $($r.name)"
                                        Write-Output "    Vault URI: $($kvProperties.vaultUri)"
                                        Write-Output "    Using multiple detection methods (Azure CLI, REST API, ARM Provider)..."
                                        if ($Script:SSLBypassEnabled) {
                                            Write-Output "    Note: SSL certificate verification is disabled for this session"
                                        }
                                        
                                        # Store current resource group for ARM API calls
                                        $script:currentResourceGroup = ($kvInfo.id -split '/')[4]
                                        
                                        $secretsInfo = Get-KeyVaultSecrets -KeyVaultName $r.name -VaultUri $kvProperties.vaultUri -SubscriptionId $subscriptionId
                                        
                                        # Add secrets information to basic info
                                        $basicKvInfo | Add-Member -NotePropertyName "SecretsInfo" -NotePropertyValue $secretsInfo -Force
                                        
                                        if ($secretsInfo.Error) {
                                            Write-Warning "    Key Vault access error: $($secretsInfo.Error)"
                                            if ($secretsInfo.DiagnosticInfo) {
                                                Write-Output "    Diagnostic Info:"
                                                Write-Output "      - ARM Token Available: $($secretsInfo.DiagnosticInfo.HasARMToken)"
                                                Write-Output "      - Graph Token Available: $($secretsInfo.DiagnosticInfo.HasGraphToken)"
                                                Write-Output "      - Azure CLI Available: $($secretsInfo.DiagnosticInfo.AzureCLIAvailable)"
                                            }
                                        } elseif ($secretsInfo.Secrets -and $secretsInfo.Secrets.Count -gt 0) {
                                            Write-Output "    SUCCESS: Retrieved information for $($secretsInfo.Secrets.Count) secrets"
                                            Write-Output "    Detection method: $($secretsInfo.Secrets[0].Source)"
                                            
                                            # Show secret summary
                                            $managedSecrets = $secretsInfo.Secrets | Where-Object { $_.SecretType -eq "Managed Secret" }
                                            $userSecrets = $secretsInfo.Secrets | Where-Object { $_.SecretType -eq "User Secret" }
                                            
                                            if ($managedSecrets.Count -gt 0) {
                                                Write-Output "      - Managed Secrets: $($managedSecrets.Count)"
                                            }
                                            if ($userSecrets.Count -gt 0) {
                                                Write-Output "      - User Secrets: $($userSecrets.Count)"
                                            }
                                            
                                            # Show names of secrets (first few)
                                            $secretNames = $secretsInfo.Secrets | Select-Object -First 5 | ForEach-Object { $_.Name }
                                            Write-Output "      - Secret Names: $($secretNames -join ', ')$(if ($secretsInfo.Secrets.Count -gt 5) { '...' })"
                                            
                                        } else {
                                            Write-Warning "    No accessible secrets found or insufficient permissions"
                                            Write-Output "    Possible causes:"
                                            Write-Output "      - No secrets exist in this Key Vault"
                                            Write-Output "      - Insufficient permissions (need Key Vault Reader + Secrets User)"
                                            Write-Output "      - Key Vault access policies block current identity"
                                            Write-Output "      - Network restrictions (firewall/private endpoint)"
                                            Write-Output "    Try manual verification with: az keyvault secret list --vault-name $($r.name)"
                                        }
                                        
                                    } catch {
                                        Write-Warning "  Failed to retrieve secrets from Key Vault $($r.name): $($_.Exception.Message)"
                                        $basicKvInfo | Add-Member -NotePropertyName "SecretsError" -NotePropertyValue $_.Exception.Message -Force
                                    }
                                    
                                    $kvDetails += $basicKvInfo
                                    
                                    # Debug: Show what we just added
                                    Write-Verbose "[KV-DEBUG] Added Key Vault to output: $($basicKvInfo.Name)"
                                    Write-Verbose "[KV-DEBUG] SecretsInfo attached: $($null -ne $basicKvInfo.SecretsInfo)"
                                    if ($basicKvInfo.SecretsInfo) {
                                        Write-Verbose "[KV-DEBUG] SecretsInfo.SecretsCount: $($basicKvInfo.SecretsInfo.SecretsCount)"
                                        Write-Verbose "[KV-DEBUG] SecretsInfo.Success: $($basicKvInfo.SecretsInfo.Success)"
                                        if ($basicKvInfo.SecretsInfo.Secrets) {
                                            Write-Verbose "[KV-DEBUG] First secret name: $($basicKvInfo.SecretsInfo.Secrets[0].Name)"
                                        }
                                    }
                                }
                            }
                            "Microsoft.AppConfiguration/configurationStores" {
                                Write-Debug "Processing App Configuration: $($r.name)"
                                $appConfigInfo = Invoke-ARMRequest -Uri "https://management.azure.com$($r.id)?api-version=2023-03-01"
                                if ($appConfigInfo) {
                                    # Get basic App Configuration info
                                    $basicAppConfigInfo = [pscustomobject]@{
                                        Name = $appConfigInfo.name
                                        Location = $appConfigInfo.location
                                        Endpoint = $appConfigInfo.properties.endpoint
                                        ProvisioningState = $appConfigInfo.properties.provisioningState
                                        CreationDate = $appConfigInfo.properties.creationDate
                                        PublicNetworkAccess = $appConfigInfo.properties.publicNetworkAccess
                                        DisableLocalAuth = $appConfigInfo.properties.disableLocalAuth
                                        SoftDeleteRetentionInDays = $appConfigInfo.properties.softDeleteRetentionInDays
                                        EnablePurgeProtection = $appConfigInfo.properties.enablePurgeProtection
                                        Sku = $appConfigInfo.sku.name
                                        ResourceGroup = ($appConfigInfo.id -split '/')[4]
                                        Tags = $appConfigInfo.tags
                                    }
                                    
                                    # Get comprehensive App Configuration details
                                    Write-Output "  Enumerating detailed App Configuration information for: $($r.name)"
                                    $detailedAppConfigInfo = Get-AppConfigurationDetails -AppConfigId $r.id -AppConfigName $r.name -AccessToken $accessToken
                                    
                                    # Combine basic and detailed info
                                    $basicAppConfigInfo | Add-Member -NotePropertyName "DetailedInfo" -NotePropertyValue $detailedAppConfigInfo -Force
                                    $appConfigDetails += $basicAppConfigInfo
                                }
                            }
                        }
                    } catch {
                        Write-Warning "Failed to process resource $($r.name): $($_.Exception.Message)"
                    }
                }
                
                Write-Progress -Activity "Processing Resource Details" -Completed
                
                # Report detailed resource counts
                Write-Output "Detailed resource enumeration complete:"
                Write-Output "  Virtual Machines: $($vmDetails.Count)"
                Write-Output "  Public IPs: $($publicIpDetails.Count)"
                Write-Output "  Web Apps: $($webAppDetails.Count)"
                Write-Output "  Function Apps: $($functionDetails.Count)"
                Write-Output "  Storage Accounts: $($storageDetails.Count) (with detailed enumeration)"
                Write-Output "  Key Vaults: $($kvDetails.Count)"
                Write-Output "  Network Security Groups: $($nsgDetails.Count) (with security rules analysis)"
                Write-Output "  Virtual Networks: $($vnetDetails.Count) (with subnets and peering analysis)"
                Write-Output "  SQL Servers: $($sqlServerDetails.Count) (with databases and firewall rules)"
                Write-Output "  App Configuration Stores: $($appConfigDetails.Count) (with keys and configuration analysis)"
                Write-Output "  Automation Accounts: $($automationDetails.Count) (with runbook scripts)"
                Write-Output "  Cosmos DB Accounts: $($cosmosDetails.Count) (with database/container analysis)"
            }

            # Enumerate Azure Blueprints
            Write-Output "`nEnumerating Azure Blueprints..."
            try {
                $blueprintEnumeration = Get-AzureBlueprints -SubscriptionId $subscriptionId -IncludeStorageSearch
                if ($blueprintEnumeration) {
                    $blueprintDetails = $blueprintEnumeration
                    Write-Output "Blueprint enumeration complete:"
                    Write-Output "  Subscription Blueprints: $($blueprintEnumeration.SubscriptionBlueprints.Count)"
                    Write-Output "  Management Group Blueprints: $($blueprintEnumeration.ManagementGroupBlueprints.Count)"
                    Write-Output "  Blueprint Assignments: $($blueprintEnumeration.BlueprintAssignments.Count)"
                    Write-Output "  Blueprint Artifacts: $($blueprintEnumeration.BlueprintArtifacts.Count)"
                    Write-Output "  Storage Blueprint Files: $($blueprintEnumeration.StorageBlueprintFiles.Count)"
                    
                    # Highlight any blueprint findings
                    if ($blueprintEnumeration.Summary.TotalBlueprints -gt 0 -or 
                        $blueprintEnumeration.Summary.TotalAssignments -gt 0 -or 
                        $blueprintEnumeration.Summary.TotalStorageFiles -gt 0) {
                        Write-Output ""
                        Write-Host "*** BLUEPRINT FINDINGS DETECTED ***" -ForegroundColor Red -BackgroundColor Yellow
                        Write-Host "Found $($blueprintEnumeration.Summary.TotalBlueprints) blueprints, $($blueprintEnumeration.Summary.TotalAssignments) assignments, and $($blueprintEnumeration.Summary.TotalStorageFiles) storage files" -ForegroundColor Red
                        Write-Output ""
                        
                        # Display blueprint storage files if found
                        if ($blueprintEnumeration.StorageBlueprintFiles.Count -gt 0) {
                            Write-Host "Blueprint Storage Files Found:" -ForegroundColor Red
                            foreach ($file in $blueprintEnumeration.StorageBlueprintFiles) {
                                Write-Host "  - $($file.StorageAccount)/$($file.Container)/$($file.BlobName)" -ForegroundColor Yellow
                                if ($file.DownloadSuccess) {
                                    Write-Host "    [DOWNLOADED] Content available in results" -ForegroundColor Green
                                }
                            }
                            Write-Output ""
                        }
                    }
                } else {
                    Write-Output "No blueprint data retrieved (may require Blueprint Contributor permissions)"
                }
            } catch {
                Write-Warning "Blueprint enumeration failed: $($_.Exception.Message)"
                $blueprintDetails = @{
                    Error = "Blueprint enumeration failed: $($_.Exception.Message)"
                    Note = "Blueprint access requires appropriate permissions"
                }
            }

            # Get comprehensive monitoring and logging details
            if ($resources -and $resources.value -and $resources.value.Count -gt 0) {
                Write-Output "`nRetrieving monitoring and logging configuration..."
                try {
                    $monitoringDetails = Get-MonitoringAndLoggingDetails -Resources $resources.value
                    if ($monitoringDetails -and -not $monitoringDetails.Error) {
                        $output.MonitoringAndLogging = $monitoringDetails
                        Write-Output "  Log Analytics Workspaces: $($monitoringDetails.LogAnalyticsWorkspaces.Count)"
                        Write-Output "  Application Insights: $($monitoringDetails.ApplicationInsights.Count)"
                        Write-Output "  Action Groups: $($monitoringDetails.ActionGroups.Count) (total receivers: $($monitoringDetails.MonitoringAnalysis.TotalActionGroupReceivers))"
                        Write-Output "  Alert Rules: $($monitoringDetails.AlertRules.Count) ($($monitoringDetails.MonitoringAnalysis.EnabledAlertRules) enabled)"
                        Write-Output "  Diagnostic Settings: $($monitoringDetails.DiagnosticSettings.Count) covering $($monitoringDetails.MonitoringAnalysis.ResourcesWithDiagnostics) resources"
                        if ($monitoringDetails.MonitoringAnalysis.HasCentralizedLogging) {
                            Write-Host "  Centralized Logging: Configured" -ForegroundColor Green
                        } else {
                            Write-Host "  Centralized Logging: Not detected" -ForegroundColor Yellow
                        }
                    } else {
                        Write-Warning "Could not retrieve monitoring details: $($monitoringDetails.Error)"
                    }
                } catch {
                    Write-Warning "Failed to retrieve monitoring details: $($_.Exception.Message)"
                }
            }
            
            # Store detailed resource information in output
            $output.VirtualMachines = $vmDetails
            $output.PublicIPs = $publicIpDetails
            $output.AzureFunctions = $functionDetails
            $output.WebApps = $webAppDetails
            $output.StorageAccounts = $storageDetails
            $output.KeyVaults = $kvDetails
            
            # Debug: Verify Key Vault assignment
            Write-Verbose "[OUTPUT-DEBUG] Assigned Key Vaults to output object"
            Write-Verbose "[OUTPUT-DEBUG] kvDetails count: $($kvDetails.Count)"  
            Write-Verbose "[OUTPUT-DEBUG] output.KeyVaults count: $($output.KeyVaults.Count)"
            if ($output.KeyVaults -and $output.KeyVaults.Count -gt 0) {
                Write-Verbose "[OUTPUT-DEBUG] First KV in output: $($output.KeyVaults[0].Name)"
                Write-Verbose "[OUTPUT-DEBUG] First KV has SecretsInfo: $($null -ne $output.KeyVaults[0].SecretsInfo)"
            }
            
            $output.NetworkSecurityGroups = $nsgDetails
            $output.VirtualNetworks = $vnetDetails
            $output.SqlServers = $sqlServerDetails
            $output.AppConfigurationStores = $appConfigDetails
            $output.AutomationAccounts = $automationDetails
            $output.CosmosDbAccounts = $cosmosDetails
            $output.AzureBlueprints = $blueprintDetails
        }
        else {
            Write-Warning "No accessible Azure subscription found. ARM resource enumeration skipped."
            Write-Output "ARM enumeration skipped - continuing with available data from other sources."
            $output.Warning = "No accessible Azure subscription - ARM enumeration skipped"
            
            # Initialize empty arrays for ARM resources since we can't access them
            $output.Resources = @()
            $output.ResourceGroups = @()
            $output.SubscriptionRoleAssignments = @()
            $output.VirtualMachines = @()
            $output.PublicIPs = @()
            $output.AzureFunctions = @()
            $output.WebApps = @()
            $output.StorageAccounts = @()
            $output.NetworkSecurityGroups = @()
            $output.VirtualNetworks = @()
            $output.SqlServers = @()
            $output.KeyVaults = @()
            $output.AppConfigurationStores = @()
            $output.AutomationAccounts = @()
            $output.CosmosDbAccounts = @()
            $output.AzureBlueprints = @()
            $output.MonitoringAndLogging = @{}
            
            # Since ARM enumeration failed but we have Graph access, perform enhanced Graph enumeration
            if ($Script:AuthenticationStatus.GraphToken -and $Script:PerformGraphChecks) {
                Write-Output "`nPerforming enhanced Azure AD enumeration (Graph API only mode - ARM access failed)..."
                
                try {
                    # Test available Graph API permissions
                    Write-Output "  Testing Graph API permissions and capabilities..."
                    $graphPermissions = Test-GraphApiPermissions
                    $output.GraphApiCapabilities = $graphPermissions
                    
                    Write-Output "    Available Endpoints: $($graphPermissions.AvailableEndpoints -join ', ')"
                    if ($graphPermissions.PermissionErrors.Count -gt 0) {
                        Write-Output "    Restricted Endpoints: $($graphPermissions.PermissionErrors.Count) endpoints require additional permissions"
                    }
                    
                    # Get comprehensive tenant information (if permitted)
                    if ($graphPermissions.CanReadOrganization) {
                        Write-Output "  Retrieving comprehensive tenant details..."
                        $tenantDetails = Get-TenantInformation
                        if ($tenantDetails -and -not $tenantDetails.Error) {
                            $output.EnhancedTenantDetails = $tenantDetails
                            Write-Output "    Tenant: $($tenantDetails.DisplayName) ($($tenantDetails.Id))"
                            Write-Output "    Domains: $($tenantDetails.VerifiedDomains.Count) verified domains"
                            Write-Output "    Country/Region: $($tenantDetails.CountryLetterCode)"
                        }
                    }
                    
                    # Get directory roles and assignments (if permitted)
                    if ($graphPermissions.CanReadDirectoryRoles) {
                        Write-Output "  Enumerating directory roles and assignments..."
                        $directoryRoles = Get-DirectoryRoles
                        if ($directoryRoles -and -not $directoryRoles.Error) {
                            $output.DirectoryRoles = $directoryRoles
                            Write-Output "    Directory Roles: $($directoryRoles.Roles.Count) roles found"
                            Write-Output "    Role Assignments: $($directoryRoles.RoleAssignments.Count) assignments"
                        }
                    }
                    
                    # Get all users in the tenant (if permitted)
                    if ($graphPermissions.CanReadUsers) {
                        Write-Output "  Retrieving all tenant users..."
                        $allUsers = Get-TenantUsers
                        if ($allUsers -and -not $allUsers.Error) {
                            $output.TenantUsers = $allUsers
                            Write-Output "    Users: $($allUsers.Users.Count) total users"
                            Write-Output "    Guest Users: $($allUsers.Analysis.GuestUsersCount) guests"
                            Write-Output "    Enabled Users: $($allUsers.Analysis.EnabledUsersCount) enabled"
                        }
                    }
                    
                    # Get all groups (if permitted)
                    if ($graphPermissions.CanReadGroups) {
                        Write-Output "  Retrieving all tenant groups..."
                        $allGroups = Get-TenantGroups
                        if ($allGroups -and -not $allGroups.Error) {
                            $output.TenantGroups = $allGroups
                            Write-Output "    Groups: $($allGroups.Groups.Count) total groups"
                            Write-Output "    Security Groups: $($allGroups.Analysis.SecurityGroupsCount) security groups"
                            Write-Output "    Distribution Groups: $($allGroups.Analysis.DistributionGroupsCount) distribution groups"
                        }
                    }
                    
                    # Get owned objects first (critical for privilege escalation detection)
                    Write-Output "  Retrieving owned objects..."
                    $ownedObjects = Get-OwnedObjectsViaGraph -AccessToken $AccessTokenGraph
                    if ($ownedObjects -and -not $ownedObjects.Error) {
                        $output.OwnedObjects = $ownedObjects
                        Write-Output "    Owned Objects: $($ownedObjects.Analysis.TotalOwnedObjects) total owned objects"
                        Write-Output "    Breakdown: Apps=$($ownedObjects.Analysis.OwnedApplications), SPs=$($ownedObjects.Analysis.OwnedServicePrincipals), Groups=$($ownedObjects.Analysis.OwnedGroups), Devices=$($ownedObjects.Analysis.OwnedDevices), Others=$($ownedObjects.Analysis.OtherOwnedObjects)"
                        
                        # Show details for owned applications (highest priority for privilege escalation)
                        if ($ownedObjects.Analysis.OwnedApplications -gt 0) {
                            Write-Host "    *** PRIVILEGE ESCALATION OPPORTUNITY: $($ownedObjects.Analysis.OwnedApplications) owned applications ***" -ForegroundColor Red
                            Write-Host "        -> You can create new secrets for these applications to authenticate as them!" -ForegroundColor Yellow
                            foreach ($app in $ownedObjects.Applications) {
                                Write-Output "        Application: $($app.displayName) (ID: $($app.id), AppId: $($app.appId))"
                            }
                        }
                        
                        # Show details for owned service principals
                        if ($ownedObjects.Analysis.OwnedServicePrincipals -gt 0) {
                            Write-Output "    Owned Service Principals: $($ownedObjects.Analysis.OwnedServicePrincipals)"
                            foreach ($sp in $ownedObjects.ServicePrincipals) {
                                Write-Output "        Service Principal: $($sp.displayName) (ID: $($sp.id), AppId: $($sp.appId))"
                            }
                        }
                        
                        # Show details for owned groups
                        if ($ownedObjects.Analysis.OwnedGroups -gt 0) {
                            Write-Output "    Owned Groups: $($ownedObjects.Analysis.OwnedGroups)"
                            foreach ($group in $ownedObjects.Groups) {
                                Write-Output "        Group: $($group.displayName) (ID: $($group.id), Type: $($group.groupTypes -join ', '))"
                            }
                        }
                        
                        # Show details for owned devices
                        if ($ownedObjects.Analysis.OwnedDevices -gt 0) {
                            Write-Output "    Owned Devices: $($ownedObjects.Analysis.OwnedDevices)"
                            foreach ($device in $ownedObjects.Devices) {
                                Write-Output "        Device: $($device.displayName) (ID: $($device.id), OS: $($device.operatingSystem))"
                            }
                        }
                        
                        # Show details for other owned objects
                        if ($ownedObjects.Analysis.OtherOwnedObjects -gt 0) {
                            Write-Output "    Other Owned Objects: $($ownedObjects.Analysis.OtherOwnedObjects)"
                            foreach ($other in $ownedObjects.Others) {
                                $objectType = $other.'@odata.type' -replace '#microsoft\.graph\.', ''
                                Write-Output "        ${objectType}: $($other.displayName) (ID: $($other.id))"
                            }
                        }
                        
                        # Fallback: If no specific categories were shown but we have objects, show all details
                        if ($ownedObjects.Analysis.TotalOwnedObjects -gt 0 -and 
                            $ownedObjects.Analysis.OwnedApplications -eq 0 -and 
                            $ownedObjects.Analysis.OwnedServicePrincipals -eq 0 -and 
                            $ownedObjects.Analysis.OwnedGroups -eq 0 -and 
                            $ownedObjects.Analysis.OwnedDevices -eq 0 -and 
                            $ownedObjects.Analysis.OtherOwnedObjects -eq 0) {
                            Write-Output "    Owned Objects Details (Fallback):"
                            foreach ($obj in $ownedObjects.OwnedObjects) {
                                $objectType = if ($obj.'@odata.type') { $obj.'@odata.type' -replace '#microsoft\.graph\.', '' } else { "Unknown" }
                                Write-Output "        $objectType`: $($obj.displayName) (ID: $($obj.id))"
                                if ($obj.appId) { Write-Output "          App ID: $($obj.appId)" }
                                if ($obj.'@odata.type' -match 'application') {
                                    Write-Host "          *** POTENTIAL PRIVILEGE ESCALATION TARGET ***" -ForegroundColor Red
                                }
                            }
                        }
                    } else {
                        Write-Output "    No owned objects found or access denied"
                    }

                    # Get all applications (if permitted)
                    if ($graphPermissions.CanReadApplications) {
                        Write-Output "  Retrieving all tenant applications..."
                        
                        # Use owned applications for highlighting
                        $ownedApplications = @()
                        if ($ownedObjects -and -not $ownedObjects.Error -and $ownedObjects.Applications) {
                            $ownedApplications = $ownedObjects.Applications
                            Write-Verbose "Found $($ownedApplications.Count) owned applications for highlighting"
                        }
                        
                        $allApplications = Get-TenantApplications -OwnedApplications $ownedApplications
                        if ($allApplications -and -not $allApplications.Error) {
                            $output.TenantApplications = $allApplications
                            Write-Output "    Applications: $($allApplications.Applications.Count) total applications"
                            Write-Output "    Service Principals: $($allApplications.ServicePrincipals.Count) service principals"
                            if ($allApplications.Analysis.ApplicationsWithSecrets -gt 0) {
                                Write-Output "    Applications with Secrets: $($allApplications.Analysis.ApplicationsWithSecrets)"
                            }
                            
                            # Highlight owned applications
                            $ownedAppsCount = ($allApplications.Applications | Where-Object { $_.IsOwned -eq $true }).Count
                            if ($ownedAppsCount -gt 0) {
                                Write-Host "    *** PRIVILEGE ESCALATION: $ownedAppsCount owned applications detected! ***" -ForegroundColor Red
                            }
                        }
                    }
                    
                    Write-Output "Enhanced Azure AD enumeration completed (Graph API scope)"
                    
                } catch {
                    Write-Warning "Enhanced Graph enumeration failed: $($_.Exception.Message)"
                }
            }
        }
    } catch {
        Write-Warning "Error during Azure resource enumeration: $($_.Exception.Message)"
        Write-Output "ARM enumeration failed, but continuing with available data from other sources..."
        $output.ARMError = $_.Exception.Message
        
        # Ensure we have the basic structure even if ARM enumeration failed completely
        if (-not $output.TenantId) { $output.TenantId = "Unknown" }
        if (-not $output.SubscriptionId) { $output.SubscriptionId = "None" }
        if (-not $output.SubscriptionName) { $output.SubscriptionName = "No Access" }
        
        # Initialize empty arrays for ARM resources since enumeration failed
        if (-not $output.Resources) { $output.Resources = @() }
        if (-not $output.ResourceGroups) { $output.ResourceGroups = @() }
        if (-not $output.SubscriptionRoleAssignments) { $output.SubscriptionRoleAssignments = @() }
        if (-not $output.VirtualMachines) { $output.VirtualMachines = @() }
        if (-not $output.PublicIPs) { $output.PublicIPs = @() }
        if (-not $output.AzureFunctions) { $output.AzureFunctions = @() }
        if (-not $output.WebApps) { $output.WebApps = @() }
        if (-not $output.StorageAccounts) { $output.StorageAccounts = @() }
        if (-not $output.KeyVaults) { $output.KeyVaults = @() }
        if (-not $output.AutomationAccounts) { $output.AutomationAccounts = @() }
        if (-not $output.CosmosDbAccounts) { $output.CosmosDbAccounts = @() }
        if (-not $output.AzureBlueprints) { $output.AzureBlueprints = @() }
    }
} elseif ($Script:PerformARMChecks) {
    Write-Warning "ARM checks requested but no ARM access token available - skipping Azure resource enumeration"
    $output.Warning = "ARM checks requested but no ARM access token available"
    
    # Enhanced Graph-only enumeration when ARM access is not available
    if ($Script:AuthenticationStatus.GraphToken -and $Script:PerformGraphChecks) {
        Write-Output "`nPerforming enhanced Azure AD enumeration (Graph API only mode)..."
        
        try {
            # Test available Graph API permissions
            Write-Output "  Testing Graph API permissions and capabilities..."
            $graphPermissions = Test-GraphApiPermissions
            $output.GraphApiCapabilities = $graphPermissions
            
            Write-Output "    Available Endpoints: $($graphPermissions.AvailableEndpoints -join ', ')"
            if ($graphPermissions.PermissionErrors.Count -gt 0) {
                Write-Output "    Restricted Endpoints: $($graphPermissions.PermissionErrors.Count) endpoints require additional permissions"
            }
            
            # Get comprehensive tenant information (if permitted)
            if ($graphPermissions.CanReadOrganization) {
                Write-Output "  Retrieving comprehensive tenant details..."
                $tenantDetails = Get-TenantInformation
                if ($tenantDetails -and -not $tenantDetails.Error) {
                    $output.EnhancedTenantDetails = $tenantDetails
                    Write-Output "    Tenant: $($tenantDetails.DisplayName) ($($tenantDetails.Id))"
                    Write-Output "    Domains: $($tenantDetails.VerifiedDomains.Count) verified domains"
                    Write-Output "    Country/Region: $($tenantDetails.CountryLetterCode)"
                }
            }
            
            # Get directory roles and assignments (if permitted)
            if ($graphPermissions.CanReadDirectoryRoles) {
                Write-Output "  Enumerating directory roles and assignments..."
                $directoryRoles = Get-DirectoryRoles
                if ($directoryRoles -and -not $directoryRoles.Error) {
                    $output.DirectoryRoles = $directoryRoles
                    Write-Output "    Directory Roles: $($directoryRoles.Roles.Count) roles found"
                    Write-Output "    Role Assignments: $($directoryRoles.RoleAssignments.Count) assignments"
                }
            }
            
            # Get all users in the tenant (if permitted)
            if ($graphPermissions.CanReadUsers) {
                Write-Output "  Retrieving all tenant users..."
                $allUsers = Get-TenantUsers
                if ($allUsers -and -not $allUsers.Error) {
                    $output.TenantUsers = $allUsers
                    Write-Output "    Users: $($allUsers.Users.Count) total users"
                    Write-Output "    Guest Users: $($allUsers.Analysis.GuestUsersCount) guests"
                    Write-Output "    Enabled Users: $($allUsers.Analysis.EnabledUsersCount) enabled"
                }
            }
            
            # Get all groups (if permitted)
            if ($graphPermissions.CanReadGroups) {
                Write-Output "  Retrieving all tenant groups..."
                $allGroups = Get-TenantGroups
                if ($allGroups -and -not $allGroups.Error) {
                    $output.TenantGroups = $allGroups
                    Write-Output "    Groups: $($allGroups.Groups.Count) total groups"
                    Write-Output "    Security Groups: $($allGroups.Analysis.SecurityGroupsCount) security groups"
                    Write-Output "    Distribution Groups: $($allGroups.Analysis.DistributionGroupsCount) distribution groups"
                }
            }
            
        } catch {
            Write-Warning "Enhanced Graph enumeration failed: $($_.Exception.Message)"
        }
        
        Write-Output "Enhanced Azure AD enumeration completed (limited to Graph API scope)"
    }


} else {
    # ARM checks not requested, but check if we should do Graph-only enumeration
    if ($Script:AuthenticationStatus.GraphToken -and $Script:PerformGraphChecks) {
        Write-Output "`nPerforming enhanced Azure AD enumeration (Graph-only mode)..."
        
        try {
            # Test available Graph API permissions
            Write-Output "  Testing Graph API permissions and capabilities..."
            $graphPermissions = Test-GraphApiPermissions
            $output.GraphApiCapabilities = $graphPermissions
            
            Write-Output "    Available Endpoints: $($graphPermissions.AvailableEndpoints -join ', ')"
            if ($graphPermissions.PermissionErrors.Count -gt 0) {
                Write-Output "    Restricted Endpoints: $($graphPermissions.PermissionErrors.Count) endpoints require additional permissions"
            }
            
            # Get owned objects first (critical for privilege escalation detection)
            Write-Output "  Retrieving owned objects..."
            $ownedObjects = Get-OwnedObjectsViaGraph -AccessToken $AccessTokenGraph
            if ($ownedObjects -and -not $ownedObjects.Error) {
                $output.OwnedObjects = $ownedObjects
                Write-Output "    Owned Objects: $($ownedObjects.Analysis.TotalOwnedObjects) total owned objects"
                Write-Output "    Breakdown: Apps=$($ownedObjects.Analysis.OwnedApplications), SPs=$($ownedObjects.Analysis.OwnedServicePrincipals), Groups=$($ownedObjects.Analysis.OwnedGroups), Devices=$($ownedObjects.Analysis.OwnedDevices), Others=$($ownedObjects.Analysis.OtherOwnedObjects)"
                if ($ownedObjects.Analysis.OwnedApplications -gt 0) {
                    Write-Host "    *** PRIVILEGE ESCALATION OPPORTUNITY: $($ownedObjects.Analysis.OwnedApplications) owned applications ***" -ForegroundColor Red
                    Write-Host "        -> You can create new secrets for these applications to authenticate as them!" -ForegroundColor Yellow
                    
                    # Show details for owned applications
                    foreach ($app in $ownedObjects.Applications) {
                        Write-Output "        Application: $($app.displayName) (ID: $($app.id))"
                        if ($app.appId) {
                            Write-Output "          App ID: $($app.appId)"
                        }
                    }
                }
                if ($ownedObjects.Analysis.OwnedServicePrincipals -gt 0) {
                    Write-Output "    Owned Service Principals: $($ownedObjects.Analysis.OwnedServicePrincipals)"
                    
                    # Show details for owned service principals
                    foreach ($sp in $ownedObjects.ServicePrincipals) {
                        Write-Output "        Service Principal: $($sp.displayName) (ID: $($sp.id))"
                        if ($sp.appId) {
                            Write-Output "          App ID: $($sp.appId)"
                        }
                    }
                }
                if ($ownedObjects.Analysis.OwnedGroups -gt 0) {
                    Write-Output "    Owned Groups: $($ownedObjects.Analysis.OwnedGroups)"
                    
                    # Show details for owned groups
                    foreach ($group in $ownedObjects.Groups) {
                        Write-Output "        Group: $($group.displayName) (ID: $($group.id))"
                        if ($group.mail) {
                            Write-Output "          Email: $($group.mail)"
                        }
                    }
                }
                if ($ownedObjects.Analysis.OwnedDevices -gt 0) {
                    Write-Output "    Owned Devices: $($ownedObjects.Analysis.OwnedDevices)"
                    
                    # Show details for owned devices
                    foreach ($device in $ownedObjects.Devices) {
                        Write-Output "        Device: $($device.displayName) (ID: $($device.id))"
                        if ($device.deviceId) {
                            Write-Output "          Device ID: $($device.deviceId)"
                        }
                    }
                }
                
                # Show details for other owned objects
                if ($ownedObjects.Analysis.OtherOwnedObjects -gt 0) {
                    Write-Output "    Other Owned Objects: $($ownedObjects.Analysis.OtherOwnedObjects)"
                    foreach ($other in $ownedObjects.Others) {
                        $objectType = $other.'@odata.type' -replace '#microsoft\.graph\.', ''
                        Write-Output "        ${objectType}: $($other.displayName) (ID: $($other.id))"
                    }
                }
            } else {
                Write-Output "    No owned objects found or access denied"
            }

            # Get all applications (if permitted)
            if ($graphPermissions.CanReadApplications) {
                Write-Output "  Retrieving all tenant applications..."
                
                # Use owned applications for highlighting
                $ownedApplications = @()
                if ($ownedObjects -and -not $ownedObjects.Error -and $ownedObjects.Applications) {
                    $ownedApplications = $ownedObjects.Applications
                    Write-Verbose "Found $($ownedApplications.Count) owned applications for highlighting"
                }
                
                $allApplications = Get-TenantApplications -OwnedApplications $ownedApplications
                if ($allApplications -and -not $allApplications.Error) {
                    $output.TenantApplications = $allApplications
                    Write-Output "    Applications: $($allApplications.Applications.Count) total applications"
                    Write-Output "    Service Principals: $($allApplications.ServicePrincipals.Count) service principals"
                    if ($allApplications.Analysis.ApplicationsWithSecrets -gt 0) {
                        Write-Output "    Applications with Secrets: $($allApplications.Analysis.ApplicationsWithSecrets)"
                    }
                    
                    # Highlight owned applications
                    $ownedAppsCount = ($allApplications.Applications | Where-Object { $_.IsOwned -eq $true }).Count
                    if ($ownedAppsCount -gt 0) {
                        Write-Host "    *** PRIVILEGE ESCALATION: $ownedAppsCount owned applications detected! ***" -ForegroundColor Red
                    }
                }
            }
            
            # Get all users (if permitted)
            if ($graphPermissions.CanReadUsers) {
                Write-Output "  Retrieving all tenant users..."
                $allUsers = Get-TenantUsers
                if ($allUsers -and -not $allUsers.Error) {
                    $output.TenantUsers = $allUsers
                    Write-Output "    Users: $($allUsers.Users.Count) total users"
                    Write-Output "    Member Users: $($allUsers.Analysis.MemberUsersCount) members"
                    Write-Output "    Guest Users: $($allUsers.Analysis.GuestUsersCount) guests"
                    Write-Output "    Enabled Users: $($allUsers.Analysis.EnabledUsersCount) enabled"
                }
            }
            
            # Get all groups (if permitted)
            if ($graphPermissions.CanReadGroups) {
                Write-Output "  Retrieving all tenant groups..."
                $allGroups = Get-TenantGroups
                if ($allGroups -and -not $allGroups.Error) {
                    $output.TenantGroups = $allGroups
                    Write-Output "    Groups: $($allGroups.Groups.Count) total groups"
                    Write-Output "    Security Groups: $($allGroups.Analysis.SecurityGroupsCount) security groups"
                    Write-Output "    Distribution Groups: $($allGroups.Analysis.DistributionGroupsCount) distribution groups"
                }
            }
            
            Write-Output "Enhanced Azure AD enumeration completed (Graph API scope)"
            
        } catch {
            Write-Warning "Enhanced Graph enumeration failed: $($_.Exception.Message)"
        }
    } else {
        Write-Output "ARM checks not requested - skipping Azure resource enumeration"
    }
}

# Azure CLI enumeration (independent of ARM token availability)
if ($Script:AuthenticationStatus.AzureCLI) {
    $separator = "=" * 60
    Write-Output ""
    Write-Output $separator
    Write-Output "AZURE CLI ENUMERATION"
    Write-Output $separator
    
    try {
        # Test CLI capabilities
        Write-Output "  Testing Azure CLI capabilities..."
        $cliCapabilities = Test-AzureCLICapabilities
        $output.AzureCLICapabilities = $cliCapabilities
        
        Write-Output "    Available Commands: $($cliCapabilities.AvailableCommands -join ', ')"
        if ($cliCapabilities.CommandErrors.Count -gt 0) {
            Write-Output "    Restricted Commands: $($cliCapabilities.CommandErrors.Count) commands require additional permissions"
        }
        
        # Get tenant details via CLI
        if ($cliCapabilities.CanListTenantDetails) {
            Write-Output "  Retrieving tenant details via CLI..."
            $cliTenantDetails = Get-TenantDetailsViaCLI
            if ($cliTenantDetails -and -not $cliTenantDetails.Error) {
                $output.CLITenantDetails = $cliTenantDetails
                if ($cliTenantDetails.CurrentAccount) {
                    Write-Output "    Current Tenant: $($cliTenantDetails.CurrentAccount.tenantId)"
                    Write-Output "    Service Principal: $($cliTenantDetails.CurrentAccount.user.name)"
                }
            }
        }
        
        # Get users via CLI
        if ($cliCapabilities.CanListUsers) {
            Write-Output "  Retrieving users via CLI..."
            $cliUsers = Get-UsersViaCLI
            if ($cliUsers -and -not $cliUsers.Error) {
                $output.CLIUsers = $cliUsers
                Write-Output "    Users: $($cliUsers.Users.Count) total users"
                Write-Output "    Enabled Users: $($cliUsers.Analysis.EnabledUsers) enabled"
                Write-Output "    Guest Users: $($cliUsers.Analysis.GuestUsers) guests"
            }
        }
        
        # Get groups via CLI
        if ($cliCapabilities.CanListGroups) {
            Write-Output "  Retrieving groups via CLI..."
            $cliGroups = Get-GroupsViaCLI
            if ($cliGroups -and -not $cliGroups.Error) {
                $output.CLIGroups = $cliGroups
                Write-Output "    Groups: $($cliGroups.Groups.Count) total groups"
                Write-Output "    Security Groups: $($cliGroups.Analysis.SecurityGroups) security groups"
            }
        }
        
        # Get owned objects via CLI first (crucial for privilege escalation opportunities)
        $ownedObjects = $null
        if ($cliCapabilities.CanListOwnedObjects) {
            Write-Output "  Retrieving owned objects via CLI..."
            $ownedObjects = Get-OwnedObjectsViaCLI
            if ($ownedObjects -and -not $ownedObjects.Error) {
                $output.OwnedObjects = $ownedObjects
                Write-Output "    Owned Objects: $($ownedObjects.Analysis.TotalOwnedObjects) total owned objects"
                
                # Show details for owned applications (highest priority for privilege escalation)
                if ($ownedObjects.Analysis.OwnedApplications -gt 0) {
                    Write-Host "    *** PRIVILEGE ESCALATION OPPORTUNITY: $($ownedObjects.Analysis.OwnedApplications) owned applications ***" -ForegroundColor Red
                    Write-Host "        -> You can create new secrets for these applications to authenticate as them!" -ForegroundColor Yellow
                    foreach ($app in $ownedObjects.Applications) {
                        Write-Output "        Application: $($app.displayName) (ID: $($app.id), AppId: $($app.appId))"
                    }
                }
                
                # Show details for owned service principals
                if ($ownedObjects.Analysis.OwnedServicePrincipals -gt 0) {
                    Write-Output "    Owned Service Principals: $($ownedObjects.Analysis.OwnedServicePrincipals)"
                    foreach ($sp in $ownedObjects.ServicePrincipals) {
                        Write-Output "        Service Principal: $($sp.displayName) (ID: $($sp.id), AppId: $($sp.appId))"
                    }
                }
                
                # Show details for owned groups
                if ($ownedObjects.Analysis.OwnedGroups -gt 0) {
                    Write-Output "    Owned Groups: $($ownedObjects.Analysis.OwnedGroups)"
                    foreach ($group in $ownedObjects.Groups) {
                        Write-Output "        Group: $($group.displayName) (ID: $($group.id), Type: $($group.groupTypes -join ', '))"
                    }
                }
                
                # Show details for owned devices
                if ($ownedObjects.Analysis.OwnedDevices -gt 0) {
                    Write-Output "    Owned Devices: $($ownedObjects.Analysis.OwnedDevices)"
                    foreach ($device in $ownedObjects.Devices) {
                        Write-Output "        Device: $($device.displayName) (ID: $($device.id), OS: $($device.operatingSystem))"
                    }
                }
                
                # Show details for other owned objects
                if ($ownedObjects.Analysis.OtherOwnedObjects -gt 0) {
                    Write-Output "    Other Owned Objects: $($ownedObjects.Analysis.OtherOwnedObjects)"
                    foreach ($other in $ownedObjects.Others) {
                        $objectType = $other.'@odata.type' -replace '#microsoft\.graph\.', ''
                        Write-Output "        ${objectType}: $($other.displayName) (ID: $($other.id))"
                    }
                }
            }
        }
        
        # Get applications via CLI (with ownership highlighting)
        if ($cliCapabilities.CanListApps) {
            Write-Output "  Retrieving applications via CLI..."
            $ownedApplications = if ($ownedObjects -and $ownedObjects.Applications) { $ownedObjects.Applications } else { @() }
            $cliApplications = Get-ApplicationsViaCLI -OwnedApplications $ownedApplications
            if ($cliApplications -and -not $cliApplications.Error) {
                $output.CLIApplications = $cliApplications
                Write-Output "    Applications: $($cliApplications.Applications.Count) total applications"
                Write-Output "    Service Principals: $($cliApplications.ServicePrincipals.Count) service principals"
                Write-Output "    Apps with Credentials: $($cliApplications.Analysis.ApplicationsWithCredentials) with credentials"
                if ($cliApplications.Analysis.OwnedApplications -gt 0) {
                    Write-Host "    *** OWNED APPLICATIONS: $($cliApplications.Analysis.OwnedApplications) owned applications marked! ***" -ForegroundColor Red
                }
            }
        }
        
        # Get role assignments via CLI
        if ($cliCapabilities.CanListRoles) {
            Write-Output "  Retrieving role assignments via CLI..."
            $cliRoles = Get-RoleAssignmentsViaCLI
            if ($cliRoles -and -not $cliRoles.Error) {
                $output.CLIRoleAssignments = $cliRoles
                Write-Output "    Role Assignments: $($cliRoles.RoleAssignments.Count) total assignments"
                Write-Output "    Unique Roles: $($cliRoles.Analysis.UniqueRoles) unique roles"
                Write-Output "    Unique Principals: $($cliRoles.Analysis.UniquePrincipals) unique principals"
            }
        }
        
    } catch {
        Write-Warning "Azure CLI enumeration failed: $($_.Exception.Message)"
    }
    
    Write-Output "Azure CLI enumeration completed"
    Write-Output ("=" * 60)
}

if (-not $Script:AuthenticationStatus.GraphToken -and -not $Script:AuthenticationStatus.AzureCLI) {
    Write-Output "No Graph API or Azure CLI access available - enumeration severely limited"
}

#region Output Generation

$separator = "=" * 60
Write-Output ""
Write-Output $separator
Write-Output "GENERATING OUTPUT"
Write-Output $separator

# Add summary statistics to output
$output.Summary = [ordered]@{
    TotalResources = if ($output.Resources) { $output.Resources.Count } else { 0 }
    ResourceGroups = if ($output.ResourceGroups) { $output.ResourceGroups.Count } else { 0 }
    VirtualMachines = if ($output.VirtualMachines) { $output.VirtualMachines.Count } else { 0 }
    PublicIPs = if ($output.PublicIPs) { $output.PublicIPs.Count } else { 0 }
    WebApps = if ($output.WebApps) { $output.WebApps.Count } else { 0 }
    FunctionApps = if ($output.AzureFunctions) { $output.AzureFunctions.Count } else { 0 }
    StorageAccounts = if ($output.StorageAccounts) { $output.StorageAccounts.Count } else { 0 }
    KeyVaults = if ($output.KeyVaults) { $output.KeyVaults.Count } else { 0 }
    NetworkSecurityGroups = if ($output.NetworkSecurityGroups) { $output.NetworkSecurityGroups.Count } else { 0 }
    VirtualNetworks = if ($output.VirtualNetworks) { $output.VirtualNetworks.Count } else { 0 }
    SqlServers = if ($output.SqlServers) { $output.SqlServers.Count } else { 0 }
    AutomationAccounts = if ($output.AutomationAccounts) { $output.AutomationAccounts.Count } else { 0 }
    CosmosDbAccounts = if ($output.CosmosDbAccounts) { $output.CosmosDbAccounts.Count } else { 0 }
    AzureBlueprints = if ($output.AzureBlueprints -and $output.AzureBlueprints.Summary) { $output.AzureBlueprints.Summary.TotalBlueprints } else { 0 }
    BlueprintAssignments = if ($output.AzureBlueprints -and $output.AzureBlueprints.Summary) { $output.AzureBlueprints.Summary.TotalAssignments } else { 0 }
    BlueprintStorageFiles = if ($output.AzureBlueprints -and $output.AzureBlueprints.Summary) { $output.AzureBlueprints.Summary.TotalStorageFiles } else { 0 }
    SubscriptionRoleAssignments = if ($output.SubscriptionRoleAssignments) { $output.SubscriptionRoleAssignments.Count } else { 0 }
}

try {
    if ($OutputFormat -eq "json") {
        Write-Output "Exporting consolidated data to JSON format..."
        $jsonOutput = $output | ConvertTo-Json -Depth 15
        $jsonOutput | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
        
        $fileSizeKB = [math]::Round((Get-Item $OutputFile).Length / 1KB, 2)
        Write-Output "Successfully exported to: $OutputFile ($fileSizeKB KB)"
        
    } elseif ($OutputFormat -eq "csv") {
        Write-Output "Exporting data to CSV format..."
        
        $categories = @(
            @{Name="Resources"; Data=$output.Resources},
            @{Name="ResourceGroups"; Data=$output.ResourceGroups},
            @{Name="VirtualMachines"; Data=$output.VirtualMachines},
            @{Name="PublicIPs"; Data=$output.PublicIPs},
            @{Name="WebApps"; Data=$output.WebApps},
            @{Name="AzureFunctions"; Data=$output.AzureFunctions},
            @{Name="StorageAccounts"; Data=$output.StorageAccounts},
            @{Name="KeyVaults"; Data=$output.KeyVaults},
            @{Name="NetworkSecurityGroups"; Data=$output.NetworkSecurityGroups},
            @{Name="VirtualNetworks"; Data=$output.VirtualNetworks},
            @{Name="SqlServers"; Data=$output.SqlServers},
            @{Name="AutomationAccounts"; Data=$output.AutomationAccounts},
            @{Name="CosmosDbAccounts"; Data=$output.CosmosDbAccounts},
            @{Name="AzureBlueprints"; Data=$output.AzureBlueprints},
            @{Name="SubscriptionRoleAssignments"; Data=$output.SubscriptionRoleAssignments}
        )
        
        $baseFileName = [System.IO.Path]::GetFileNameWithoutExtension($OutputFile)
        $exportedFiles = @()
        
        foreach ($category in $categories) {
            if ($category.Data -and $category.Data.Count -gt 0) {
                $csvFileName = "${baseFileName}_$($category.Name).csv"
                try {
                    $category.Data | Export-Csv -Path $csvFileName -NoTypeInformation -Encoding UTF8 -Force
                    $exportedFiles += $csvFileName
                    Write-Output "  $($category.Name): $csvFileName ($($category.Data.Count) items)"
                } catch {
                    Write-Warning "Failed to export $($category.Name) to CSV: $($_.Exception.Message)"
                }
            } else {
                Write-Output "  $($category.Name): No data to export"
            }
        }
        
        # Create summary file
        $summaryFileName = "${baseFileName}_Summary.csv"
        $output.Summary.GetEnumerator() | ForEach-Object { [PSCustomObject]@{Category=$_.Key; Count=$_.Value} } | Export-Csv -Path $summaryFileName -NoTypeInformation -Encoding UTF8 -Force
        $exportedFiles += $summaryFileName
        
        Write-Output "`nExported $($exportedFiles.Count) CSV files"
    }
    
    # Enhanced Display Output
    try {
        # Display header with subscription info
        Show-EnumerationHeader -SubscriptionName $output.SubscriptionName -SubscriptionId $output.SubscriptionId -TenantId $output.TenantId -AuthMethod $output.AuthenticationMethod
        
        # Display quick statistics
        Show-QuickStats -Summary $output.Summary
        
        # Display role assignments with detailed principal information
        if ($output.SubscriptionRoleAssignments -and $output.SubscriptionRoleAssignments.Count -gt 0) {
            Show-RoleAssignmentsSummary -RoleAssignments $output.SubscriptionRoleAssignments -Title "SUBSCRIPTION-LEVEL ROLE ASSIGNMENTS"
        }
        
        # Display resource group role assignments if any found
        if ($output.ResourceGroups) {
            $allRgRoles = @()
            foreach ($rg in $output.ResourceGroups) {
                if ($rg.RoleAssignments) {
                    foreach ($role in $rg.RoleAssignments) {
                        $allRgRoles += [PSCustomObject]@{
                            ResourceGroup = $rg.Name
                            RoleDefinitionName = $role.RoleName
                            PrincipalId = $role.PrincipalId
                            PrincipalType = $role.PrincipalType
                            PrincipalName = if ($role.PrincipalName) { $role.PrincipalName } else { Get-PrincipalName -PrincipalId $role.PrincipalId }
                            Scope = $role.Scope
                        }
                    }
                }
            }
            
            if ($allRgRoles.Count -gt 0) {
                Show-RoleAssignmentsSummary -RoleAssignments $allRgRoles -Title "RESOURCE GROUP-LEVEL ROLE ASSIGNMENTS"
            }
        }
        
        # Display resources summary with detailed tables
        Write-Verbose "`n[MAIN] About to call Show-ResourcesSummary..."
        Write-Verbose "[MAIN] Key Vaults in output: $(if ($output.KeyVaults) { $output.KeyVaults.Count } else { 'null/missing' })"
        if ($output.KeyVaults) {
            $output.KeyVaults | ForEach-Object {
                Write-Verbose "[MAIN] Key Vault: $($_.Name) - SecretsInfo: $($null -ne $_.SecretsInfo)"
                if ($_.SecretsInfo -and $_.SecretsInfo.Secrets) {
                    Write-Verbose "[MAIN]   - Secrets Count: $($_.SecretsInfo.Secrets.Count)"
                    Write-Verbose "[MAIN]   - First Secret: $($_.SecretsInfo.Secrets[0].Name)"
                }
            }
        }
        Show-ResourcesSummary -Resources $output
        
        # Display security highlights and recommendations
        Show-SecurityHighlights -Resources $output
        
        # Display detailed owned applications information
        if ($output.TenantApplications -and $output.TenantApplications.Applications) {
            $ownedApps = $output.TenantApplications.Applications | Where-Object { $_.IsOwned -eq $true }
            if ($ownedApps.Count -gt 0) {
                Show-OwnedApplicationsDetails -Applications $output.TenantApplications.Applications
            }
        } elseif ($output.CLIApplications -and $output.CLIApplications.Applications) {
            $ownedApps = $output.CLIApplications.Applications | Where-Object { $_.IsOwned -eq $true }
            if ($ownedApps.Count -gt 0) {
                Show-OwnedApplicationsDetails -Applications $output.CLIApplications.Applications
            }
        }
        
        # Footer
        $separator = "=" * 80
        Write-Host ""
        Write-Host $separator -ForegroundColor Cyan
        Write-Host " ENUMERATION COMPLETED SUCCESSFULLY" -ForegroundColor Green
        Write-Host " Complete JSON output saved: $OutputFile" -ForegroundColor Gray
        Write-Host $separator -ForegroundColor Cyan
        
    } catch {
        Write-Warning "Enhanced display failed, falling back to basic summary: $($_.Exception.Message)"
        
        # Fallback to original simple display
        Write-Output "`nEnumeration Summary:"
        $output.Summary.GetEnumerator() | ForEach-Object {
            Write-Output "  $($_.Key): $($_.Value)"
        }
    }
    
} catch {
    Write-Error "Failed to generate output file(s): $($_.Exception.Message)"
    exit 1
}

Write-Output "`nEnumeration completed successfully!"

#endregion
