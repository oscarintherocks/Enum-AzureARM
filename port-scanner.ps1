<#
.SYNOPSIS
Network port scanner with real-time results

.PARAMETER NetworkRange
IP range: 192.168.1.0/24 or 10.0.1.1-50

.PARAMETER Ports  
Optional ports: "22,80,443"

.EXAMPLE
.\port-scanner.ps1 -NetworkRange "192.168.1.0/24" -Ports "22,80,443"
#>

[CmdletBinding(DefaultParameterSetName='Help')]
param(
    [Parameter(ParameterSetName='Scan', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$NetworkRange,
    
    [Parameter(ParameterSetName='Scan')]
    [string]$Ports,
    
    [Parameter(ParameterSetName='Scan')]
    [string]$OutputFile,
    
    [Parameter(ParameterSetName='Scan')]
    [ValidateRange(100, 10000)]
    [int]$Timeout = 1000,
    
    [Parameter(ParameterSetName='Scan')]
    [ValidateRange(1, 100)]
    [int]$MaxThreads = 50,
    
    [Parameter(ParameterSetName='Help')]
    [switch]$Help
)

# Display help if requested or no parameters provided
if ($Help -or $PSCmdlet.ParameterSetName -eq 'Help') {
    Write-Host "Network Port Scanner - Real-time results" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\port-scanner.ps1 -NetworkRange <range> [-Ports <ports>]"
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  .\port-scanner.ps1 -NetworkRange '192.168.1.0/24'"
    Write-Host "  .\port-scanner.ps1 -NetworkRange '10.0.1.1-50' -Ports '22,80,443'"
    Write-Host ""
    exit 0
}

# Set error action preference
$ErrorActionPreference = 'Stop'

# Validate network range format
if ($NetworkRange -notmatch "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$" -and 
    $NetworkRange -notmatch "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$") {
    Write-Error "Invalid network range format. Use CIDR notation (e.g., 192.168.1.0/24) or IP range (e.g., 10.0.1.1-254)"
    exit 1
}

# Ensure Results directory exists
$ResultsDir = "Results"
if (-not (Test-Path $ResultsDir)) {
    New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
}

# Initialize output file if not specified
if (-not $OutputFile) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputFile = "Results\NetworkScan_$timestamp.csv"
} else {
    # Ensure output file is in Results directory
    if ($OutputFile -notmatch "^Results\\") {
        $OutputFile = Join-Path $ResultsDir (Split-Path $OutputFile -Leaf)
    }
}

#region Helper Functions

function Write-Log {
    param([string]$Message, [string]$Level = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Error" { Write-Error $logMessage }
        "Warning" { Write-Warning $logMessage }
        "Verbose" { Write-Verbose $logMessage }
        default { Write-Output $logMessage }
    }
}

function ConvertFrom-CIDR {
    param([string]$CIDR)
    
    $parts = $CIDR.Split('/')
    $baseIP = $parts[0]
    $subnetMask = [int]$parts[1]
    
    $ip = [System.Net.IPAddress]::Parse($baseIP)
    $ipBytes = $ip.GetAddressBytes()
    
    if ([System.BitConverter]::IsLittleEndian) {
        [Array]::Reverse($ipBytes)
    }
    
    $ipInt = [System.BitConverter]::ToUInt32($ipBytes, 0)
    $maskInt = [UInt32]([Math]::Pow(2, 32) - [Math]::Pow(2, 32 - $subnetMask))
    
    $networkInt = $ipInt -band $maskInt
    $broadcastInt = $networkInt -bor (-bnot $maskInt -band 0xFFFFFFFF)
    
    $ipList = @()
    for ($i = $networkInt + 1; $i -lt $broadcastInt; $i++) {
        $bytes = [System.BitConverter]::GetBytes($i)
        if ([System.BitConverter]::IsLittleEndian) {
            [Array]::Reverse($bytes)
        }
        $ipList += [System.Net.IPAddress]::new($bytes).ToString()
    }
    
    return $ipList
}

function ConvertFrom-IPRange {
    param([string]$IPRange)
    
    $parts = $IPRange.Split('-')
    $baseIP = $parts[0]
    $endOctet = [int]$parts[1]
    
    $ipParts = $baseIP.Split('.')
    $startOctet = [int]$ipParts[3]
    $baseNetwork = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2])"
    
    $ipList = @()
    for ($i = $startOctet; $i -le $endOctet; $i++) {
        $ipList += "$baseNetwork.$i"
    }
    
    return $ipList
}

function Test-NetworkConnectivity {
    param([string]$IPAddress, [int]$TimeoutMs = 1000)
    
    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $result = $ping.Send($IPAddress, $TimeoutMs)
        
        if ($result.Status -eq 'Success') {
            return @{
                IsAlive = $true
                ResponseTime = $result.RoundtripTime
                Status = $result.Status.ToString()
            }
        } else {
            return @{
                IsAlive = $false
                ResponseTime = $null
                Status = $result.Status.ToString()
            }
        }
    } catch {
        return @{
            IsAlive = $false
            ResponseTime = $null
            Status = "Error: $($_.Exception.Message)"
        }
    }
}

function Test-PortConnectivity {
    param([string]$IPAddress, [int]$Port, [int]$TimeoutMs = 1000)
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcpClient.ConnectAsync($IPAddress, $Port)
        
        if ($connectTask.Wait($TimeoutMs)) {
            $tcpClient.Close()
            return $true
        } else {
            $tcpClient.Close()
            return $false
        }
    } catch {
        return $false
    }
}

function Get-HostnameFromIP {
    param([string]$IPAddress)
    
    try {
        $hostname = [System.Net.Dns]::GetHostEntry($IPAddress).HostName
        return $hostname
    } catch {
        return $null
    }
}

#endregion

#region Main Execution

Write-Log "Starting network scanner..."
Write-Log "Network Range: $NetworkRange"
Write-Log "Output File: $OutputFile"

# Parse network range
$ipList = @()
if ($NetworkRange -match "/") {
    Write-Log "Parsing CIDR notation: $NetworkRange"
    $ipList = ConvertFrom-CIDR -CIDR $NetworkRange
} elseif ($NetworkRange -match "-") {
    Write-Log "Parsing IP range: $NetworkRange"
    $ipList = ConvertFrom-IPRange -IPRange $NetworkRange
} else {
    Write-Error "Invalid network range format. Use CIDR (e.g., 192.168.1.0/24) or range (e.g., 10.0.1.1-254)"
    exit 1
}

Write-Log "Generated $($ipList.Count) IP addresses to scan"

# Parse ports if provided
$portList = @()
if ($Ports) {
    $portList = $Ports -split ',' | ForEach-Object { [int]$_.Trim() }
    Write-Log "Ports to scan: $($portList -join ', ')"
} else {
    Write-Log "No ports specified - performing ping sweep only"
}

# Initialize results collection
$results = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()
$aliveHosts = [System.Collections.Concurrent.ConcurrentBag[string]]::new()

# Display headers for real-time output
Write-Host "`n" -NoNewline
Write-Host "LIVE HOSTS DETECTED:" -ForegroundColor Green

# Perform threaded ping sweep
Write-Log "Starting threaded ping sweep..."
$pingJobs = @()

# Split IPs into chunks for threading
$chunkSize = [math]::Ceiling($ipList.Count / $MaxThreads)
$ipChunks = @()
for ($i = 0; $i -lt $ipList.Count; $i += $chunkSize) {
    $end = [math]::Min($i + $chunkSize - 1, $ipList.Count - 1)
    $ipChunks += ,@($ipList[$i..$end])
}

# Create ping sweep jobs
foreach ($chunk in $ipChunks) {
    $job = Start-Job -ScriptBlock {
        param($ipChunk, $timeout)
        
        foreach ($ip in $ipChunk) {
            try {
                $ping = New-Object System.Net.NetworkInformation.Ping
                $result = $ping.Send($ip, $timeout)
                
                if ($result.Status -eq 'Success') {
                    # Try to get hostname
                    $hostname = $null
                    try {
                        $hostname = [System.Net.Dns]::GetHostEntry($ip).HostName
                    } catch { }
                    
                    [PSCustomObject]@{
                        IPAddress = $ip
                        Hostname = $hostname
                        Status = "Alive"
                        ResponseTime = $result.RoundtripTime
                        Port = $null
                        PortStatus = $null
                        ScanTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                }
                $ping.Dispose()
            } catch { }
        }
    } -ArgumentList $chunk, $Timeout
    
    $pingJobs += $job
}

# Monitor ping jobs and display results in real-time
$pingResults = @()
$completedJobIds = @()
while ($pingJobs | Where-Object { $_.State -eq 'Running' }) {
    foreach ($job in ($pingJobs | Where-Object { $_.State -eq 'Completed' -and $_.Id -notin $completedJobIds })) {
        $jobResults = Receive-Job -Job $job
        foreach ($result in $jobResults) {
            if ($result) {
                $aliveHosts.Add($result.IPAddress)
                $results.Add($result)
                $pingResults += $result
                
                # Real-time display
                Write-Host "✓ " -ForegroundColor Green -NoNewline
                Write-Host "$($result.IPAddress)" -ForegroundColor Yellow -NoNewline
                if ($result.Hostname) {
                    Write-Host " ($($result.Hostname))" -ForegroundColor Cyan -NoNewline
                }
                Write-Host " - $($result.ResponseTime)ms" -ForegroundColor White
            }
        }
        $completedJobIds += $job.Id
    }
    Start-Sleep -Milliseconds 100
}

# Clean up all ping jobs
Get-Job | Where-Object { $_.Id -in ($pingJobs | Select-Object -ExpandProperty Id) } | Remove-Job -Force

$aliveHostsList = @($aliveHosts.ToArray())
Write-Log "`nPing sweep completed. Found $($aliveHostsList.Count) alive hosts"

# Perform port scanning if requested
if ($portList.Count -gt 0 -and $aliveHostsList.Count -gt 0) {
    Write-Host "`nOPEN PORTS DETECTED:" -ForegroundColor Green
    Write-Host "=" * 50 -ForegroundColor Green
    
    Write-Log "Starting threaded port scan on $($aliveHostsList.Count) alive hosts..."
    
    $portJobs = @()
    
    # Create port scan jobs for each host
    foreach ($ip in $aliveHostsList) {
        $job = Start-Job -ScriptBlock {
            param($ipAddress, $portList, $timeout)
            
            $openPorts = @()
            foreach ($port in $portList) {
                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $connectTask = $tcpClient.ConnectAsync($ipAddress, $port)
                    
                    if ($connectTask.Wait($timeout)) {
                        $openPorts += $port
                    }
                    $tcpClient.Close()
                } catch { }
            }
            
            if ($openPorts.Count -gt 0) {
                [PSCustomObject]@{
                    IPAddress = $ipAddress
                    OpenPorts = $openPorts
                }
            }
        } -ArgumentList $ip, $portList, $Timeout
        
        $portJobs += $job
    }
    
    # Monitor port scan jobs and display results in real-time
    $completedPortJobIds = @()
    while ($portJobs | Where-Object { $_.State -eq 'Running' }) {
        foreach ($job in ($portJobs | Where-Object { $_.State -eq 'Completed' -and $_.Id -notin $completedPortJobIds })) {
            $jobResult = Receive-Job -Job $job
            if ($jobResult -and $jobResult.OpenPorts) {
                # Find the corresponding ping result for hostname
                $hostInfo = $pingResults | Where-Object { $_.IPAddress -eq $jobResult.IPAddress } | Select-Object -First 1
                
                foreach ($port in $jobResult.OpenPorts) {
                    # Real-time display
                    Write-Host "◉ " -ForegroundColor Red -NoNewline
                    Write-Host "$($jobResult.IPAddress):$port" -ForegroundColor Yellow -NoNewline
                    if ($hostInfo.Hostname) {
                        Write-Host " ($($hostInfo.Hostname))" -ForegroundColor Cyan
                    } else {
                        Write-Host ""
                    }
                    
                    # Add to results
                    $portResult = [PSCustomObject]@{
                        IPAddress = $jobResult.IPAddress
                        Hostname = $hostInfo.Hostname
                        Status = "Alive"
                        ResponseTime = $hostInfo.ResponseTime
                        Port = $port
                        PortStatus = "Open"
                        ScanTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                    $results.Add($portResult)
                }
            }
            $completedPortJobIds += $job.Id
        }
        Start-Sleep -Milliseconds 100
    }
    
    # Clean up all port scan jobs
    Get-Job | Where-Object { $_.Id -in ($portJobs | Select-Object -ExpandProperty Id) } | Remove-Job -Force
    Write-Log "Port scan completed"
}

# Export results
try {
    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -Force
    $fileSizeKB = [math]::Round((Get-Item $OutputFile).Length / 1KB, 2)
    Write-Log "Results exported to: $OutputFile ($fileSizeKB KB)"
} catch {
    Write-Log "Failed to export results: $($_.Exception.Message)" -Level "Error"
    exit 1
}

# Display summary
Write-Log "`nScan Summary:"
Write-Log "  Total IPs scanned: $($ipList.Count)"
Write-Log "  Alive hosts: $($aliveHosts.Count)"
if ($portList.Count -gt 0) {
    $openPorts = ($results | Where-Object { $_.PortStatus -eq "Open" }).Count
    Write-Log "  Open ports found: $openPorts"
}
Write-Log "  Results file: $OutputFile"

Write-Log "Network scan completed successfully!"

#endregion
