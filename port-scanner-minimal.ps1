# minimal port scan for copy/paste in PowerShell console
# Define the network base (without the last octet)
$network = "10.0.1"

# Define the start and end of the range
$start = 1
$end   = 254

# Do the scan using ping and resolving names when asset is live
for ($i = $start; $i -le $end; $i++) {
    if ($i % 20 -eq 0) {
        $subtotal = [math]::Floor($i/20) * 20
        Write-Host "$subtotal IPs Scanned"
    }

    $ip = "$network.$i"

    $result = ping.exe -n 1 $ip -w 10 | findstr "Repl"
    if ($result) {
        $name = ping.exe -n 1 -a $ip | findstr "Pinging"
        Write-Host "$ip is reachable: $name"
    } 
}
