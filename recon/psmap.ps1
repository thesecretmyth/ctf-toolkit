<#
.SYNOPSIS
    A simple network ping sweep and port scanner for a /24 subnet.
.PARAMETER Subnet
    The first three octets of the network (e.g., 192.168.100). This parameter is MANDATORY.
#>
param(
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = "You must provide a subnet base (e.g., 192.168.100)")]
    [ValidateNotNullOrEmpty()]
    [string]$Subnet,

    [Parameter(Mandatory = $false, Position = 1)]
    [int[]]$Ports = @(53, 88, 135, 139, 389, 445, 3389, 5985)
)

# Clean up input variations if the user appended '.0' or '/24'
$Subnet = $Subnet -replace '\.0$', '' -replace '/24$', ''

Write-Host "[*] Starting subnet sweep on $Subnet.0/24..." -ForegroundColor Cyan

# Initialize a .NET Ping object for universal compatibility and speed
$PingSender = New-Object System.Net.NetworkInformation.Ping
$PingTimeout = 500 # Timeout in milliseconds (500ms)

# Iterate through all possible hosts in a /24 network (1 to 254)
for ($i = 1; $i -le 254; $i++) {
    $IP = "$Subnet.$i"

    $PingStatus = $false
    try {
        # Perform a fast .NET ping
        $Reply = $PingSender.Send($IP, $PingTimeout)
        if ($Reply.Status -eq "Success") {
            $PingStatus = $true
        }
    }
    catch {
        $PingStatus = $false
    }

    # If the host responded to the ping
    if ($PingStatus) {

        # Resolve Hostname & IPv6 details
        $Hostname = "Unknown"
        $IPv6 = "N/A"
        try {
            $Resolve = [System.Net.Dns]::GetHostEntry($IP)
            $Hostname = $Resolve.HostName
            $IPv6Addresses = $Resolve.AddressList | Where-Object { $_.AddressFamily -eq 'InterNetworkV6' } | ForEach-Object { $_.IPAddressToString }
            if ($IPv6Addresses) { $IPv6 = $IPv6Addresses -join ", " }
        }
        catch {}

        Write-Host "`n[+] $IP" -ForegroundColor Green
        Write-Host "    Hostname: $Hostname"
        Write-Host "    IPv6: $IPv6"

        # Check for specified open ports
        $OpenPorts = @()
        foreach ($Port in $Ports) {
            $TcpClient = New-Object System.Net.Sockets.TcpClient
            $Connect = $TcpClient.BeginConnect($IP, $Port, $null, $null)
            $Wait = $Connect.AsyncWaitHandle.WaitOne(200, $false)

            if ($Wait -and $TcpClient.Connected) {
                $OpenPorts += $Port
                $TcpClient.EndConnect($Connect)
            }
            $TcpClient.Close()
        }

        if ($OpenPorts.Count -gt 0) {
            Write-Host "    Open Ports: $($OpenPorts -join ', ')" -ForegroundColor Yellow
        }
        else {
            Write-Host "    Open Ports: None detected" -ForegroundColor Gray
        }
    }
}
Write-Host "`n[*] Sweep complete." -ForegroundColor Cyan
