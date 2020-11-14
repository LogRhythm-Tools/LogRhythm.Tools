<#
Example source input for CSV:
hostname,ipv4address1,ipv4address2,ipv4address3,fqdn1,fqdn2,fqdn3,shortdescription
exhostwin01,172.16.1.2,,,exhostwin01.example.com,gbhostwin01.eu.example.com,,Domain Controller eu.example.com
exhostwin02,172.16.1.3,,,exhostwin02.example.com,gbhostwin02.eu.example.com,,
exhostwin03,172.16.1.4,172.16.22.5,199.55.12.15,exhostwin03.example.com,gbhostwin03.eu.example.com,extraavail1.pubdomain.example.com,External partner access portal 1
#>

#API sleep time between calls - Prevent API rate limit
$APISleep = .2

# Import CSV with updated Headers, removing the header from the original CSV.  Add a new column for Entity set to Global Entity.
$HostRecords = Import-Csv N:\Projects\git\SRF.Repo\LogRhythm.Tools\LR-FQDN-updates.csv -Header 'Hostname', 'ipv4address1', 'ipv4address2', 'ipv4address3', 'fqdn1', 'fqdn2', 'fqdn3', 'shortdesc' | Select-Object -Skip 1



foreach ($HostRecord in $HostRecords) {
    Write-Host "----- New Csv Entry -----"
    # Check if Network exists in LR Entity
    Write-Host "$(Get-Timestamp) - HostID Discovery via Hostname: $($HostRecord.Hostname)"
    $HostStatus = Get-LrHosts -HostIdentifier $($HostRecord.Hostname)
    Start-Sleep $APISleep
    if ($HostStatus) {
        Write-Host "$(Get-Timestamp) - HostID Discovery: $($HostStatus.id)"
        $HostIdentifiers = $HostStatus.hostIdentifiers

        # Create variables containing values for specific identifier types
        $HostIPv4Identifiers = $HostIdentifiers | Where-Object -Property type -like "IPAddress" | Select-Object -ExpandProperty value
        $HostDNSIdentifiers = $HostIdentifiers | Where-Object -Property type -like "DNSName" | Select-Object -ExpandProperty value
        $HostNameIdentifiers = $HostIdentifiers | Where-Object -Property type -like "WindowsName" | Select-Object -ExpandProperty value

        
        # Update a host record DNS entries
        if ($HostRecord.fqdn1.Length -gt 0) {
            if ($HostDNSIdentifiers -notcontains $HostRecord.fqdn1) {
                Write-Host "$(Get-Timestamp) - Add Identifier - DNS - HostID: $($HostStatus.id) Identifier: $($HostRecord.fqdn1)"
                Update-LrHostIDentifier -Id $HostStatus.Id -Type dnsname -Value $HostRecord.fqdn1
                Start-Sleep $APISleep
            }
        }
        if ($HostRecord.fqdn2.Length -gt 0) {
            if ($HostDNSIdentifiers -notcontains $HostRecord.fqdn2) {
                Write-Host "$(Get-Timestamp) - Add Identifier - DNS - HostID: $($HostStatus.id) Identifier: $($HostRecord.fqdn2)"
                Update-LrHostIDentifier -Id $HostStatus.Id -Type dnsname -Value $HostRecord.fqdn2
                Start-Sleep $APISleep
            }
        }
        if ($HostRecord.fqdn3.Length -gt 0) {
            if ($HostDNSIdentifiers -notcontains $HostRecord.fqdn3) {
                Write-Host "$(Get-Timestamp) - Add Identifier - DNS - HostID: $($HostStatus.id) Identifier: $($HostRecord.fqdn3)"
                Update-LrHostIDentifier -Id $HostStatus.Id -Type dnsname -Value $HostRecord.fqdn3
                Start-Sleep $APISleep
            }
        }
        
        # Upst a host record IPv4 entries
        if ($HostRecord.ipv4address1.Length -gt 0) {
            if ($HostIPv4Identifiers -notcontains $HostRecord.ipv4address1) {
                Write-Host "$(Get-Timestamp) - Add Identifier - IPv4Address - HostID: $($HostStatus.id) Identifier: $($HostRecord.ipv4address1)"
                Update-LrHostIDentifier -Id $HostStatus.Id -Type ipaddress -Value $HostRecord.ipv4address1
                Start-Sleep $APISleep
            }
        }
        if ($HostRecord.ipv4address2.Length -gt 0) {
            if ($HostIPv4Identifiers -notcontains $HostRecord.ipv4address2) {
                Write-Host "$(Get-Timestamp) - Add Identifier - IPv4Address - HostID: $($HostStatus.id) Identifier: $($HostRecord.ipv4address2)"
                Update-LrHostIDentifier -Id $HostStatus.Id -Type ipaddress -Value $HostRecord.ipv4address2
                Start-Sleep $APISleep
            }
        }
        if ($HostRecord.ipv4address3.Length -gt 0) {
            if ($HostIPv4Identifiers -notcontains $HostRecord.ipv4address3) {
                Write-Host "$(Get-Timestamp) - Add Identifier - IPv4Address - HostID: $($HostStatus.id) Identifier: $($HostRecord.ipv4address3)"
                Update-LrHostIDentifier -Id $HostStatus.Id -Type ipaddress -Value $HostRecord.ipv4address3
                Start-Sleep $APISleep
            }
        }

        # Update host ShortDesc if a value was provided.
        if ($HostRecord.ShortDesc.Length -gt 0) {
            Write-Host "$(Get-Timestamp) - Update Field - ShortDesc - HostID: $($HostStatus.id) Value: $($HostRecord.ShortDesc)"
            Update-LrHost -Id $HostStatus.Id -ShortDesc $HostRecord.ShortDesc
        }

    } else {
        Write-Host "$(Get-Timestamp) - HostID Discovery: No record found."
    }
    Write-Host "----- End Csv Entry -----"
}