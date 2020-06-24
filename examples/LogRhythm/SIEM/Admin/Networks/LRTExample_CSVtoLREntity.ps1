#Regex to help find DMZ and External networks.
[regex]$RegexDMZ = '^.*(?<tag>[dD][mM][zZ]).*$'
[regex]$RegexPublic = '^.*(?<tag>[pP][uU][bB][lL][iI][cC]).*$'
[regex]$RegexExternal = '^.*(?<tag>[eE][xX][tT][eE][rR][nN][aA][lL]).*$'

# Import CSV with updated Headers, removing the header from the original CSV.  Add a new column for Entity set to Global Entity.
$Networks = Import-Csv C:\Users\Administrator\Documents\GitHub\SmartResponse.Framework\examples\LogRhythm\SIEM\Admin\Networks\infoblox_logrythm.csv -Header 'Name', 'ShortDesc', 'LongDesc', 'RiskLevel', 'Zone', 'Location', 'BIP', 'EIP' | Select-Object -Skip 1 | Select-Object *,@{Name='Entity';Expression={''}}

foreach ($Network in $Networks) {
    Write-Host "----- New Csv Entry -----"
    # Check if Network exists in LR Entity
    Write-Host "$(Get-Timestamp) - NetworkID Discovery: BIP=$($Network.bip) EIP=$($Network.eip)"
    $NetworkStatus = Find-LrNetworkByIP -BIP $Network.BIP -EIP $Network.EIP
    Write-Host "$(Get-Timestamp) - NetworkID Discovery: $($NetworkStatus.id)"

    # Set defaults for null values
    if (($null -eq $Network.Entity) -or ($Network.Entity -eq "")) { $Network.Entity = "Global Entity"}

    if (($null -eq $Network.RiskLevel) -or ($Network.RiskLevel -eq "")) { $Network.RiskLevel = "None"}

    if(($Network.Name -match $RegexDMZ) -or ($Network.Location -match $RegexDMZ) -or ($Network.ShortDesc -match $RegexDMZ)) {
        Write-Host "$(Get-Timestamp) - Network Zone: Set to DMZ based on Regex Match:DMZ to Name, ShortDesc, or Location"
        $Network.Zone = "DMZ"
    } elseif (($Network.Name -match $RegexPublic) -or ($Network.Location -match $RegexPublic) -or ($Network.ShortDesc -match $RegexPublic)) {
        Write-Host "$(Get-Timestamp) - Network Zone: Set to External based on Regex Match:Public to Name, ShortDesc, or Location"
        $Network.Zone = "DMZ"
    } elseif (($Network.Name -match $RegexExternal) -or ($Network.Location -match $RegexExternal) -or ($Network.ShortDesc -match $RegexExternal)) {
        Write-Host "$(Get-Timestamp) - Network Zone: Set to External based on Regex Match:External to Name, ShortDesc, or Location"
        $Network.Zone = "DMZ"
    } else {#>
        if (($null -eq $Network.Zone) -or ($Network.Zone -eq "")) { 
            $Network.Zone = "Internal"
        }
    }

    # If network does not exist, create it.  Else, update it.
    if (($NetworkStatus.Note -eq "NetworkID Discovery: No Network found") -or ($null -eq $NetworkStatus)) {
        Try {
            Write-Host "$(Get-Timestamp) - Createing Network: $($Network.Name)"
            $Network | Create-LrNetwork 
        } Catch {
            Write-Host "$(Get-Timestamp) - Unable to create network for entry: $Network"
        }
    } else {
        Try {
            $Network | Add-Member -MemberType NoteProperty -Name RecordStatus -Value Active -PassThru | Out-Null
            $Network | Add-Member -MemberType NoteProperty -Name ThreatLevel -Value None -PassThru | Out-Null
            Write-Host "$(Get-Timestamp) - Updating Network: $($Network.Name)"
            $NetUpdate = $Network | Update-LrNetwork -id $NetworkStatus.id
            if ($NetUpdate.Error -eq "True") {
                Write-Host "$(Get-Timestamp) - Network Update Error: $NetUpdate"
            } else {
                Write-Host "$(Get-Timestamp) - Sucessfully updated: $($NetUpdate.Name)"
            }

        } Catch {
            Write-Host "$(Get-Timestamp) - Unable to update network for entry: $Network"
        }
    }
    start-sleep -seconds .4
    Write-Host "----- End Csv Entry -----"
}