using namespace System
using namespace System.IO
using namespace System.Collections.Generic

#Regex to help find DMZ and External networks.
[regex]$RegexDMZ = '^.*(?<tag>[dD][mM][zZ]).*$'
[regex]$RegexPublic = '^.*(?<tag>[pP][uU][bB][lL][iI][cC]).*$'
[regex]$RegexExternal = '^.*(?<tag>[eE][xX][tT][eE][rR][nN][aA][lL]).*$'

# Import CSV with updated Headers, removing the header from the original CSV.  Add a new column for Entity set to Global Entity.
$Networks = Import-Csv C:\Users\Administrator\Downloads\NetworkSync\IPRanges_Formatted.csv -Header 'Range', 'Type', 'Schedule', 'Free', 'Utilization', 'Title', 'Description', 'Monitoring', 'ADSite', 'RouterName', 'Gateway', 'InterfaceID', 'InterfaceName', 'InterfaceDescription', 'VLANID', 'VRFName', 'CreationTime', 'DefaultGateway', 'SubnetMask', 'VLAN', 'NetworkType', 'Location', 'Contact', 'DNS1', 'DNS2', 'CampusView', 'FacilityID', 'Lat', 'Long' | Select-Object -Skip 4

# Exclude Child Entities, Global Entity, and any Echo Entity
$Entities = Get-LrEntities | Where-Object parentEntityName -EQ $null | Where-Object id -ne -100 | Where-Object name -NotMatch ".*echo.*" | Where-Object fullName -eq "LRT-Sandbox"

#$Entities = Get-LrEntities -name "FirstTestEntity" -Exact

# RevisedNetworks contains list of Networks that have been had the CIDR notation blocks compared 
# This process ensures  high level net blocks are ommited from being established
$RevisedNetworks = [list[pscustomobject]]::new()
$OmitNetworks = [list[pscustomobject]]::new()
# End list after comparisons and cleanup
$NetworkList = [list[pscustomobject]]::new()


#Loop through each Network entry from CSV
foreach ($Network in $Networks) {
    Write-Host "$(Get-Timestamp) - Begin - Entry: $($Network.range)"
    $OmitAddition = $false
    $NetworkDetails = Test-IPv4CIDR -network $Network.range

    # For each Network entry loop through each entry from CSV for comparison
    foreach ($VersusNetwork in $Networks) {
        if ($OmitAddition -eq $false) {
            Write-Verbose "$(Get-Timestamp) - Reviewing Network: $($Network.range) vs Network: $($VersusNetwork.range)"
            $VersusDetails = Test-IPv4CIDR -network $VersusNetwork.range
            $BIPStatus = Test-IPv4AddressInRange -IP $NetworkDetails.BIP -BIP $VersusDetails.BIP -EIP $VersusDetails.EIP
            $EIPStatus = Test-IPv4AddressInRange -IP $NetworkDetails.EIP -BIP $VersusDetails.BIP -EIP $VersusDetails.EIP
    
            if (($NetworkDetails.BIP -eq $VersusDetails.BIP) -and ($NetworkDetails.EIP -eq $VersusDetails.EIP)) {
            } else {
                # If the Network Beginning IP and Ending IP are not overlapping
                if (($EIPStatus -eq $true) -or ($BIPStatus -eq $true)) {
                    if ($NetworkDetails.CIDR -ge $VersusDetails.CIDR) {
                        Write-Host "$(Get-Timestamp) - Overlap detected."
                        Write-Host "$(Get-Timestamp) - Added Network: $($Network.range)"
                        Write-Host "$(Get-Timestamp) - Overlap Network: $($VersusNetwork.range)"
                        $RevisedNetworks.add($Network)
                        $OmitNetworks.add($VersusNetwork)
                        $OmitAddition = $true
                    } 
                }
            }
        }
    }
    if ($OmitAddition -eq $false) {
        Write-Host "$(Get-Timestamp) - Adding entry: $($Network.range) - No overlap detected."
        $RevisedNetworks.add($Network)
    }
    Write-Host "$(Get-Timestamp) - End - Entry: $($Network.range)"
}

$OmitResults = $($OmitNetworks | Sort-Object range -Unique)
Write-Host "$(Get-Timestamp) - Begin - Removing Omissions from Revised Networks"
ForEach ( $Omission in $OmitResults ) {
    $RevisedNetworks.remove($Omission) | Out-Null
    Write-Host "$(Get-Timestamp) - Removed: $($Omission.range)"
}
Write-Host "$(Get-Timestamp) - End - Removing Omissions from Revised Networks"
$Network = $null
# Loop through each LogRhythm Parent Entity
foreach ($ParentEntity in $Entities) {
    Write-Host "$(Get-Timestamp) - Processing Entity:$($ParentEntity.name)  EntityID:$($ParentEntity.Id)"
    foreach ($Network in $RevisedNetworks) {
        Write-Host "$(Get-TimeStamp) ----- New Csv Entry -----"
        # Convert CIDR to Network Object with Beginning IP, Ending IP, and Private IP Address status
        $NetworkDetails = Test-IPv4CIDR -Network $Network.range
        if ($NetworkDetails.IsValid -eq $true) {
            # Inspect the LogRhythm Entity Structure for a corresponding entry
            Write-Host "$(Get-Timestamp) - NetworkID Discovery: BIP=$($NetworkDetails.bip) EIP=$($NetworkDetails.eip) Entity=$($ParentEntity.name)"
            $NetworkStatus = Find-LrNetworkByIP -BIP $NetworkDetails.BIP -EIP $NetworkDetails.EIP -Entity $ParentEntity.name
            if ($NetworkStatus) {
                Write-Host "$(Get-Timestamp) - NetworkID Discovery Summary"
                Write-Host "$(Get-Timestamp) - ID: $($NetworkStatus.Id)  Entity: $($NetworkStatus.Entity.Id)"
                Write-Host "$(Get-Timestamp) - Name: $($NetworkStatus.Name)"
                Write-Host "$(Get-Timestamp) - BIP: $($NetworkStatus.BIP)  EIP: $($NetworkStatus.EIP)"
            }
            # Name - Add Entry to CSV Object
            $NameResults = Get-LrNetworks -name $Network.Title -Entity $ParentEntity.name -Exact -RecordStatus "All"
            [int]$NameCounter = 0
            if ($NameResults) {
                Write-Host "$(Get-Timestamp) - Network Name Discovery Summary"
                Write-Host "$(Get-Timestamp) - ID: $($NameResults.Id)  Entity: $($NameResults.Entity.Id)"
                Write-Host "$(Get-Timestamp) - Name: $($NameResults.Name)"
                Write-Host "$(Get-Timestamp) - BIP: $($NameResults.BIP)  EIP: $($NameResults.EIP)"
                if ((($NetworkStatus.id -ne $NameResults.id)) -and ($Network.title -eq $NameResults.name)) {
                    Write-Host "$(Get-Timestamp) - NetworkStatus ID: $($NetworkStatus.id)  NameResult Id: $($NameResults.id)"
                    Write-Host "$(Get-Timestamp) - Network Title: $($Network.Title)   NameResults Name: $($NameResults.name)"
                    <#
                    do {
                        $NameCounter += 1
                        Write-Host "$(Get-Timestamp) - NameResults Name: $($NameResults.name)"
                        if ($($NameResults.name) -match '^.*\s\d*$') {
                            $MatchedName = [regex]::match($NameResults.name, '^(.*)\s\d*$').Groups[1].Value
                            #$MatchedCounter = [regex]::Match("$($NameResults.name)",'^.*\s(\d*)$').Groups[1].Value
    
                            $UpdatedName = "$MatchedName $NameCounter"
                            Write-Host "$(Get-Timestamp) - Current Name: $UpdatedName"
                        } else {
                            $UpdatedName = "$($Network.Title) $NameCounter"
                            Write-Host "$(Get-Timestamp) - New Name: $UpdatedName"
                        }
                    } until ($null -eq $NameResults)
                    Write-Verbose "$(Get-Timestamp) - Updated Name: $UpdatedName"
                    #>
                }
                $UpdatedName = $Network.Title +" "+ $(Get-Random -Minimum 0 -Maximum 100000).ToString()
            } else {
                $UpdatedName = $null
            }
    
            # Establish Name to CSV Object
            if ($Network.Name) {
                if ($UpdatedName) {
                    $Network.name = $UpdatedName
                    $UpdatedName = $null
                }
                else {
                    $Network.name = $Network.Title
                }
            } else {
                if ($UpdatedName) {
                    $Network | Add-Member -MemberType NoteProperty -Name Name -Value $UpdatedName -PassThru | Out-Null
                    $UpdatedName = $null
                }
                else {
                    $Network | Add-Member -MemberType NoteProperty -Name Name -Value $Network.Title -PassThru | Out-Null
                }
            }
            
    
            # BIP - Add Entry to CSV Object
            if ($Network.bip) {
                $Network.bip = $NetworkDetails.BIP
            } else {
                $Network | Add-Member -MemberType NoteProperty -Name BIP -Value $NetworkDetails.BIP -PassThru | Out-Null
            }
    
            # EIP - Add Entry to CSV Object
            if ($Network.eip) {
                $Network.eip = $NetworkDetails.EIP
            } else {
                $Network | Add-Member -MemberType NoteProperty -Name EIP -Value $NetworkDetails.EIP -PassThru | Out-Null
            }
            
    
            # Record Status - Add Entry to CSV Object
            if ($Network.recordStatus) {
                $Network.recordstatus = "Active"
            } else {
                $Network | Add-Member -MemberType NoteProperty -Name RecordStatus -Value Active -PassThru | Out-Null
            }
            
    
            # Short Description - Add Entry to CSV Object
            if ($Network.Description) {
                $ShortDesc = $Network.Description   
            } else {
                $ShortDesc = "No short description provided from source import."
            }
            if ($Network.ShortDesc) {
                $Network.ShortDesc = $ShortDesc
            } else {
                $Network | Add-Member -MemberType NoteProperty -Name ShortDesc -Value $ShortDesc -PassThru | Out-Null
            }
            
    
            # Long Description - Add blank entry to CSV Object
            # Build and set Long Description
            $LongDesc = ""
            if ($Network.ADSite -ne "") {
                $LongDesc += "ADSite: $($Network.ADSite) "
            }
    
            if ($Network.RouterName -ne "") {
                $LongDesc += "Router Name: $($Network.RouterName) "
            }
    
            if ($Network.Gateway -ne "") {
                $LongDesc += "Gateway: $($Network.Gateway) "
            }
    
            if ($Network.CreationTime -ne "") {
                $LongDesc += "CreationTime: $($Network.CreationTime) "
            }
    
            if ($Network.DefaultGateway -ne "") {
                $LongDesc += "Default Gateway: $($Network.DefaultGateway) "
            }
    
            if ($Network.SubnetMask -ne "") {
                $LongDesc += "Subnet Mask: $($Network.SubnetMask) "
            } else {
                $LongDesc += "Subnet Mask: $($NetworkDetails.Subnet) "
            }
    
            if ($Network.Vlan -ne "") {
                $LongDesc += "VLAN: $($Network.Vlan) "
            } 
    
            if ($Network.NetworkType -ne "") {
                $LongDesc += "Network Type: $($Network.NetworkType) "
            } 
    
            # Location
            if (!$Network.location) {
                # Create Location field
                $Network | Add-Member -MemberType NoteProperty -Name location -Value $null -PassThru -force | Out-Null
            }
    
            if (!$Network.locationid) {
                # Create LocationId field
                $Network | Add-Member -MemberType NoteProperty -Name locationid -Value -1 -PassThru | Out-Null
            }
    
            # Populate Locations
            if ($null -eq $Network.LocationId) {
                Switch ($($Network.Location)) {
                    # Redlands CA - 17508   HQ - Redlands
                    {$_ -match '.*-\s*redlands'} { 
                        $Network.Location = "Redlands"
                        $Network.LocationId = 17508
                    }
    
                    # DC - 255              RO - DC
                    {$_ -match '.*-\s*dc.*'} { 
                        $Network.Location = "District of Columbia"
                        $Network.LocationId = 255
                    }
                    # Phoenix - 16715       SO - Phoenix
                    {$_ -match '.*-\s*phoenix'} { 
                        $Network.Location = "Phoenix"
                        $Network.LocationId = 16715
                    }
                    # Boston - 21871        RO - Boston
                    {$_ -match '.*-\s*boston'} { 
                        $Network.Location = "Boston"
                        $Network.LocationId = 21871
                    }
                    # Denver - 17853        RO - Denver
                    {$_ -match '.*-\s*denver.*'} { 
                        $Network.Location = "Denver"
                        $Network.LocationId = 17853
                    }
                    # Minneapolis - 23751   RO - Minneapolis
                    {$_ -match '.*-\s*minneapolis.*'} { 
                        $Network.Location = "Minneapolis"
                        $Network.LocationId = 23751
                    }
                    # Olympia, WA - 32264       RO - Olympia
                    {$_ -match '.*-\s*olympia.*'} { 
                        $Network.Location = "Olympia"
                        $Network.LocationId = 32264
                    }
                    # San Antonio, TX - 31093   RO - San Antonio
                    {$_ -match '.*-\s*san antonio.*'} { 
                        $Network.Location = "San Antonio"
                        $Network.LocationId = 31093
                    }
                    # St Louis, MI - 24428     RO - St. Louis
                    {$_ -match '.*-\s*st\. louis.*'} { 
                        $Network.Location = "St Louis"
                        $Network.LocationId = 24428
                    }
                    # Kansas - 265                 SO - Kansas
                    {$_ -match '.*-\s*Kansas.*'} { 
                        $Network.Location = "Kansas"
                        $Network.LocationId = 265
                    }
                    # Philadelphia - 29382       RO - Phildelphia
                    {$_ -match '.*-\s*phildelphia.*'} { 
                        $Network.Location = "Philadelphia"
                        $Network.LocationId = 29382
                    }
                    # Philadelphia - 29382       RO - Phildelphia
                    {$_ -match '.*-\s*philadelphia.*'} { 
                        $Network.Location = "Philadelphia"
                        $Network.LocationId = 29382
                    }
                    # Ohio - 285                SO - Ohio
                    {$_ -match '.*-\s*ohio.*'} { 
                        $Network.Location = "Ohio"
                        $Network.LocationId = 285
                    }
                    # Atlanta, GA -  18706      SO - Atlanta
                    {$_ -match '.*-\s*atlanta.*'} { 
                        $Network.Location = "Atlanta"
                        $Network.LocationId = 18706
                    }
                    # Beijing, China - 527      IO - China - Beijing
                    {$_ -match '.*-\s*beijing.*'} { 
                        $Network.Location = "Beijing"
                        $Network.LocationId = 527
                    }
                    # Ottawa, Ontario - 3950    IO - Canada - Ottawa
                    {$_ -match '.*-\s*ottawa.*'} { 
                        $Network.Location = "Ottawa"
                        $Network.LocationId = 3950
                    }
                    # Charlotte, NC - 24916     RO - Charlotte
                    {$_ -match '.*-\s*charlotte.*'} { 
                        $Network.Location = "Charlotte"
                        $Network.LocationId = 24916
                    }
                    # Sarjah, UAE - 69656       IO - UAE - Sharjah
                    {$_ -match '.*-\s*sharjah.*'} { 
                        $Network.Location = "Sharjah"
                        $Network.LocationId = 69656
                    }
    
                    # Zurich, Switcherland - 4849    IO - Switzerland - Zurich
                    {$_ -match '.*-\s*zurich.*'} { 
                        $Network.Location = "Zurich"
                        $Network.LocationId = 4849
                    }

                    # Edinburgh, UK - 65273          IO - UK - Edinburgh
                    {$_ -match '.*-\s*edinburgh.*'} { 
                        $Network.Location = "Edinburgh"
                        $Network.LocationId = 65273
                    }
                    
                    # Arlington, VA - 31424          SO - Arlington (GeoIQ)
                    {$_ -match '.*-\s*arlington.*'} { 
                        $Network.Location = "Arlington"
                        $Network.LocationId = 31424
                    }
                    # Melbourne, Australia - 64384   IO - Australia - Melbourne (Maptel)
                    {$_ -match '.*-\s*melbourne.*'} { 
                        $Network.Location = "Melbourne"
                        $Network.LocationId = 64384
                    }
                    # Chicago, Illinois - 19895       SO - Chicago
                    {$_ -match '.*-\s*chicago.*'} { 
                        $Network.Location = "Chicago"
                        $Network.LocationId = 19895
                    }
                    # Hawaii - 260                    SO - Hawaii
                    {$_ -match '.*-\s*hawaii.*'} { 
                        $Network.Location = "Hawaii"
                        $Network.LocationId = 260
                    }
                    # Dallas, TX - 30594     SO - Dallas
                    {$_ -match '.*-\s*dallas.*'} { 
                        $Network.Location = "Dallas"
                        $Network.LocationId = 30594
                    }
                    # New York, NY - 27117   SO - New York
                    {$_ -match '.*-\s*new york.*'} { 
                        $Network.Location = "New York"
                        $Network.LocationId = 27117
                    }
                    # Portland, Maine - 22780         SO - Portland ME
                    {$_ -match '.*-\s*portland me.*'} { 
                        $Network.Location = "Portland"
                        $Network.LocationId = 22780
                    }
                    # Portland, OR #2 28611 - SO - Portland OR (Geoloqi)
                    {$_ -match '.*-\s*portland or.*'} { 
                        $Network.Location = "Portland"
                        $Network.LocationId = 28611
                    }
                    # Mumbai, India - 9181    IO - India - Mumbai (Cybertech)
                    {$_ -match '.*-\s*Mumbai.*'} { 
                        $Network.Location = "Mumbai"
                        $Network.LocationId = 9181
                    }
                    # Aylesbury, UK - 65292     IO - UK - Aylesbury (EDT)
                    {$_ -match '.*-\s*aylesbury.*'} { 
                        $Network.Location = "Aylesbury"
                        $Network.LocationId = 65292
                    }
                    # Cachan, France - 8151     IO - France - Cachan (Cartonet)
                    {$_ -match '.*-\s*cachan.*'} { 
                        $Network.Location = "Cachan"
                        $Network.LocationId = 8151
                    }
                    # Sacramento, CA - 17542        SO - Sacramento
                    {$_ -match '.*-\s*sacramento.*'} { 
                        $Network.Location = "Sacramento"
                        $Network.LocationId = 17542
                    }
                    # Johnstown, PA - 29124         SO - Johnstown
                    {$_ -match '.*-\s*johnstown.*'} { 
                        $Network.Location = "Johnstown"
                        $Network.LocationId = 29124
                    }
                    # Albany, NY - 26592           SO - Albany
                    {$_ -match '.*-\s*albany.*'} { 
                        $Network.Location = "Albany"
                        $Network.LocationId = 26592
                    }
                    # Pleasant Hill, CA  - 17476             SO - Pleasant Hill
                    {$_ -match '.*-\s*pleasant hill.*'} { 
                        $Network.Location = "Pleasant Hill"
                        $Network.LocationId = 17476
                    }
                    # Singapore - 14483        IO - Singapore - Singapore
                    {$_ -match '.*-\s*singapore.*'} { 
                        $Network.Location = "Singapore"
                        $Network.LocationId = 14483
                    }
                    # Rotterdam, NL - 12221    IO - Netherlands - Rotterdam
                    {$_ -match '.*-\s*rotterdam.*'} { 
                        $Network.Location = "Rotterdam"
                        $Network.LocationId = 12221
                    }
                    # Dubai, UAE - 1475       IO - UAE - Dubai
                    {$_ -match '.*-\s*dubai.*'} { 
                        $Network.Location = "Dubai"
                        $Network.LocationId = 1475
                    }
                    # Kuala Lumpur, Malaysia - 11697       IO - Malaysia - Kuala Lumpur (ISC)
                    {$_ -match '.*-\s*kuala lumpur.*'} { 
                        $Network.Location = "Kuala Lumpur"
                        $Network.LocationId = 11697
                    }
                    # Mesa, AR -  16693      Mesa
                    {$_ -match '.*-\s*mesa.*'} { 
                        $Network.Location = "Mesa"
                        $Network.LocationId = 16693
                    }
                    #  Is this IO??  Miami, FL -  18528      IO - Miami
                    {$_ -match '.*-\s*miami.*'} { 
                        $Network.Location = "Miami"
                        $Network.LocationId = 18528
                    }
                    # Cardiff, UK - 65330   IO - UK - Cardiff
                    {$_ -match '.*-\s*cardiff.*'} { 
                        $Network.Location = "Cardiff"
                        $Network.LocationId = 65330
                    }
                    # Houston, TX  - 30766   SO - Houston
                    {$_ -match '.*-\s*Houston.*'} { 
                        $Network.Location = "Houston"
                        $Network.LocationId = 30766
                    }
                    # Singapore - 14483   IO - Singapore - Singapore
                    {$_ -match '.*-\s*singapore.*'} { 
                        $Network.Location = "Singapore"
                        $Network.LocationId = 14483
                    }
                    default {                    
                        $Network.Location = ""
                        $Network.LocationId = -1
                    }
                }
                $LongDesc += "Location: $($Network.Location) "
            } else {
                $Network.Location = ""
                $Network.LocationId = -1
                $LongDesc += "Location: $($Network.Location) "
            }
    
            if ($Network.Contact -ne "") {
                $LongDesc += "Contact: $($Network.Contact) "
            } 
    
            if ($Network.Lat -ne "") {
                $LongDesc += "Latitude: $($Network.Lat) "
            } 
    
            if ($Network.Long -ne "") {
                $LongDesc += "Longitude: $($Network.Long) "
            } 
    
    
            if ($Network.longdesc) {
                # Update LongDesc
                $Network.LongDesc = $LongDesc
            } else {
                $Network | Add-Member -MemberType NoteProperty -Name LongDesc -Value $LongDesc -PassThru | Out-Null
            }
            
            # Set defaults for null values
            if ($Network.Entity) {
                $Network.Entity = $ParentEntity.name
            } else {
                $Network | Add-Member -MemberType NoteProperty -Name Entity -Value $ParentEntity.name -PassThru | Out-Null
            }

            if ($Network.EntityId) {
                $Network.EntityId = $ParentEntity.Id
            } else {
                $Network | Add-Member -MemberType NoteProperty -Name EntityId -Value $ParentEntity.Id -PassThru | Out-Null
            }
    
            # Assign RiskLevel
            if ($Network.RiskLevel) {
                $Network.RiskLevel = "None"
            } else {
                $Network | Add-Member -MemberType NoteProperty -Name RiskLevel -Value "None" -PassThru | Out-Null
            }
    
            # Assign ThreatLevel
            if ($Network.Threatlevel) {
                $Network.ThreatLevel = "None"
            } else {
                $Network | Add-Member -MemberType NoteProperty -Name ThreatLevel -Value "None" -PassThru | Out-Null
            }
    
            # Assing Zone
            if(($Network.Name -match $RegexDMZ) -or ($Network.NetworkType -match $RegexDMZ)) {
                Write-Host "$(Get-Timestamp) - Network Zone: Set to DMZ based on Regex Match:DMZ to Name, ShortDesc, or Location"
                $Zone = "DMZ"
            } elseif (($Network.Name -match $RegexPublic) -or ($Network.NetworkType -match $RegexPublic)) {
                Write-Host "$(Get-Timestamp) - Network Zone: Set to External based on Regex Match:Public to Name, ShortDesc, or Location"
                $Zone = "DMZ"
            } elseif (($Network.Name -match $RegexExternal) -or ($Network.NetworkType -match $RegexExternal) -or ($NetworkDetails.IsPrivate -eq $false)) {
                Write-Host "$(Get-Timestamp) - Network Zone: Set to External based on Regex Match:External to Name, ShortDesc, or Location"
                $Zone = "External"
            } else {
                $Zone = "Internal"
            }
    
            if ($Network.Zone) {
                $Network.Zone = $Zone
            } else {
                $Network | Add-Member -MemberType NoteProperty -Name Zone -Value $Zone -PassThru | Out-Null
            }
    
    
            # If Network Record exists, maintain current record's Risk and Threat levels.
            if ($NetworkStatus) {
                Write-Host "$(Get-Timestamp) - NetworkID Discovery: $($NetworkStatus.id)"
                $LRNetworkDetails = Get-LrNetworkDetails -Id $($NetworkStatus.id)
                $Network.RiskLevel = $LRNetworkDetails.RiskLevel
                $Network.ThreatLevel = $LRNetworkDetails.ThreatLevel
            }
    
    
    
    
        } else {
            Write-Host "$(Get-TimeStamp) CidrNetwork: $CidrNetwork not not able to validate through Test-IPv4CIDR."
            Write-Host "$(Get-Timestamp) Lookup results: $CidrNetwork" 
        }
    
        # Check if Network exists in LR Entity
        
        
    
        
    
        # If network does not exist, create it.  Else, update it.
        if (($NetworkStatus.Note -eq "NetworkID Discovery: No Network found") -or ($null -eq $NetworkStatus)) {
            $NetUpdate = $Network | New-LrNetwork 
            if ($NetUpdate.Error -eq "True") {
                Write-Host "$(Get-Timestamp) - Unable to create network for entry: $Network" 
                Write-Host "$(Get-Timestamp) - Error: $NetUpdate"
            } else {
                Write-Host "$(Get-Timestamp) - Created Network ID: $($NetUpdate.Id)  Name: $($NetUpdate.Name)"
            }
        } else {
            Write-Host "$(Get-Timestamp) - Updating Network: $($Network.Name)"
            $NetUpdate = $Network | Update-LrNetwork -id $NetworkStatus.id
            if ($NetUpdate.Error -eq "True") {
                Write-Host "$(Get-Timestamp) - Network Update Error: $NetUpdate"
            } else {
                Write-Host "$(Get-Timestamp) - Sucessfully updated Network ID:$($NetUpdate.Id)  Name: $($NetUpdate.Name)"
            }
        }

        start-sleep -seconds .8
        Write-Host "$(Get-Timestamp) ----- End Csv Entry -----"
    }
}
