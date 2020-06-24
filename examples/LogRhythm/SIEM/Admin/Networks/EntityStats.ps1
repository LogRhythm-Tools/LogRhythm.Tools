# Pull some stats

#Regex to help find DMZ and External networks.
[regex]$RegexDMZ = '^.*(?<tag>[dD][mM][zZ]).*$'
[regex]$RegexPublic = '^.*(?<tag>[pP][uU][bB][lL][iI][cC]).*$'
[regex]$RegexExternal = '^.*(?<tag>[eE][xX][tT][eE][rR][nN][aA][lL]).*$'

# Retrieve Network Entities
$EntityList = Get-LrNetworks
Write-Host "Network Entities Count: $($EntityList.Count)"
Write-Host "Network Entities in Zone:DMZ Count:" $($EntityList | Where-Object hostZone -like "DMZ" | Measure-Object | Select-Object -ExpandProperty Count)
Write-Host "Network Entities in Zone:External Count:" $($EntityList | Where-Object hostZone -like "External" | Measure-Object | Select-Object -ExpandProperty Count)
Write-Host "Network Entities in Zone:Internal Count:" $($EntityList | Where-Object hostZone -like "Internal" | Measure-Object | Select-Object -ExpandProperty Count)

Write-Host $($EntityList | Where-Object hostZone -like "External")

Write-Host "Network Entities Counts with DMZ, External, Public referenced in Short Description."
Write-Host "DMZ contained in ShortDesc:"$($EntityList | Where-Object hostZone -notlike "DMZ" | Where-Object ShortDesc -Match $RegexDMZ | Measure-Object | Select-Object -ExpandProperty Count)
Write-Host "External contained in ShortDesc:"$($EntityList | Where-Object hostZone -notlike "External" | Where-Object ShortDesc -Match $RegexExternal | Measure-Object | Select-Object -ExpandProperty Count)
Write-Host "Public contained in ShortDesc:"$($EntityList | Where-Object hostZone -notlike "External" | Where-Object ShortDesc -Match $RegexPublic | Measure-Object | Select-Object -ExpandProperty Count)
