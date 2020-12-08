param (
    [Parameter(Mandatory=$true,Position=0)][int32]$AlarmId,
    [Parameter(Mandatory=$false,Position=1)][string]$CaseSummary,
    [Parameter(Mandatory=$false,Position=2)][string]$DefaultCaseTag,
	[Parameter(Mandatory=$false,Position=3)][string]$Playbook,
    [Parameter(Mandatory=$false,Position=4)][string]$TagOriginUsers  = "false",
    [Parameter(Mandatory=$false,Position=5)][string]$TagImpactedUsers  = "false",
	[Parameter(Mandatory=$false,Position=6)][string]$TagOriginHosts = "false",
    [Parameter(Mandatory=$false,Position=7)][string]$TagImpactedHosts = "false",
	[Parameter(Mandatory=$false,Position=8)][string]$BindAlarmToExistingCase
 )
 
import-module logrhythm.tools

if ($null -eq $CaseSummary) {
	$CaseSummary = "The SmartResponse should be configured with a default case summary."
}

$Results = new-lrcasehelper -AlarmId $AlarmId -CaseSummary $CaseSummary -TagOriginUsers $TagOriginUsers -TagImpactedUsers $TagImpactedUsers -TagOriginHosts $TagOriginHosts -TagImpactedHosts $TagImpactedHosts -BindAlarmToExistingCase $BindAlarmToExistingCase -Playbook $Playbook -PassThru

Write-Host $Results
return 0