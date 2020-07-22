[CmdletBinding()] 
Param(  
    [Parameter(Mandatory=$True)] 
    [string]$Scope
)
Try {
    Start-Job -InitializationScript { Import-Module LogRhythm.Tools } -ScriptBlock {Invoke-RfSync -SyncScope $args} -ArgumentList $Scope
    Write-Host "$(Get-TimeStamp) - Started: Invoke-RfSync Scope: $Scope"
} Catch {
    Write-Host "Unable to start background Recorded Future Sync task.  Please run Invoke-RfSync manually on configured Sync asset."
}