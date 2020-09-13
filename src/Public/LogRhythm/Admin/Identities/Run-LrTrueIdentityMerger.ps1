using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Run-LrTrueIdentityConflictMerger {
    <#
    .SYNOPSIS
        Merge a list of Identifier Conflicts for LogRhythm 7.4.

        This cmdlet is currently under development.
    .DESCRIPTION
        A TrueIdentity "Conflict" is when two TrueIdentities share the same Identifier
        This is common if multiple Active Directory domains are synced; any user with an account in both Domains will likely create a Conflict
    .PARAMETER EntityId
        Optional long
        Only search for conflicts within this Root EntityId
        Recommended when IdentityEntitySegregation has been enabled in the Data Processor(s)
    .EXAMPLE
        PS C:\> Run-LrTrueIdentityMerger
        ----
        This cmdlet is currently under development.
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>
    
    [CmdletBinding()]
    param( 
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [long] $EntityId = 1,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 1)]
        [bool] $OutputPath,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 2)]
        [bool] $TestMode = $true,


        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        $Version = 0.1
        function Show-Menu
        {
        param (
               [string] $Title = "TrueIdentity Conflict Merger - Version: $Version"
        )
            Clear-Host
            Write-Host "================ $Title ================"
            Write-Host " *** THIS CMDLET IS CURRENTLY UNDER DEVELOPMENT *** "
            Write-Host "1: Identity Conflicts via API"
            Write-Host "2: Load Identity Conflicts from File"
            Write-Host "3: Begin "
            Write-Host "Q: Press 'Q' to quit."
            Write-Host " *** THIS CMDLET IS CURRENTLY UNDER DEVELOPMENT *** "
        }
    }


    Process {
            do {
                Show-Menu
                $input = Read-Host "Please make a selection"
                switch ($input)
                {
                    '1' {
                        Try {
                            $IdentityConflicts = Get-LrIdentityConflicts -Entity $EntityId
                        } Catch {
                            Write-Host "Unable to load Identity Conflicts"
                        }
                        Write-Host "Identity Conflicts loaded: $($IdentityConflicts.count)"
                    } '2' {
                        'You chose option #2'
                    } '3' {
                        Clear-Host
                        'You chose option #3'
                    } 'q' {
                        return
                    }
                }
                pause
            }
            until ($input -eq 'q')
        ForEach ($Conflict in $IdentityConflicts) {
        
        }

    }

    End {

    }

}