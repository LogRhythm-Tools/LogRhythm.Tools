using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrHostIdentifiers {
    <#
    .SYNOPSIS
        Retrieve the Host Identifiers for a specific host from the LogRhythm Entity structure.
    .DESCRIPTION
        Get-LrHostIdentifiers returns a full LogRhythm Host object with host Identifier information.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Id
        [System.String] (Name or Int)
        Specifies a LogRhythm host object by providing one of the following property values:
          + List Name (as System.String), e.g. "MYSECRETHOST"
          + List Int (as System.Int), e.g. 2657

        Can be passed as ValueFromPipeline but does not support Arrays.
    .OUTPUTS
        PSCustomObject representing LogRhythm Entity Host record and its contents.
    .EXAMPLE
        PS C:\> Get-LrHostIdentifiers -Credential $MyKey -Id "2657"
        ----
        type        value                         dateAssigned
        ----        -----                         ------------
        WindowsName MYSECRETHOST                  2019-10-25T17:07:05.65Z
        IPAddress   10.1.1.5                      2019-10-25T19:15:47.943Z
        DNSName     mysecrethost.example.com      2019-12-02T18:23:17.003Z

    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,

        [Parameter(Mandatory = $true, ValueFromPipeline=$true, Position = 1)]
        [ValidateNotNull()]
        [object] $Id
    )

    Begin {
        $_int = 0
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Value                 =   $Id
            Note                  =   $null
        }
        

        # Check if ID value is an integer
        if ([int]::TryParse($Id, [ref]$_int)) {
            Write-Verbose "[$Me]: Id parses as integer."
            $Guid = $Id
        } else {
            Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
            $Guid = Get-LrHosts -Name $Id -Exact | Select-Object -ExpandProperty id
            if (!$Guid) {
                $ErrorObject.Error = $true
                $ErrorObject.Note = "Id String [$Id] not found in LrHosts List."
            }
        }

        if ($ErrorObject.Error -eq $false) {
            $Results = Get-LrHostDetails -Id $Id | Select-Object -ExpandProperty hostIdentifiers
        } else {
            return $ErrorObject
        }

        return $Results
    }

    End { }
}