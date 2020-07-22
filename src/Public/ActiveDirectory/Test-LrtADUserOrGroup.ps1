using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Test-LrtADUserOrGroup {
    <#
    .SYNOPSIS
        Determine if an Identity is a valid ADUser or ADGroup in the directory.
    .DESCRIPTION
        The Test-LrtADUserOrGroup cmdlet determines if an Identity
        can be resolved to an existing ADUser or ADGroup in the
        current AD Domain.
        If the specified Identity cannot be resolved, this cmdlet does 
        not generate any output.
    .PARAMETER Identity
        (Mandatory) [object] to validate as an existing ADUser or ADGroup.
        For example, you could pass an ADUser object, an ADGroup object or
        the string "john.smith".
    .INPUTS
        This cmdlet does not accept pipeline input.
    .OUTPUTS
        None, System.Type
        If the specified Identity cannot be resolved, this cmdlet does not generate any output.

        If the specified Identity is resolved to an existing User, a [Microsoft.ActiveDirectory.Management.ADUser] 
        type reference will be returned.

        If the specified Identity is resolved to an existing User, a [Microsoft.ActiveDirectory.Management.ADGroup] 
        type reference will be returned.
    .EXAMPLE
        PS C:\> Test-LrtADUserOrGroup "bobsmith"
        [Microsoft.ActiveDirectory.Management.ADUser]
        PS C:\>
        Description: Test if the string "bobsmith" is a valid user or group. In this case, it is a valid user,
        so the System.Type for ADUser is returned.
    .EXAMPLE
        xxxx
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    #region: Parameters
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0, ValueFromPipeline=$true)]
        [object] $Identity
    )
    # ADUser
    try {
        $x = Get-ADUser -Identity $Identity
        return $x.GetType()
    }
    catch { }

    try {
        $x = Get-ADGroup -Identity $Identity
        return $x.GetType()
    }
    catch { }
}