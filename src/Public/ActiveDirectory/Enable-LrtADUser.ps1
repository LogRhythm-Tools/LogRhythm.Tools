using namespace System

Function Enable-LrtADUser {
    <#
    .SYNOPSIS
        Disable an Active Directory user account.
    .PARAMETER Identity
        AD User Account to disable
    .PARAMETER Credential
        [pscredential] Credentials to use for local auth.
        Default: Current User
    .EXAMPLE
        Disable-LrtADUser -Identity bobsmith -Credential (Get-Credential)
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Identity,
        [Parameter(Mandatory=$true,Position=1)]
        [pscredential] $Credential
    )
    $ThisFunction = $MyInvocation.MyCommand
    $Verbose = $false
    if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
        $Verbose = $true
    }

    # Get Domain
    $Domain = Get-ADDomain
    if (!$Domain) {
        Write-Verbose "[$ThisFunction]: Could not determine current domain."
        return $false
    }

    # Check User Account
    if (!(Test-SrfADUserExists $Identity)) {
        Write-Verbose "[$ThisFunction]: Could not find user [$Identity]"
        return $false
    }

    try {
        Get-ADUser -Identity $Identity | Enable-ADAccount -Credential $Credential -ErrorAction Stop
    }
    catch [exception] {
        Write-Verbose "[$ThisFunction]: Error encoutered while trying to enable [$Identity]"
        return $false
    }

    $Detail = Get-ADUser -Identity $Identity -Properties Enabled
    if ($Detail.Enabled) {
        Write-Verbose "Account successfully enabled"
        return $true
    } else {
        return $false
    }
}