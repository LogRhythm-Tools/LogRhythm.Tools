using namespace System

Get-Module ActiveDirectory | Remove-Module
#Requires -Modules ActiveDirectory

Function Disable-SrfADUser {
    <#
    .SYNOPSIS
        Disable an Active Directory user account.
    .PARAMETER Identity
        AD User Account to disable
    .PARAMETER Credential
        [pscredential] Credentials to use for local auth.
        Default: Current User
    .EXAMPLE
        Disable-SrfADUser -Identity testuser -Credential (Get-Credential)
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Identity,
        [Parameter(Mandatory=$true,Position=1)]
        [pscredential] $Credential
    )
    $ThisFunction = $MyInvocation.MyCommand

    # Get Domain
    $Domain = Get-ADDomain
    if (!$Domain) {
        Write-Verbose "[$ThisFunction]: Could not determine current domain."
        return $false
    }

    # Check User Account
    if (!(Test-SrfADUserExists $Identity)) {
        Write-Verbose "[$ThisFunction]: Could not find user [$Identity]."
        return $false
    }

    try {
        Get-ADUser -Identity $Identity | Disable-ADAccount -Credential $Credential -ErrorAction Stop
    }
    catch [exception] {
        Write-Verbose "[$ThisFunction]: Error encoutered while trying to disable [$Identity]"
        return $false
    }

    $Detail = Get-ADUser -Identity $Identity -Properties Enabled
    if (-not ($Detail.Enabled)) {
        Write-Verbose "Account successfully disabled."
        return $true
    } else {
        return $false
    }
}