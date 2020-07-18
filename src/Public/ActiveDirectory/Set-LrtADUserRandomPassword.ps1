using namespace System

Function Set-LrtADUserRandomPassword {
    <#
    .SYNOPSIS
        Randomly set a new password for user account.
    .PARAMETER Identity
        AD User Account for password change.
    .PARAMETER SecretId
        Secret Server Account Id with which to perform the action.
    .EXAMPLE
        Set-LrtADUserPassword -Identity testuser -SecretId 121212
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,Position=0)]
        [string] $Identity,

        [Parameter(Mandatory = $false, Position=2)]
        [ValidateLength(8, 120)]
        [string] $DesiredPw,

        [Parameter(Mandatory=$True,Position=1)]
        [pscredential] $Credential
    )

    $ThisFunction = $MyInvocation.MyCommand

    # Check User Account
    if (!(Test-LrtADUserExists $Identity)) {
        Write-Verbose "[$ThisFunction]: Could not find user [$Identity]"
        return $false
    }

    # Create Password SecureString
    if ($DesiredPw) {
        $SecurePass = ConvertTo-SecureString `
            -AsPlainText `
            -Force `
            -String $DesiredPw
    } else {
        $SecurePass =  ConvertTo-SecureString `
            -AsPlainText `
            -Force `
            -String ([Web.Security.Membership]::GeneratePassword(20,1))
    }

    # Set Password
    # TODO: Use the 4 option version of Set-ADAccountPassword
    try {
        Set-ADAccountPassword -Identity $Identity -NewPassword $SecurePass -Reset -PassThru -Credential $Credential | Set-ADuser -ChangePasswordAtLogon $true
    }
    catch {
        Write-Verbose "[$ThisFunction]: Error encoutered while changing password for [$Identity]"
        return $False
    }

    # check PasswordExpired and PasswordLastSet
    $Result = Get-LrtADUserInfo -Identity $Identity

    # note: the combo above sets the PasswordLastSet property to $null for some reason - a bug in the AD powershell commands maybe
    # therefore compare the PasswordAge to null, as it is not calculated in Get-LrtADUserInfo if the property is null
    return ($Result.PasswordExpired -And ($null -eq $Result.PasswordAge))
}