using namespace System.IO

Function New-LrtCredXml {
    <#
    .SYNOPSIS
        Create PSCredential stored in XML file format
    .DESCRIPTION
        Allows the storing of PSCredential witthout requiring a user prompt.

        If saving the credxml fails for any reason, the New-LrtCredXml cmdlet
        will still return the created credential in its output object.
    .PARAMETER Username
        Name that will be stored in the Username field of the PSCredential.
    .PARAMETER Secret
        There are two methods of supplying the password for the PSCredential:

        1. Providing a plaintext value the Secret parameter.

        2. Not providing the Secret parameter - the New-LrtCredXml cmdlet will prompt
        for a password to be entered, which will be masked and processed as a secure string.
    .PARAMETER Path
        The path to a directory where the file will be stored.  If not specified, path will default to current directory.
    .PARAMETER FileName
        The name of the target credential file.
    .INPUTS
        None
    .OUTPUTS
        ---------------------------------------------------
        [PSCustomObject]  Summary of new credential creation
        ---------------------------------------------------
        Successful = [bool]
        Username   = [string]
        Path       = [DirectoryInfo]
        FileName   = [string]
        Credential = [pscredential]
    .EXAMPLE
        Supplying a plain text password:

        PS C:\> New-LRTCredXml -Username "Frank" -Secret "abcd1234" -Path c:\tmp\ -FileName MyCred

        Successful : True
        Username   : Frank
        Path       : c:\tmp\
        FileName   : MyCred
        Credential : System.Management.Automation.PSCredential
    .EXAMPLE
        Prompt for a password:

        PS C:\> New-LRTCredXml -Username "Bob" -Path c:\tmp
        Enter Password: ********

        Successful : True
        Username   : Bob
        Path       : c:\tmp
        FileName   : Bob.xml
        Credential : System.Management.Automation.PSCredential
    .NOTES
        SmartResponse.Framework
    .LINK
        https://github.com/SmartResponse-Framework/SmartResponse.Framework
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNull()]
        [string] $Username,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $Secret,


        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [DirectoryInfo] $Path,

        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string] $FileName
    )


    #[securestring]$password = ConvertTo-SecureString $Password -AsPlainText -Force
    #[pscredential]$Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $Password
    $Response = [PSCustomObject]@{
        Successful = $false
        Username   = $Username
        Path       = $null
        FileName   = ""
        Credential = $null
    }


    # Validate Path
    if (! $Path.Exists) {
        Write-Warning "Path not specified as a directory. Using current directory: ($PSScriptRoot)"
        $Path = [DirectoryInfo]::new($PSScriptRoot)
    }
    $Response.Path = $Path


    # Validate FileName
    if ([string]::IsNullOrEmpty($FileName)) {
        $FileName = $Username + ".xml"
    }
    $Response.FileName = $FileName


    # Prompt for secret if not specified
    if ([string]::IsNullOrEmpty($Secret)) {
        $Password = Read-Host -AsSecureString -Prompt "Enter Password"
    } else {
        $Password = $Secret | ConvertTo-SecureString -AsPlainText -Force
    }


    # Create Credential
    $cred = [pscredential]::new($Username, $Password)
    $Response.Credential = $cred


    # Save Credential
    try {
        $cred | Export-CliXml (Join-Path -Path $Path.FullName -ChildPath $FileName)
        $Response.Successful = $true
    } catch {
        Write-Warning $PSItem.Exception.Message
    }


    return $Response
}