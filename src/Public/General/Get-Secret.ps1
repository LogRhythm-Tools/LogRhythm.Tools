using namespace System
using namespace System.Net

Function Get-Secret {
    <#
    .SYNOPSIS
        Retrieve SecretServer credentials.
    .DESCRIPTION
        Uses Thycotic Secret Server SOAP Api to obtain the requested Secret, by its ID
        and returns them to the user as a PSCredential.
    .PARAMETER SecretId
        ID correcsponding to a stored credential in Secret Server. 
        You can find this by examining the URL of a SecretView page. Example:
        https://secretserver.domain.com/SecretView.aspx?secretid=12345
    .PARAMETER Credential
        (Optional) [PSCredential] object to authenticate to Secret Server. By default, 
        the caller's account (DefaultCredential) will be used for authentication.
    .PARAMETER AuthFilePath
        (Optional) Path to serialized [PSCredential] object for authenticating to 
        Secret Server. You can store a [PSCredential] in a file with the following 
        command:

            PS C:\> Get-Credential | Export-CliXml -Path \path\to\credfile.xml
    .INPUTS
        [int] => SecretId
    .OUTPUTS
        A [PSCredential] object for the requested secret.
    .NOTES
        ** Callers should consider using a Try/Catch block when using Get-Secret. **

        If any error occurs during execution of the Get-Secret cmdlet, an exception will 
        be thrown, some of which may be non-terminating for upstream scripts. Try/Catch
        will ensure you know if there was any issue or not.
    .EXAMPLE
        PS C:\> $SvcAccount = Get-Secret -SecretId 12345
        ---
        Description: Gets [PSCredential] for Secret Id 12345 with your default crednetials.
    .EXAMPLE
        PS C:\> $MyCred = 56335 | Get-Secret -Credential $SvcAccount
        ---
        Description: Authenticate to SecretServer using credentials in $SvcAccount to
        retrieve the Secret Id 56335 into $MyCred
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>
    #region: Parameters                                                                  
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, ValueFromPipeline = $true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [int] $SecretId,

        [Parameter(Mandatory=$false,Position=1)]
        [pscredential] $Credential,

        [Parameter(Mandatory=$false, Position=2)]
        [string] $AuthFilePath,

        [Parameter(Mandatory=$false, Position=3)]
        [string] $SecretServerUrl = $LrtConfig.SecretServer.BaseUrl
    )
    #endregion


    Begin {
        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy


        # Load Credential File if provided.
        if ($AuthFilePath) {
            if (Test-Path $AuthFilePath) {
                Write-Verbose "[$Me] Loading SecretServer credential from: $AuthFilePath"
                try {
                    $Credential = Import-CliXml -Path $AuthFilePath
                } catch { $PSCmdlet.ThrowTerminatingError($PSItem) }
            } else {
                throw [exception] "Unable to find credential file at: $AuthFilePath"
            }
        }


        # Create WebServiceProxy for SecretServer Soap API
        try {
            if ($Credential) {
                Write-Verbose "[$Me] SecretServer authenticating with credential $($Credential.UserName)"
                $SecretServerService = New-WebServiceProxy -uri $SecretServerUrl -Credential $Credential -ErrorAction Stop
            } else {
                $SecretServerService = New-WebServiceProxy -uri $SecretServerUrl -UseDefaultCredential -ErrorAction Stop
            }
        }
        catch [Exception] {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }



    Process {
        # Get Secret
        try {
            $RequestResult = $SecretServerService.GetSecret($SecretId, $false, $null)
        } catch [Exception] {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
        
        # Convert to PSCredential object.
        if ($RequestResult.Errors.length -gt 0) {
            throw [WebException]::new($RequestResult.Errors)
        } else {
            $SecurePass = ConvertTo-SecureString -String  $RequestResult.Secret.Items[2].Value -AsPlainText -Force
            $ReturnCredential = [pscredential]::new($RequestResult.Secret.Items[1].Value, $SecurePass)
        }

        return $ReturnCredential
    }



    End { }
}