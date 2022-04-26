using namespace System
using namespace System.IO
using namespace System.Text
using namespace System.Collections.Generic
using namespace System.Net.Http

Function Import-LrPlaybook {
    <#
    .SYNOPSIS
        Import a new playbook for LogRhythm case use.
    .DESCRIPTION
        The Import-LrPlaybook cmdlet adds a playbook to LogRhythm.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .INPUTS
        [System.Object] "Id" ==> [Id] : The ID of the Case to modify.
    .OUTPUTS
        PSCustomObject representing the added playbook.
    .EXAMPLE
        PS C:\> 
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

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string] $Playbook
    )


    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","multipart/form-data")
        #$Headers.Add("Boundary","$Boundary")

        # Request Method
        $Method = $HttpMethod.Post

        # Int reference
        $_int = 1
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            ResponseUrl           =   $null
            Value                 =   $Playbook
        }

        if (Test-Path -path $Playbook) {
            $FileName = split-path $Playbook -leaf
        } else {
            $ErrorObject.Error = $true 
            $ErrorObject.Note = "Provided path is not resolvable.  Please provide a full path to the LogRhythm Playbook."
            return $ErrorObject
        }

        $RequestUrl = $BaseUrl + "/lr-case-api/playbooks/import"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"


        if (-not $ContentType)
        {
            Add-Type -AssemblyName System.Web

            $mimeType = [System.Web.MimeMapping]::GetMimeMapping($File)
            
            if ($mimeType)
            {
                $ContentType = $mimeType
            }
            else
            {
                $ContentType = "application/octet-stream"
            }
        }

        $httpClientHandler = New-Object System.Net.Http.HttpClientHandler
        $httpClient = New-Object System.Net.Http.Httpclient $httpClientHandler
        $httpClient.DefaultRequestHeaders.add("Authorization", "Bearer $Token")
        $packageFileStream = New-Object System.IO.FileStream @($File, [System.IO.FileMode]::Open)
        $contentDispositionHeaderValue = New-Object System.Net.Http.Headers.ContentDispositionHeaderValue "form-data"
	    $contentDispositionHeaderValue.Name = "file"
        $contentDispositionHeaderValue.FileName = (Split-Path $File -leaf)
        
        $streamContent = New-Object System.Net.Http.StreamContent $packageFileStream
        $streamContent.Headers.ContentDisposition = $contentDispositionHeaderValue
        $streamContent.Headers.ContentType = New-Object System.Net.Http.Headers.MediaTypeHeaderValue $ContentType
        
        $content = New-Object System.Net.Http.MultipartFormDataContent
        $content.Add($streamContent)


        try
        {
			$response = $httpClient.PostAsync($RequestUrl, $content).Result

			if (!$response.IsSuccessStatusCode)
			{
				$responseBody = $response.Content.ReadAsStringAsync().Result
				$errorMessage = "Status code {0}. Reason {1}. Server reported the following message: {2}." -f $response.StatusCode, $response.ReasonPhrase, $responseBody

				throw [System.Net.Http.HttpRequestException] $errorMessage
			}

			return $response.Content.ReadAsStringAsync().Result
        }
        catch [Exception]
        {
			$PSCmdlet.ThrowTerminatingError($_)
        }
        finally
        {
            if($null -ne $httpClient)
            {
                $httpClient.Dispose()
            }

            if($null -ne $response)
            {
                $response.Dispose()
            }
        }

        return $Response
    }


    End { }
}