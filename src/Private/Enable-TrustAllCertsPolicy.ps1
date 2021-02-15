using namespace System
using namespace System.Net
using namespace System.Collections.Generic
using namespace System.Reflection

Function Enable-TrustAllCertsPolicy {
    <#
    .SYNOPSIS
        Trust all SSL certificates even if self-signed, and set protocol to Tls 1.2.
    #>
    [CmdletBinding()]
    Param()
    # Establish Certification Policy Exception
    $PSDesktopException = @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@

    # Set PowerShell to TLS1.2
    [ServicePointManager]::SecurityProtocol = [SecurityProtocolType]::Tls12

    if ($LrtConfig.General.CertPolicyRequired) {
        if ($PSEdition -ne 'Core'){
            if (-Not ("TrustAllCertsPolicy" -as [type])) {
                Write-Verbose "[Enable-TrustAllCertsPolicy]: Cert Policy is not enabled. Enabling."
                Add-Type $PSDesktopException
                try {
                    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                } catch {
                    throw [Exception] `
                        "[Enable-TrustAllCertsPolicy]: Failed to update System.Net.ServicePointManager::CertificatePolicy to new TrustAllCertsPolicy"
                }
            }
        } else {
            # Set session default for Invoke-RestMethod and Invoke-WebRequest to SkipCertificateCheck
            if (-Not $PSDefaultParameterValues.ContainsKey('Invoke-RestMethod:SkipCertificateCheck')) {
                Write-Verbose "[Enable-TrustAllCertsPolicy]: PowerShell Core - Invoke-RestMethod SkipCertificateCheck set to true"
                Try {
                    $PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck",$true)
                } Catch {
                    throw [Exception] `
                    "[Enable-TrustAllCertsPolicy]: Failed to update PSDefaultParameterValues Invoke-RestMethod:SkipCertificateCheck to value true"
                }
                
            }
        }
    } else {
        Write-Verbose "[Enable-TrustAllCertsPolicy]: Cert Policy set as Not Required."
    }
}