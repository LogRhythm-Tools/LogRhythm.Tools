.\build\New-TestBuild.ps1

# This is dumb, but I just need it for testing locally.
# This script is not intended to be added to the repository!

$CredPath = "C:\Users\genec\AppData\Local\LogRhythm.Tools"
$ADCred = "C:\Users\genec\AppData\Local\LogRhythm.Tools\ad.xml"
$PACred = "C:\Users\genec\AppData\Local\LogRhythm.Tools\pa.xml"

$resultOk = $false
$re = [regex]::new("([Pp][Aa])|([Aa][Dd])")


if (Test-Path -Path $ADCred) {
    # Use AD cred if it exists
    $UseCred = "ad"
    if (Test-Path -Path $PACred) {
        # If both creds exist, ask which to use
        while (! $resultOk) {
            $UseCred = Read-Host "Use PA or AD account"
            if ($re.Match($UseCred)) {
                $resultOk = $true
            } else {
                Write-Host "(type AD or PA)" -ForegroundColor Yellow
            }
        }
    }
} else {
    if (Test-Path -Path $PACred) {
        $UseCred = "pa"
    }
}

Write-Verbose "Loading credential: [$UseCred]"

if ($UseCred) {
    $credFileName = $UseCred + ".xml"
    $LoadCredPath = Join-Path -Path $CredPath -ChildPath $credFileName
    $LrtConfig.ActiveDirectory.Credential = Import-Clixml -Path $LoadCredPath
    $usr = ($LrtConfig.ActiveDirectory.Credential).UserName
    Write-Host "LrtConfig AD Credential: $usr"
}