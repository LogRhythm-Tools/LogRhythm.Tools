$InstallCmds = @(Get-ChildItem -Path $PSScriptRoot\include\*.ps1 -ErrorAction SilentlyContinue)
foreach ($function in $InstallCmds) {
    . $function.FullName
}


$InputCmds = @(Get-ChildItem -Path $PSScriptRoot\include\input\*.ps1 -ErrorAction SilentlyContinue)
foreach ($function in $InputCmds) {
    . $function.FullName
}

Export-ModuleMember -Function $InstallCmds.BaseName
Export-ModuleMember -Function $InputCmds.BaseName