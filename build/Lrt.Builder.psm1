
# Create [debug] and [release] directories if missing - they are in gitignore
$DebugPath = Join-Path -Path $PSScriptRoot -ChildPath "debug"
if (! (Test-Path -Path $DebugPath)) {
    Write-Verbose "Creating [debug] directory"
    $DebugPath = New-Item -ItemType Directory -Name "debug" -Path $PSScriptRoot
}

$ReleasePath = Join-Path -Path $PSScriptRoot -ChildPath "release"
if (! (Test-Path -Path $ReleasePath)) {
    Write-Verbose "Creating [release] directory"
    $DebugPath = New-Item -ItemType Directory -Name "release" -Path $PSScriptRoot
}

# Import Functions
$BuildFunctions = @(Get-ChildItem -Path $PSScriptRoot\include\*.ps1 -ErrorAction SilentlyContinue)
foreach ($function in $BuildFunctions) {
    . $function.FullName
}

# Export Members
Export-ModuleMember -Function $BuildFunctions.BaseName