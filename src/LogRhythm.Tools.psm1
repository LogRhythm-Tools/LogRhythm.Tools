
#region: Module Info                                                                     
# Module Name: To make it easier to change the name of the module.
# NOTE: These two variables should be set exactly the same as they appear in setup\New-LrtConfig!
#       The name of the file may be $ModuleName.config.json, but the object is still called
$ModuleName = "LogRhythm.Tools"
$PreferencesFileName = $ModuleName + ".json"

# [Namespaces]: Directories to include in this module
$Namespaces = @(
    "Public",
    "Private"
)
#endregion



#region: Load Preferences                                                                
$ConfigDirPath = Join-Path `
    -Path ([Environment]::GetFolderPath("LocalApplicationData"))`
    -ChildPath $ModuleName

$ConfigFileInfo = [System.IO.FileInfo]::new((Join-Path -Path $ConfigDirPath -ChildPath $PreferencesFileName))

# Try to load the Config File from Local AppData, fallback to the copy in the install directory.
if ($ConfigFileInfo.Exists) {
    $LrtConfig = Get-Content -Path $ConfigFileInfo.FullName -Raw | ConvertFrom-Json
} else {
    Write-Error "Failed to load configuration file.  Run Setup.ps1 from a published release to create one."
}
#endregion



#region: Module Reference Object Variables                                               
# LogRhythm Case Vars
$LrCaseStatus = [PSCustomObject]@{
    Created     = 1
    Completed   = 2
    Open        = 3
    Mitigated   = 4
    Resolved    = 5
}


# HTTP Vars
$HttpMethod = [PSCustomObject]@{
    Get     = "Get"
    Head    = "Head"
    Post    = "Post"
    Put     = "Put"
    Delete  = "Delete"
    Trace   = "Trace"
    Options = "Options"
    Merge   = "Merge"
    Patch   = "Patch"
}


$HttpContentType = [PSCustomObject]@{
    Json        = "application/json"
    Text        = "text/plain"
    Html        = "text/html"
    Xml         = "application/xml"
    JavaScript  = "application/javascript"
    FormUrl     = "application/x-www-form-urlencoded"
    FormData    = "multipart/form-data"
}
#endregion



#region: Import Functions                                                                
# Build Import Hash Table
$Includes = @{}
foreach ($namespace in $Namespaces) {
    $Includes.Add($namespace, @(Get-ChildItem -Recurse -Include *.ps1 -Path $PSScriptRoot\$namespace -ErrorAction SilentlyContinue))
}
# Run Import
foreach ($include in $Includes.GetEnumerator()) {
    foreach ($file in $include.Value) {
        try {
            . $file.FullName
        }
        catch {
            Write-Error "  - Failed to import function $($file.BaseName): $_"
        }
    }
}
#endregion



#region: Import API Keys                                                                 
# Load API Keys from LrtConfig
foreach($ConfigCategory in $LrtConfig.PSObject.Properties) {
    # $myObject.PSobject.Properties.name -match "myPropertyNameToTest"

    foreach($ConfigCategory in $LrtConfig.PSObject.Properties){                                   
        if("ApiKey" -in $ConfigCategory.Value.PSObject.Properties.Name) {
            $KeyFileName = $ConfigCategory.Name + ".ApiKey.xml"
            $KeyFile = [FileInfo]::new("$ConfigDirPath\$KeyFileName")

            if ($KeyFile.Exists) {
                $LrtConfig.($ConfigCategory.Name).ApiKey = Import-Clixml -Path $KeyFile.FullName    
            } else {
                Write-Warning "Unable to load key: $KeyFileName from $($ConfigDirPath)"
            }
            continue
        }
    }
}
#     if($ConfigCategory.Value.PSObject.Properties.Name -eq "ApiKey") {
#         $ConfigCategory.Value.PSObject.Properties.Value
#     }
#     if ($ConfigCategory.Value.PSObject.Properties) {
#         $KeyFileName = $ConfigCategory.Name + ".ApiKey.xml"
#         Write-Host "$ConfigDirPath\$KeyFileName"
#         $KeyFile = [FileInfo]::new("$ConfigDirPath\$KeyFileName")
#         if ($KeyFile.Exists) {
#             $ConfigCategory.Value.ApiKey = Import-Clixml -Path $KeyFile.FullName
#         } else {
            
#         }
#     }
# }
#endregion



#region: Export Module Members                                                           
Export-ModuleMember -Variable ModuleName
Export-ModuleMember -Variable LrtConfig
Export-ModuleMember -Variable LrCaseStatus
Export-ModuleMember -Variable AssemblyList
Export-ModuleMember -Variable HttpMethod
Export-ModuleMember -Variable HttpContentType
Export-ModuleMember -Function $Includes["Public"].BaseName
#endregion