<#
.SYNOPSIS
    Synchronize Exabeam PHI 500 - Endpoints context table to Qualys tags.

.DESCRIPTION
    This script pulls data from the Exabeam context table "PHI 500 - Endpoints" and
    applies the "PHI500-E" tag to matching assets in Qualys.

    The script:
    1. Retrieves hostnames from Exabeam context table
    2. Strips domain from FQDN hostnames
    3. Searches for matching assets in Qualys
    4. Applies the PHI500-E tag to matched assets
    5. Optionally removes the tag from assets no longer in Exabeam (with -RemoveStale)

.PARAMETER TestMode
    When enabled, performs all operations except applying/removing tags in Qualys.
    This allows you to see which assets would be modified without making changes.

.PARAMETER RemoveStale
    When enabled, removes the PHI500-E tag from Qualys assets that are no longer
    in the Exabeam context table. This ensures Qualys reflects the current state
    of Exabeam as the source of truth.

.PARAMETER ExabeamTableName
    Name of the Exabeam context table to query. Defaults to "PHI 500 - Endpoints".

.PARAMETER QualysTagName
    Name of the Qualys tag to apply. Defaults to "PHI500-E".

.PARAMETER ExabeamCredential
    PSCredential for Exabeam API. If not provided, uses $LrtConfig.Exabeam.Credential.

.PARAMETER QualysCredential
    PSCredential for Qualys API. If not provided, uses $LrtConfig.Qualys.Credential.

.PARAMETER WebhookToken
    Bearer token for webhook logging to Exabeam cloud collector endpoint.
    When provided, the script will send progress and activity logs to:
    https://api2.sa.exabeam.cloud/cloud-collectors/v1/logs/json

.EXAMPLE
    PS C:\> .\Sync-ExabeamPHI500ToQualys.ps1 -TestMode

    Runs in test mode, showing which assets would be tagged without making changes.

.EXAMPLE
    PS C:\> .\Sync-ExabeamPHI500ToQualys.ps1

    Applies the PHI500-E tag to all matching Qualys assets.

.EXAMPLE
    PS C:\> .\Sync-ExabeamPHI500ToQualys.ps1 -RemoveStale -TestMode

    Shows which assets would have the tag removed (stale assets not in Exabeam).

.EXAMPLE
    PS C:\> .\Sync-ExabeamPHI500ToQualys.ps1 -RemoveStale

    Adds tags to matching assets AND removes tags from assets no longer in Exabeam.

.EXAMPLE
    PS C:\> .\Sync-ExabeamPHI500ToQualys.ps1 -TestMode -Verbose

    Runs in test mode with verbose output showing detailed progress.

.EXAMPLE
    PS C:\> .\Sync-ExabeamPHI500ToQualys.ps1 -RemoveStale -WebhookToken "your-bearer-token-here"

    Full sync with webhook logging enabled. Logs will be sent to Exabeam cloud collector.

.NOTES
    Requires:
    - LogRhythm.Tools module with Exabeam and Qualys cmdlets
    - Exabeam context table: PHI 500 - Endpoints
    - Qualys tag: PHI500-E (must exist before running)

.LINK
    https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false)]
    [switch] $TestMode,

    [Parameter(Mandatory = $false)]
    [switch] $RemoveStale,

    [Parameter(Mandatory = $false)]
    [string] $ExabeamTableName = "PHI 500 - Endpoints",

    [Parameter(Mandatory = $false)]
    [string] $QualysTagName = "PHI500-E",

    [Parameter(Mandatory = $false)]
    [pscredential] $ExabeamCredential,

    [Parameter(Mandatory = $false)]
    [pscredential] $QualysCredential,

    [Parameter(Mandatory = $false)]
    [string] $WebhookToken
)

#region: Webhook Configuration

# Webhook endpoint for logging activity
$EnableWebhookLogging = $true
$WebhookEndpoint = ""
$WebhookToken = ''
# Sync job name for tracking
$SyncJobName = "$ExabeamTableName -> Qualys Tag: $QualysTagName"

#endregion

#region: Helper Functions

Function Send-WebhookLog {
    <#
    .SYNOPSIS
        Sends a log entry to the webhook endpoint.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string] $Message,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string] $Status,

        [Parameter(Mandatory = $true)]
        [string] $Task,

        [Parameter(Mandatory = $false)]
        [string] $Hostname,

        [Parameter(Mandatory = $false)]
        [string] $JobName
    )

    if (-not $EnableWebhookLogging) {
        Write-Verbose "[WEBHOOK] Logging disabled - skipping"
        return
    }

    try {
        # Generate ISO 8601 timestamp
        $Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"

        $LogEntry = @{
            sourcekey = "Exabeam2QualysPHI500-Endpoint"
            timestamp = $Timestamp
            message = $Message
            status = $Status
            task = $Task
        }

        # Add hostname if provided
        if ($Hostname) {
            $LogEntry.hostname = $Hostname
        }

        # Add job name if provided, otherwise use script-level variable
        if ($JobName) {
            $LogEntry.job = $JobName
        } elseif ($script:SyncJobName) {
            $LogEntry.job = $script:SyncJobName
        }

        # Build headers using Dictionary type (consistent with other Exabeam cmdlets)
        $Headers = [System.Collections.Generic.Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $WebhookToken")
        $Headers.Add("Content-Type", "application/json")

        $Body = $LogEntry | ConvertTo-Json -Depth 2 -Compress

        Write-Verbose "[WEBHOOK] Enabled: $EnableWebhookLogging"
        Write-Verbose "[WEBHOOK] Endpoint: $WebhookEndpoint"
        Write-Verbose "[WEBHOOK] Token length: $($WebhookToken.Length) chars"
        Write-Verbose "[WEBHOOK] Token starts with: $($WebhookToken.Substring(0, [Math]::Min(20, $WebhookToken.Length)))..."
        Write-Verbose "[WEBHOOK] Headers: Authorization=Bearer [REDACTED], Content-Type=application/json"
        Write-Verbose "[WEBHOOK] Body: $Body"

        $Response = Invoke-RestMethod -Uri $WebhookEndpoint -Method Post -Headers $Headers -Body $Body -ErrorAction Stop

        Write-Verbose "[WEBHOOK] ✓ Successfully sent - Status: $Status, Task: $Task"
        if ($Response) {
            Write-Verbose "[WEBHOOK] Response: $($Response | ConvertTo-Json -Compress)"
        }
    } catch {
        Write-Verbose "[WEBHOOK] ✗ Failed to send webhook log"
        Write-Verbose "[WEBHOOK] Error: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            Write-Verbose "[WEBHOOK] HTTP Status: $($_.Exception.Response.StatusCode.value__) - $($_.Exception.Response.StatusDescription)"
        }
        if ($_.ErrorDetails) {
            Write-Verbose "[WEBHOOK] Error Details: $($_.ErrorDetails.Message)"
        }
    }
}

Function Get-HostnameWithoutDomain {
    <#
    .SYNOPSIS
        Extracts hostname from FQDN.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string] $Hostname
    )

    # If hostname contains a dot, split and take first part
    if ($Hostname -match '\.') {
        return $Hostname.Split('.')[0]
    }

    # Otherwise return as-is
    return $Hostname
}

#endregion

#region: Initialization

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Exabeam to Qualys PHI500 Tag Sync" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($TestMode) {
    Write-Host "[TEST MODE] No changes will be made to Qualys" -ForegroundColor Yellow
    Write-Host ""
}

if ($RemoveStale) {
    Write-Host "[REMOVE STALE MODE] Tags will be removed from assets not in Exabeam" -ForegroundColor Yellow
    Write-Host ""
}

# Log script start
Send-WebhookLog -Message "Script execution started - TestMode: $TestMode, RemoveStale: $RemoveStale" -Status Info -Task "Initialization"

# Statistics
$Stats = @{
    ExabeamHostsRetrieved = 0
    QualysAssetsFound     = 0
    QualysAssetsNotFound  = 0
    TagsAlreadyPresent    = 0
    TagsApplied           = 0
    TagsRemoved           = 0
    StaleAssetsFound      = 0
    Errors                = 0
}

# Results collection
$Results = [System.Collections.ArrayList]::new()
$StaleResults = [System.Collections.ArrayList]::new()

#endregion

#region: Step 1 - Get Qualys Tag ID

Write-Host "[Step 1/4] Looking up Qualys tag: $QualysTagName" -ForegroundColor White

try {
    $GetTagParams = @{
        Name = $QualysTagName
        Exact = $true
    }
    if ($QualysCredential) {
        $GetTagParams.Credential = $QualysCredential
    }

    $QualysTag = Get-QualysTags @GetTagParams

    if (-not $QualysTag -or $QualysTag.Error) {
        Write-Host "  [ERROR] Qualys tag '$QualysTagName' not found or API error occurred" -ForegroundColor Red
        Write-Host "  Please create the tag in Qualys before running this script" -ForegroundColor Yellow
        exit 1
    }

    # Handle case where multiple tags are returned
    if ($QualysTag -is [System.Array]) {
        $QualysTag = $QualysTag[0]
        Write-Verbose "  Multiple tags found, using first match"
    }

    $QualysTagId = $QualysTag.id
    Write-Host "  [OK] Found Qualys tag: $QualysTagName (ID: $QualysTagId)" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Failed to retrieve Qualys tag: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""

#endregion

#region: Step 2 - Get Exabeam Context Table Records

Write-Host "[Step 2/4] Retrieving records from Exabeam context table: $ExabeamTableName" -ForegroundColor White

try {
    # First, get the table ID by name
    $GetTableParams = @{
        Name = $ExabeamTableName
        Exact = $true
    }
    if ($ExabeamCredential) {
        $GetTableParams.Credential = $ExabeamCredential
    }

    $ExabeamTable = Get-ExaContextTables @GetTableParams

    if (-not $ExabeamTable) {
        Write-Host "  [ERROR] Exabeam context table '$ExabeamTableName' not found" -ForegroundColor Red
        Write-Host "  Please verify the table name exists in Exabeam" -ForegroundColor Yellow
        exit 1
    }

    # Handle case where multiple tables are returned
    if ($ExabeamTable -is [System.Array]) {
        $ExabeamTable = $ExabeamTable[0]
        Write-Verbose "  Multiple tables found, using first match"
    }

    $TableId = $ExabeamTable.id
    Write-Verbose "  Found Exabeam table: $ExabeamTableName (ID: $TableId)"

    # Now get the records using the table ID
    $GetRecordsParams = @{
        id = $TableId
    }
    if ($ExabeamCredential) {
        $GetRecordsParams.Credential = $ExabeamCredential
    }

    $ExabeamResponse = Get-ExaContextRecords @GetRecordsParams

    if (-not $ExabeamResponse -or -not $ExabeamResponse.records) {
        Write-Host "  [WARNING] No records found in Exabeam table" -ForegroundColor Yellow
        exit 0
    }

    $ExabeamRecords = $ExabeamResponse.records
    $Stats.ExabeamHostsRetrieved = @($ExabeamRecords).Count
    Write-Host "  [OK] Retrieved $($Stats.ExabeamHostsRetrieved) records from Exabeam" -ForegroundColor Green

    Send-WebhookLog -Message "Retrieved $($Stats.ExabeamHostsRetrieved) records from source table: $ExabeamTableName" -Status Success -Task "Exabeam Source Retrieval"
} catch {
    Write-Host "  [ERROR] Failed to retrieve Exabeam records: $_" -ForegroundColor Red
    Send-WebhookLog -Message "Failed to retrieve Exabeam records: $($_.Exception.Message)" -Status Error -Task "Retrieve Exabeam Records"
    $Stats.Errors++
    exit 1
}

Write-Host ""

#endregion

#region: Step 3 - Process Each Hostname

Write-Host "[Step 3/4] Processing hostnames and searching Qualys" -ForegroundColor White

foreach ($Record in $ExabeamRecords) {
    # Extract hostname attribute (adjust based on your Exabeam table structure)
    # Common attributes: hostname, host, asset_name, etc.
    $Hostname = $null

    # Debug: Show available properties on first record
    if ($ExabeamRecords.IndexOf($Record) -eq 0) {
        Write-Verbose "  First record properties: $($Record.PSObject.Properties.Name -join ', ')"
    }

    # Try common attribute names
    if ($Record.hostname) {
        $Hostname = $Record.hostname
        Write-Verbose "  Using 'hostname' property: $Hostname"
    } elseif ($Record.host) {
        $Hostname = $Record.host
        Write-Verbose "  Using 'host' property: $Hostname"
    } elseif ($Record.asset_name) {
        $Hostname = $Record.asset_name
        Write-Verbose "  Using 'asset_name' property: $Hostname"
    } elseif ($Record.name) {
        $Hostname = $Record.name
        Write-Verbose "  Using 'name' property: $Hostname"
    }

    if (-not $Hostname) {
        Write-Host "  [WARNING] No hostname found in record. Available properties: $($Record.PSObject.Properties.Name -join ', ')" -ForegroundColor Yellow
        continue
    }

    # Strip domain from FQDN
    $ShortHostname = Get-HostnameWithoutDomain -Hostname $Hostname
    Write-Verbose "  Processing: $Hostname -> $ShortHostname"

    # Search for asset in Qualys
    try {
        # Try uppercase search first (Qualys typically stores hostnames in uppercase)
        $UpperHostname = $ShortHostname.ToUpper()
        $QualysParams = @{
            Name = $UpperHostname
        }
        if ($QualysCredential) {
            $QualysParams.Credential = $QualysCredential
        }

        Write-Verbose "  Searching Qualys for: $UpperHostname"
        $QualysAssets = Get-QualysHostAssets @QualysParams
        Write-Verbose "  Qualys returned: $($QualysAssets.Count) result(s)"

        # If not found and original was different case, try original case as fallback
        if ((-not $QualysAssets -or $QualysAssets.Count -eq 0) -and ($ShortHostname -cne $UpperHostname)) {
            Write-Verbose "  Trying original case search: $ShortHostname"
            $QualysParams.Name = $ShortHostname
            $QualysAssets = Get-QualysHostAssets @QualysParams
            Write-Verbose "  Qualys returned: $($QualysAssets.Count) result(s)"

            if (-not $QualysAssets -or $QualysAssets.Count -eq 0) {
                # Keep uppercase for reporting consistency
                $ShortHostname = $UpperHostname
            }
        } else {
            # Use uppercase for reporting
            $ShortHostname = $UpperHostname
        }

        if ($QualysAssets -and -not $QualysAssets.Error) {
            # Handle multiple matches
            $MatchedAssets = @($QualysAssets)
            Write-Verbose "  Processing $($MatchedAssets.Count) matched asset(s)"

            foreach ($Asset in $MatchedAssets) {
                $Stats.QualysAssetsFound++

                $ResultEntry = [PSCustomObject]@{
                    ExabeamHostname    = $Hostname
                    ShortHostname      = $ShortHostname
                    QualysAssetId      = $Asset.id
                    QualysAssetName    = $Asset.name
                    QualysAddress      = $Asset.address
                    TagApplied         = $false
                    TestMode           = $TestMode
                    Error              = $null
                }

                Write-Host "  [FOUND] $ShortHostname -> Qualys Asset ID: $($Asset.id) ($($Asset.name))" -ForegroundColor Green
                Send-WebhookLog -Message "Asset found in Qualys" -Status Success -Task "Qualys Lookup" -Hostname $Asset.name

                # Retrieve full asset details to check tags
                Write-Verbose "  Retrieving full asset details for ID: $($Asset.id)"
                try {
                    $GetAssetParams = @{
                        Id = $Asset.id
                    }
                    if ($QualysCredential) {
                        $GetAssetParams.Credential = $QualysCredential
                    }

                    $FullAsset = Get-QualysHostAsset @GetAssetParams

                    if ($FullAsset -and -not $FullAsset.Error) {
                        # Check if tag already exists on this asset
                        $TagAlreadyExists = $false
                        if ($FullAsset.tags -and $FullAsset.tags.list) {
                            $ExistingTagIds = @($FullAsset.tags.list.TagSimple | ForEach-Object { $_.id })
                            Write-Verbose "  Asset has $($ExistingTagIds.Count) existing tag(s): $($ExistingTagIds -join ', ')"
                            if ($ExistingTagIds -contains $QualysTagId) {
                                $TagAlreadyExists = $true
                            }
                        } else {
                            Write-Verbose "  Asset has no existing tags"
                        }

                        if ($TagAlreadyExists) {
                            Write-Host "    [SKIP] Tag already present on asset" -ForegroundColor Cyan
                            $ResultEntry.TagApplied = $true
                            $Stats.TagsAlreadyPresent++
                            Send-WebhookLog -Message "Tag $QualysTagName already exists on asset (skipped)" -Status Info -Task "Tag Management" -Hostname $Asset.name
                        } else {
                            # Apply tag (unless in test mode)
                            if (-not $TestMode) {
                                try {
                                    $UpdateParams = @{
                                        Id = $Asset.id
                                        AddTagIds = @($QualysTagId)
                                    }
                                    if ($QualysCredential) {
                                        $UpdateParams.Credential = $QualysCredential
                                    }

                                    $UpdateResult = Update-QualysHostAsset @UpdateParams

                                    if ($UpdateResult.Error) {
                                        Write-Host "    [ERROR] Failed to apply tag: $($UpdateResult.Note)" -ForegroundColor Red
                                        $ResultEntry.Error = $UpdateResult.Note
                                        $Stats.Errors++
                                        Send-WebhookLog -Message "Failed to apply tag: $($UpdateResult.Note)" -Status Error -Task "Tag Management" -Hostname $Asset.name
                                    } else {
                                        Write-Host "    [OK] Tag applied successfully" -ForegroundColor Green
                                        $ResultEntry.TagApplied = $true
                                        $Stats.TagsApplied++
                                        Send-WebhookLog -Message "Tag $QualysTagName added to asset" -Status Success -Task "Tag Management" -Hostname $Asset.name
                                    }
                                } catch {
                                    Write-Host "    [ERROR] Exception applying tag: $_" -ForegroundColor Red
                                    $ResultEntry.Error = $_.Exception.Message
                                    $Stats.Errors++
                                    Send-WebhookLog -Message "Exception applying tag: $($_.Exception.Message)" -Status Error -Task "Tag Management" -Hostname $Asset.name
                                }
                            } else {
                                Write-Host "    [TEST MODE] Would apply tag: $QualysTagName" -ForegroundColor Yellow
                                $ResultEntry.TagApplied = $null  # Null indicates test mode
                                Send-WebhookLog -Message "Would apply tag $QualysTagName (test mode)" -Status Info -Task "Tag Management" -Hostname $Asset.name
                            }
                        }
                    } else {
                        Write-Host "    [ERROR] Failed to retrieve full asset details" -ForegroundColor Red
                        $ResultEntry.Error = "Failed to retrieve full asset details"
                        $Stats.Errors++
                    }
                } catch {
                    Write-Host "    [ERROR] Exception retrieving asset details: $_" -ForegroundColor Red
                    $ResultEntry.Error = $_.Exception.Message
                    $Stats.Errors++
                }

                [void]$Results.Add($ResultEntry)
            }
        } else {
            $Stats.QualysAssetsNotFound++
            $Stats.Errors++  # Asset not found is an error (404)

            # Provide more detailed error information
            if ($QualysAssets.Error) {
                Write-Host "  [ERROR] $ShortHostname - Qualys API error: $($QualysAssets.Note)" -ForegroundColor Red
                $ErrorMessage = "Qualys API error: $($QualysAssets.Note)"
                Send-WebhookLog -Message "Qualys API error: $($QualysAssets.Note)" -Status Error -Task "Qualys Lookup" -Hostname $ShortHostname
            } else {
                Write-Host "  [NOT FOUND] $ShortHostname - No matching asset in Qualys" -ForegroundColor DarkYellow
                $ErrorMessage = "Asset not found in Qualys (404)"
                Send-WebhookLog -Message "Asset not found in Qualys" -Status Error -Task "Qualys Lookup" -Hostname $ShortHostname
            }

            $ResultEntry = [PSCustomObject]@{
                ExabeamHostname    = $Hostname
                ShortHostname      = $ShortHostname
                QualysAssetId      = $null
                QualysAssetName    = $null
                QualysAddress      = $null
                TagApplied         = $false
                TestMode           = $TestMode
                Error              = $ErrorMessage
            }
            [void]$Results.Add($ResultEntry)
        }
    } catch {
        Write-Host "  [ERROR] Exception searching for $ShortHostname : $_" -ForegroundColor Red
        $Stats.Errors++

        $ResultEntry = [PSCustomObject]@{
            ExabeamHostname    = $Hostname
            ShortHostname      = $ShortHostname
            QualysAssetId      = $null
            QualysAssetName    = $null
            QualysAddress      = $null
            TagApplied         = $false
            TestMode           = $TestMode
            Error              = $_.Exception.Message
        }
        [void]$Results.Add($ResultEntry)
    }
}

Write-Host ""

#endregion

#region: Step 4 - Remove Stale Tags (if enabled)

if ($RemoveStale) {
    Write-Host "[Step 4/5] Removing stale tags from Qualys assets" -ForegroundColor White

    # Build a HashSet of uppercase hostnames from Exabeam for fast lookup
    $ExabeamHostnameSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Record in $ExabeamRecords) {
        $Hostname = $null
        if ($Record.hostname) {
            $Hostname = $Record.hostname
        } elseif ($Record.host) {
            $Hostname = $Record.host
        } elseif ($Record.asset_name) {
            $Hostname = $Record.asset_name
        } elseif ($Record.name) {
            $Hostname = $Record.name
        }

        if ($Hostname) {
            $ShortHostname = Get-HostnameWithoutDomain -Hostname $Hostname
            [void]$ExabeamHostnameSet.Add($ShortHostname.ToUpper())
        }
    }

    Write-Verbose "  Built lookup set with $($ExabeamHostnameSet.Count) Exabeam hostnames"

    # Get all Qualys assets that have the PHI500-E tag
    try {
        $TaggedAssetParams = @{
            TagId = $QualysTagId
        }
        if ($QualysCredential) {
            $TaggedAssetParams.Credential = $QualysCredential
        }

        Write-Verbose "  Retrieving all Qualys assets with tag: $QualysTagName (ID: $QualysTagId)"
        $TaggedAssets = Get-QualysHostAssets @TaggedAssetParams

        if ($TaggedAssets -and -not $TaggedAssets.Error) {
            $TaggedAssetsList = @($TaggedAssets)
            Write-Host "  Found $($TaggedAssetsList.Count) Qualys assets with tag $QualysTagName" -ForegroundColor Cyan

            foreach ($Asset in $TaggedAssetsList) {
                $AssetName = $Asset.name.ToUpper()

                # Check if this asset exists in Exabeam
                if (-not $ExabeamHostnameSet.Contains($AssetName)) {
                    $Stats.StaleAssetsFound++

                    $StaleEntry = [PSCustomObject]@{
                        QualysAssetId      = $Asset.id
                        QualysAssetName    = $Asset.name
                        QualysAddress      = $Asset.address
                        TagRemoved         = $false
                        TestMode           = $TestMode
                        Error              = $null
                    }

                    Write-Host "  [STALE] $($Asset.name) (ID: $($Asset.id)) - Not in Exabeam list" -ForegroundColor Magenta
                    Send-WebhookLog -Message "Stale asset detected - not in Exabeam source" -Status Warning -Task "Stale Detection" -Hostname $Asset.name

                    # Remove tag (unless in test mode)
                    if (-not $TestMode) {
                        try {
                            $RemoveParams = @{
                                Id = $Asset.id
                                RemoveTagIds = @($QualysTagId)
                            }
                            if ($QualysCredential) {
                                $RemoveParams.Credential = $QualysCredential
                            }

                            $RemoveResult = Update-QualysHostAsset @RemoveParams

                            if ($RemoveResult.Error) {
                                Write-Host "    [ERROR] Failed to remove tag: $($RemoveResult.Note)" -ForegroundColor Red
                                $StaleEntry.Error = $RemoveResult.Note
                                $Stats.Errors++
                                Send-WebhookLog -Message "Failed to remove tag: $($RemoveResult.Note)" -Status Error -Task "Tag Management" -Hostname $Asset.name
                            } else {
                                Write-Host "    [OK] Tag removed successfully" -ForegroundColor Green
                                $StaleEntry.TagRemoved = $true
                                $Stats.TagsRemoved++
                                Send-WebhookLog -Message "Tag $QualysTagName removed from stale asset" -Status Success -Task "Tag Management" -Hostname $Asset.name
                            }
                        } catch {
                            Write-Host "    [ERROR] Exception removing tag: $_" -ForegroundColor Red
                            $StaleEntry.Error = $_.Exception.Message
                            $Stats.Errors++
                            Send-WebhookLog -Message "Exception removing tag: $($_.Exception.Message)" -Status Error -Task "Tag Management" -Hostname $Asset.name
                        }
                    } else {
                        Write-Host "    [TEST MODE] Would remove tag: $QualysTagName" -ForegroundColor Yellow
                        $StaleEntry.TagRemoved = $null  # Null indicates test mode
                        Send-WebhookLog -Message "Would remove tag $QualysTagName (test mode)" -Status Info -Task "Tag Management" -Hostname $Asset.name
                    }

                    [void]$StaleResults.Add($StaleEntry)
                } else {
                    Write-Verbose "  [CURRENT] $($Asset.name) - Still in Exabeam list"
                }
            }
        } else {
            if ($TaggedAssets.Error) {
                Write-Host "  [ERROR] Failed to retrieve tagged assets: $($TaggedAssets.Note)" -ForegroundColor Red
            } else {
                Write-Host "  No assets found with tag $QualysTagName" -ForegroundColor DarkYellow
            }
        }
    } catch {
        Write-Host "  [ERROR] Exception retrieving tagged assets: $_" -ForegroundColor Red
        $Stats.Errors++
    }

    Write-Host ""
}

#endregion

#region: Step 5 - Summary

Write-Host "[Step $(@{$true=5;$false=4}[$RemoveStale])/5] Summary" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Exabeam hosts retrieved:       $($Stats.ExabeamHostsRetrieved)" -ForegroundColor White
Write-Host "Qualys assets found:           $($Stats.QualysAssetsFound)" -ForegroundColor Green
Write-Host "Qualys assets not found:       $($Stats.QualysAssetsNotFound)" -ForegroundColor DarkYellow

if ($TestMode) {
    Write-Host "Tags that would be applied:    $($Stats.QualysAssetsFound - $Stats.TagsAlreadyPresent)" -ForegroundColor Yellow
} else {
    Write-Host "Tags already present:          $($Stats.TagsAlreadyPresent)" -ForegroundColor Cyan
    Write-Host "Tags applied successfully:     $($Stats.TagsApplied)" -ForegroundColor Green
}

if ($RemoveStale) {
    Write-Host "Stale assets found:            $($Stats.StaleAssetsFound)" -ForegroundColor Magenta
    if ($TestMode) {
        Write-Host "Tags that would be removed:    $($Stats.StaleAssetsFound)" -ForegroundColor Yellow
    } else {
        Write-Host "Tags removed successfully:     $($Stats.TagsRemoved)" -ForegroundColor Green
    }
}

if ($Stats.Errors -gt 0) {
    Write-Host "Errors encountered:            $($Stats.Errors)" -ForegroundColor Red
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($TestMode) {
    Write-Host "[TEST MODE] No changes were made to Qualys" -ForegroundColor Yellow
    Write-Host "Run without -TestMode to apply/remove tags" -ForegroundColor Yellow
}


$CompletionStatus = "Info"

$SummaryMessage = "Sync completed - Source: $($Stats.ExabeamHostsRetrieved) records, Found: $($Stats.QualysAssetsFound), Not Found: $($Stats.QualysAssetsNotFound), Already Tagged: $($Stats.TagsAlreadyPresent), Tags Added: $($Stats.TagsApplied), Tags Removed: $($Stats.TagsRemoved), Errors: $($Stats.Errors)"
Send-WebhookLog -Message $SummaryMessage -Status $CompletionStatus -Task "Sync Summary"

#endregion
