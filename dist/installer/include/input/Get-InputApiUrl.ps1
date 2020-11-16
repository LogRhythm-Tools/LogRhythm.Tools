Function Get-InputApiUrl {
    <#
    .SYNOPSIS 
        Determine if a user entered a valid IP Address
    .PARAMETER Value
        String to evaluate as an IP Address or hostname.
    .EXAMPLE
        PS C:\> Get-InputIpAddress -Value 1.2.3.4

        Value   Valid
        -----   -----
        1.2.3.4  True
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Value,

        [Parameter(Mandatory = $false, Position = 1)]
        [string] $OldValue
    )

    # Accept Hostname or IPAddress
    $ValidRegex = [regex]::new("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$")
    # Parses hostname and optionally port from URL.  Named groups produced: Address, Port
    $Extract = [regex]::new("^(?<prefix>^http(s)?:\/\/)?(((?<address>[^:]+):(?<port>\d+))|(?<address>\S+[^\/])?$|((?<address>[^\/]+)\/)).*?$")


    # Return object
    $Return = [PSCustomObject]@{
        Value = $null
        Valid = $false
        Changed = $false
    }


    # Parse the old value so we can find the hostname and port parts
    $ExtractResult = $Extract.Match($OldValue)

    # Parse the new value so we can find the hostname and port parts
    $ExtractInputValue = $Extract.Match($Value)

    # If OldValue wasn't a valid match for https://host/ or https://host:9999/ then we have a source data problem
    if (! $ExtractResult.Success) {
        Write-Host "    [!] Warning: Value found in current configuration file is invalid, so it cannot be updated." -ForegroundColor Red
        Write-Host "    Update this field directly in the configuration." -ForegroundColor Red
        # set valid to true because user input won't help change it.
        $Return.Valid = $true
        return $Return
    }


    # Check if OldValue contains a Port group match
    if ($ExtractResult.Groups["port"].Success) {
        $ExistingPort = $ExtractResult.Groups["port"].Value
        Write-Verbose "Current Port extraction.  Port: $ExistingPort"
    } 
    
    # Verify if OldValue contains an Address group match
    if ($ExtractResult.Groups["address"].Success) {
        $ExistingAddress = $ExtractResult.Groups["address"].Value
        Write-Verbose "Current Address extraction. Address: $ExistingAddress"
    }

    # Check if Value contains a Port group match
    if ($ExtractInputValue.Groups["port"].Success) {
        $InputPort = $ExtractInputValue.Groups["port"].Value
        Write-Verbose "Input Port extraction.  Port: $InputPort"
    } 
    
    # Verify if Value contains an Address group match
    if ($ExtractInputValue.Groups["address"].Success) {
        $InputAddress = $ExtractInputValue.Groups["address"].Value
        Write-Verbose "Input Address extraction. Address: $InputAddress"
    }

    # We need a valid hostname to use for replacement
    if ($InputAddress -match $ValidRegex) {
        $Return.Valid = $true
    }

    # Create URL from OldValue
    $Return.Value = $OldValue.Replace($ExistingAddress, $InputAddress)

    if ($InputPort) {
        # Replace current port address string
        if ($ExistingPort) {
            Write-Verbose "Updating Port.  Old Value: $ExistingPort  New Value: $InputPort"
            $Return.Value = $Return.Value.Replace($ExistingPort, $InputPort)
        } else {
            $Return.Value = $Return.Value + ":$InputPort"
        }

    }

    Write-Verbose "Value: $($Return.Value)"


    if ($Return.Value -ne $OldValue) {
        $Return.Changed = $true
    }

    return $Return
}