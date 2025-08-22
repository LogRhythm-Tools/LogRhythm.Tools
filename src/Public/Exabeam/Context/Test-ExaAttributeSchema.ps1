Function Test-ExaAttributeSchema {
    <#
    .SYNOPSIS
        Tests if a given attribute conforms to one of the two allowed schemas.

    .DESCRIPTION
        This function validates a PSCustomObject to ensure it matches one of the two schemas:
        Schema 1: { id, isKey }
        Schema 2: { displayName, isKey }

        The `isKey` property, if present, must match the string "true" or "false" (case-insensitive).

    .PARAMETER Attribute
        The attribute object to validate.

    .INPUTS
        [PSCustomObject]

    .OUTPUTS
        [bool]
        Returns $true if the attribute matches a schema; otherwise, $false.

    .NOTES
        Approved verb "Test" is used in the function name to comply with PowerShell best practices.
    #>
    Param(
        [PSCustomObject]$Attribute
    )

    # Schema 1: { id, isKey }
    if ($Attribute.PSObject.Properties["id"]) {
        if (-not $Attribute.PSObject.Properties["id"].Value -is [string]) {
            throw "The 'id' property must be a string."
        }
        if ($Attribute.PSObject.Properties["isKey"]) {
            $isKeyValue = $Attribute.PSObject.Properties["isKey"].Value.ToString()
            if (-not ($isKeyValue -match '^(?i:true|false)$')) {
                throw "The 'isKey' property must be 'true' or 'false' (case-insensitive)."
            }
        }
        return $true
    }

    # Schema 2: { displayName, isKey }
    if ($Attribute.PSObject.Properties["displayName"]) {
        if (-not $Attribute.PSObject.Properties["displayName"].Value -is [string]) {
            throw "The 'displayName' property must be a string."
        }
        if ($Attribute.PSObject.Properties["isKey"]) {
            $isKeyValue = $Attribute.PSObject.Properties["isKey"].Value.ToString()
            if (-not ($isKeyValue -match '^(?i:true|false)$')) {
                throw "The 'isKey' property must be 'true' or 'false' (case-insensitive)."
            }
        }
        return $true
    }

    throw "Invalid schema. Object must contain 'id' or 'displayName' and optionally 'isKey'."
}
