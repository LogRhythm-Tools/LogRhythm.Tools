using namespace System.Collections.Generic
import-module logrhythm.tools

# Load existing TrueIdentities
$EntityId = 1
$EntityName = Get-LrEntityDetails -Id $EntityId | Select-Object -ExpandProperty Name

# Example of leveraging LogRhythm.Tools Error Objects
if ($EntityName.Error) {
    Return "Invalid EntityID provided.  Valid Entity is required to synchronize with TrueIdentity."
} else {
    $TrueIdentities = Get-LrIdentities -Entity $EntityName
}

# Retrieve Azure AD User details
$AzureUsers = Get-LrtAzUsers

# Retrieve Organization details from Azure Graph API
$AzureOrgDetails = Get-LrtAzOrganization

# Create optimized objects for data and action management
# MatchedIdentities contains the TrueID data for AzureUsers that are identified as existing TrueID Users based on their userPrincipalName
$MatchedIdentities = [list[object]]::new()

# NewIdentities contains the AzureAD user information in a format to support the TrueIdentity Add-LrIdentity cmdlet.  
# These records have no matches in the existing TrueID structure.
$NewIdentities = [list[object]]::new()



ForEach ($AzureUser in $AzureUsers) {
    $UserTrueIdResults = Find-LrIdentitySummaries -Login $AzureUser.userPrincipalName
    if ($UserTrueIdResults) {
        # A TrueIdentity record exists in the target Entity that contains the userPrincipalName as a matching TrueId login value
        if ($MatchedIdentities -notcontains $UserTrueIdResults) {
            # Add the TrueIdentity details to the MatchedIdentities object list for later reference as needed
            $MatchedIdentites.add($UserTrueIdResults)
        }
    } else {
        # Else a TrueIdentity Record does not exist in the target entity that contains the userPrincipalName.

        # List that serves as an identifier container to support processing
        $NewIdentifiers = [list[object]]::new()

        # Since we have the UserDetails currently, lets perform a lookup for the user's manager for TrueID metadata enrichment
        $AzureUserManager = Get-LrtAzUserManager -userPrincipalName $AzureUser.userPrincipalName
        if ($AzureUserManager) {
            $_azureUserManager = $AzureUserManager.userPrincipalName
        } else {
            $_azureUserManager = ""
        }

        # This section goes into creating the TrueIdentity Identifier values for population into TrueID

        # Set user's mail Identifier if value is populated on AzureAd record
        if ($AzureUser.mail) {
            $Identifier = [PSCustomObject]@{
                Value = $AzureUser.mail
                Type = "Email"
                Note = "User e-mail"
            }
            # Check if the identifier is in the current NewIdentifiers list.  If it is not in the list, add it.
            if ($NewIdentifiers -notcontains $Identifier) {
                $NewIdentifiers.add($Identifier)
            }
        }

        if ($AzureUser.id) {
            $Identifier = [PSCustomObject]@{
                Value = $AzureUser.id
                Type = "Login"
                Note = "User id/sid"
            }
            if ($NewIdentifiers -notcontains $Identifier) {
                $NewIdentifiers.add($Identifier)
            }
        }

        if ($AzureUser.userPrincipalName) {
            $Identifier = [PSCustomObject]@{
                Value = $AzureUser.userPrincipalName
                Type = "Login"
                Note = "User userPrincipalName"
            }
            if ($NewIdentifiers -notcontains $Identifier) {
                $NewIdentifiers.add($Identifier)
            }
        }

        Switch ($($NewIdentifiers.count)) {
            1 {
                $IdentityObject = [PSCustomObject]@{
                    EntityId = $EntityId
                    NameFirst = $AzureUser.givenName
                    NameLast = $AzureUser.surname
                    DisplayIdentifier = $AzureUser.userPrincipalName
                    Title = $AzureUser.jobtitle
                    Manager = $_azureUserManager
                    Company = $AzureOrgDetails.displayName
                    Identifier1Value = $NewIdentifiers[0].Value
                    Identifier1Type = $NewIdentifiers[0].Type
                }
                if ($NewIdentities -notcontains $IdentityObject) {
                    $NewIdentities.add($IdentityObject)
                }
                break
            }
            2 {
                $IdentityObject = [PSCustomObject]@{
                    EntityId = $EntityId
                    NameFirst = $AzureUser.givenName
                    NameLast = $AzureUser.surname
                    DisplayIdentifier = $AzureUser.userPrincipalName
                    Title = $AzureUser.jobtitle
                    Manager = $_azureUserManager
                    Company = $AzureOrgDetails.displayName
                    Identifier1Value = $NewIdentifiers[0].Value
                    Identifier1Type = $NewIdentifiers[0].Type
                    Identifier2Value = $NewIdentifiers[1].Value
                    Identifier2Type = $NewIdentifiers[1].Type
                }
                if ($NewIdentities -notcontains $IdentityObject) {
                    $NewIdentities.add($IdentityObject)
                }
                break
            }
            3 {
                $IdentityObject = [PSCustomObject]@{
                    EntityId = $EntityId
                    NameFirst = $AzureUser.givenName
                    NameLast = $AzureUser.surname
                    DisplayIdentifier = $AzureUser.userPrincipalName
                    Title = $AzureUser.jobtitle
                    Manager = $_azureUserManager
                    Company = $AzureOrgDetails.displayName
                    Identifier1Value = $NewIdentifiers[0].Value
                    Identifier1Type = $NewIdentifiers[0].Type
                    Identifier2Value = $NewIdentifiers[1].Value
                    Identifier2Type = $NewIdentifiers[1].Type
                    Identifier3Value = $NewIdentifiers[2].Value
                    Identifier3Type = $NewIdentifiers[2].Type
                }
                if ($NewIdentities -notcontains $IdentityObject) {
                    $NewIdentities.add($IdentityObject)
                }
                break
            }
            Default {;break}
        }

    }
}