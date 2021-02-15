using namespace System.Collections.Generic

Import-Module LogRhythm.Tools
## ADD import-module for Windows AD Module


$SyncList = [Dictionary[object]]::new()

# Define the AD groups you want to populate into LogRhythm by this example Object.
$InfoSec = [PSCustomObject]@{
    Name = "Company InfoSec Team"
    InputGroup = "Company.Infosec"
    Output_IdentityListName = "Company.Infosec - Identity"
    Output_LoginListName = "Company.Infosec - Login"
}

# Here is a second object example with additional details
$FinanceDepartment = [PSCustomObject]@{
    # Name is showcased in the audit log outlining what is being processed
    Name = "Company Finance Department"
    # The InputGroup should be the GroupName as it appears in Active Directory and is the source of the Users that will be populated in LogRhyhtm
    InputGroup = "Company.Finance"
    # The Output Identity is the output list name that will be created and maintained in LogRhythm with TrueIdentity values for the input group
    Output_IdentityListName = "Company.Finance Dep - Identity"
    # The Output Login is the output list name that will be created and maintained in LogRhythm with Login values for the input group
    Output_LoginListName = "Company.Finance Dep - Login"
}

# CloudAI Monitored Identities
$CloudAIUsers = [PSCustomObject]@{
    # Name is showcased in the audit log outlining what is being processed
    Name = "LogRhythm CloudAI Subscribed Users"
    # The InputGroup should be the GroupName as it appears in Active Directory and is the source of the Users that will be populated in LogRhyhtm
    InputGroup = "AD_MonitoredIdentities"
    # The Output Identity is the output list name that will be created and maintained in LogRhythm with TrueIdentity values for the input group
    Output_IdentityListName = "CloudAI: Monitored Identities"
    # The Output Login is the output list name that will be created and maintained in LogRhythm with Login values for the input group
    Output_LoginListName = $null
}


$SyncList.add($InfoSec)
$SyncList.add($FinanceDepartment)

Write-Host "$(Get-Timestamp) - Start - List Synchronization" -ForegroundColor Green -BackgroundColor Black
ForEach ($List in $SyncList) {
    Write-Host "$(Get-Timestamp) - Start - Processing List: $($List.name)" -ForegroundColor Green -BackgroundColor Black
    Write-Host "$(Get-Timestamp) - Info - Source AD Group: $($List.InputGroup)" -ForegroundColor Green -BackgroundColor Black
    Write-Host "$(Get-Timestamp) - Info - Destination Identity List: $($List.Output_IdentityListName)" -ForegroundColor Green -BackgroundColor Black
    Write-Host "$(Get-Timestamp) - Info - Destination Login List: $($List.Output_LoginListName)" -ForegroundColor Green -BackgroundColor Black
    $SyncUserLogins = [Dictionary[string]]::new()
    $SyncUserIdentities = [Dictionary[int32]]::new()
    #If you have a single group, you can replace the variables for group name and list name with the specific corresponding names in quotes and then run this line by itself instead of the whole script
    $ADUsers = $(Get-ADGroup $($List.InputGroup) -properties member | Select-Object -ExpandProperty member | get-aduser)
    ForEach ($User in $ADUsers) {
        # Populate Login List
        $UserSamAccountName = $($User | Select-Object -ExpandProperty samaccountname)
        if ($SyncUserLogins -notcontains $UserSamAccountName) {
            $SyncUserLogins.add($UserSamAccountName)
            Write-Host "$(Get-Timestamp) - Info - UserLogin Sync - Adding SamAccountName: $($UserSamAccountName)" -ForegroundColor Green -BackgroundColor Black
        }
        

        # Populate Identity List
        $IdentityResults = Get-LrIdentities -Identifier $UserSamAccountName
        if ($IdentityResults) {
            $UserIdentityId = $($IdentityResults Select-Object -ExpandProperty identityId)
            ForEach ($UserId in $UserIdentityId) {
                if ($SyncUserIdentities -notcontains $UserId) {
                    $SyncUserIdentities.add($UserId)
                    Write-Host "$(Get-Timestamp) - Error - TrueIdentity Sync - Adding TrueIdentity ID: $($UserId)" -ForegroundColor Green -BackgroundColor Black
                }
            }
        } else {
            Write-Host "$(Get-Timestamp) - Alert - TrueIdentity Sync - No Identity found for SamAccountName: $($UserSamAccountName)" -ForegroundColor Green -BackgroundColor Black
        }     
    }
    Write-Host "$(Get-Timestamp) - Info - AD Group Member Count: $($ADUsers.count)" -ForegroundColor Green -BackgroundColor Black
    Write-Host "$(Get-Timestamp) - Info - SamAccountName Count: $($SyncUserLogins.count)" -ForegroundColor Green -BackgroundColor Black
    Write-Host "$(Get-Timestamp) - Info - Destination Login List: $($List.Output_LoginListName)" -ForegroundColor Green -BackgroundColor Black
    Write-Host "$(Get-Timestamp) - Info - Identities Count: $($SyncUserIdentities.count)" -ForegroundColor Green -BackgroundColor Black
    Write-Host "$(Get-Timestamp) - Info - Destination Identity List: $($List.Output_IdentityListName)" -ForegroundColor Green -BackgroundColor Black

    # Update Login List
    if ($List.Output_LoginListName) {
        Sync-LrListItems -Name $($List.Output_LoginListName) -Value $SyncUserLogins
    }
    
 
    # Update Identity List
    if ($List.Output_IdentityListName) {
        Sync-LrListItems -Name $($List.Output_IdentityListName) -Value $SyncUserIdentities
    }

    Write-Host "$(Get-Timestamp) - End - Processing List: $($List)" -ForegroundColor Green -BackgroundColor Black
}
Write-Host "$(Get-Timestamp) - End - List Synchronization" -ForegroundColor Green -BackgroundColor Black