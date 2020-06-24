$AdminIdentities = Get-ADGroupMember -identity "MYOrgs_PrivilegedAccounts" -Recursive | Select-Object -ExpandProperty SamAccountName | Find-LrIdentity

$UserIdentities = Get-ADGroupMember -identity "MyDepartmentsADGroup" -Recursive | Select-Object -ExpandProperty SamAccountName | Find-LrIdentity

ForEach ($AdminIdentity in $AdminIdentities) {
    ForEach ($UserIdentity in $UserIdentities) {
        if (($UserIdentity.NameFirst -eq $AdminIdentity.NameFirst) -and ($UserIdentity.NameLast -eq $AdminIdentity.NameLast)) {
            merge-lridentities -PrimaryIdentityId $UserIdentity.Id -SecondaryIdentityId $AdminIdentity.Id
        }
    }
}