# Example code that utilizes LogRhythm List APIs in conjunction with Recorded Future Threat List APIs.
# This code is not recommended for direct use but as an example of potential use cases.

# Test if LogRhythm List exists. 
$ListStatus = Get-LrList -Name "RF: Suspicious Phishing IP Address"

# If the target LogRhythm List does not exist we will create the list.  If the list does exist a method will be used to purge the contents from the list.
if (!$ListStatus) {
    # Create the new LogRhythm List
    New-LrList -Name "RF: Suspicious Phishing IP Address" -ListType "ip" -ShortDescription "Recorded Future list of IP Addresses associated with Phishing activity.  RF Risk score between 65 and 89." -ReadAccess "PublicGlobalAnalyst" -WriteAccess "PublicRestrictedAdmin" 
} else {
    # Purge the full contents from the list
    Get-LrListItems -Name "RF: Suspicious Phishing IP Address" -ValuesOnly | Remove-LrListItem -Name "RF: Suspicious Phishing IP Address"
}

# Pull RecordedFuture IP RiskList for PhishingHost Risk 65 - 89 and add to LogRhythm List: RF: Suspicious Phishing IP Address
Get-RfIPRiskList -List "phishingHost" -MinimumRisk 65 -MaximumRisk 89 -ValuesOnly -IPv4 | Add-LrListItem -Name "RF: Suspicious Phishing IP Address"

# Test if LogRhythm List exists.  If it does not exist, create it.
$ListStatus = Get-LrList -Name "RF: High Risk Phishing IP Address"
if (!$ListStatus) {
    # Create the new LogRhythm List
    New-LrList -Name "RF: High Risk Phishing IP Address" -ListType "ip" -ShortDescription "Recorded Future list of IP Addresses associated with Phishing activity.  RF Risk score between 90 and 100." -ReadAccess "PublicGlobalAnalyst" -WriteAccess "PublicRestrictedAdmin" 
} else {
    Get-LrListItems -Name "RF: High Risk Phishing IP Address" -ValuesOnly | Remove-LrListItem -Name "RF: High Risk Phishing IP Address"
}

# Pull RecordedFuture IP RiskList for PhishingHost Risk 90 - 100 and add to LogRhythm List: RF: High Risk Phishing IP Address
Get-RfIPRiskList -List "phishingHost" -MinimumRisk 90 -MaximumRisk 99 -ValuesOnly -IPv4 | Add-LrListItem -Name "RF: High Risk Phishing IP Address"

# Test if LogRhythm List exists.  If it does not exist, create it.
$ListStatus = Get-LrList -Name "RF: Suspicious C&C Server IP Address"
if (!$ListStatus) {
    # Create the new LogRhythm List
    New-LrList -Name "RF: Suspicious C&C Server IP Address" -ListType "ip" -ShortDescription "Recorded Future list of IP Addresses associated with Command and Control activity.  RF Risk score between 40 and 89." -ReadAccess "PublicGlobalAnalyst" -WriteAccess "PublicRestrictedAdmin" 
} else {
    # Purge the full contents from the list
    Get-LrListItems -Name "RF: Suspicious C&C Server IP Address" -ValuesOnly | Remove-LrListItem -Name "RF: Suspicious C&C Server IP Address"
}

# Pull RecordedFuture IP RiskList for Current C&C Server Risk 65 - 89 and add to LogRhythm List: RF: Suspicious C&C Server IP Address
Get-RfIPRiskList -List "recentCncServer" -MinimumRisk 40 -MaximumRisk 89 -ValuesOnly -IPv4 | Add-LrListItem -Name "RF: Suspicious C&C Server IP Address"

# Test if LogRhythm List exists.  If it does not exist, create it.
$ListStatus = Get-LrList -Name "RF: High Risk C&C Server IP Address"
if (!$ListStatus) {
    # Create the new LogRhythm List
    New-LrList -Name "RF: High Risk C&C Server IP Address" -ListType "ip" -ShortDescription "Recorded Future list of IP Addresses associated with Command and Control activity.  RF Risk score between 90 and 100." -ReadAccess "PublicGlobalAnalyst" -WriteAccess "PublicRestrictedAdmin" 
} else {
    # Purge the full contents from the list
    Get-LrListItems -Name "RF: High Risk C&C Server IP Address" -ValuesOnly | Remove-LrListItem -Name "RF: High Risk C&C Server IP Address"
}

# Pull RecordedFuture IP RiskList for Current C&C Server Risk 90 - 100 and add to LogRhythm List: RF: Suspicious C&C Server IP Address
Get-RfIPRiskList -List "recentCncServer" -MinimumRisk 90 -MaximumRisk 99 -ValuesOnly -IPv4 | Add-LrListItem -Name "RF: High Risk C&C Server IP Address"

