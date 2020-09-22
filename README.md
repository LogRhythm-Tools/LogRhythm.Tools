<!-- markdownlint-disable MD026 -->

![Logo](../assets/logos/logo.v1.png?raw=true)

LogRhythm.Tools is a PowerShell module for interacting with LogRhythm APIs. The module is a powerful addition to a LogRhythm analyst's toolbox, and can be used interactively within PowerShell or as a framework for developing SmartResponse plugins - without requiring an understanding of LogRhythm's API layer.

**LogRhythm Components:**

- Admin (Agents, Entities, Hosts, Identities, lists, Locations, LogSources, Networks, Users)
- AI Engine Drilldown for Alarms
- Cases (Evidence, Metrics, Playbooks, Tags)
- LogRhythm Search (LR version 7.5 required)
- LogRhythm Echo

**Third Party Integrations:**

LogRhythm.Tools supports API access to various third party vendors.  Access to these services requires authorization keys provided by the third party and is not granted as a part of the LogRhythm.Tools module.  

- Virus Total
- Recorded Future
- Shodan
- Urlscan

---------

Each command included in the LogRhythm.Tools module is deigned to be modular and built to leverage the power of the PowerShell pipeline.  The output of one LRT command can be sent for processing as input to the another command. And that output can be sent to yet another command. The result is a complex command chain or pipeline that is composed of a series of simple commands.


# Getting Started

## [Requirements](#Requirements)

**Operating Systems**

- Windows 7
- Windows 8.1
- Windows 10
- Windows Server 2008r2
- Windows Server 2012
- Windows Server 2012r2
- Windows Server 2019

**Software**

- Windows Management Framework 5.1
- Windows .Net Framework 4.5.2

**Permissions**

- Ability to download resources from Github.com
- Ability to extract archive files from zip
- User level privileges to run PowerShell
- User level privileges to install PowerShell modules

**Credentials**

***Required***

- LogRhythm API Key

***Optional***

- Recorded Future API Key
- Shodan API Key
- Urlscan API Key
- VirusTotal API Key



> NOTE: For specific Cmdlet requirements reference the section [Cmdlet Version Requirements](#Cmdlet-Version-Requirements)

## Installation

* <a href="https://github.com/LogRhythm-Tools/LogRhythm.Tools/releases" target="_blank">Download</a> and extract the LogRhythm.Tools release package
* Run <code>Setup.ps1</code> on a host that meets LogRhythm.Tools system [requirements](#Requirements)
* Follow the directions presented through the interactive installer
  * To apply configuration changes re-run the <code>Setup.ps1</code>
* Once installation has been complete follow these steps to test basic functionality
  * Open <code>powershell.exe</code>
  * Enter <code>Import-Module LogRhythm.Tools</code>
    * Verify no errors were returned during module import
  * Execute LogRhythm.Tools Cmdlet(s)
    * <code>Get-LrLists</code>
    * <code>Get-LrEntities</code>
    * <code>Get-LrUsers</code>

### Installation Demo
<img src="https://raw.githubusercontent.com/LogRhythm-Tools/LogRhythm.Tools/master/docs/examples/LR.Tools_Installer.gif" width="750" />

For additional examples on how to leverage LogRhythm.Tools check out the [Examples](#examples) section.

---------

## Contributing

Contributions are welcome. Please review the [Contributing](CONTRIBUTING.md) guide and the [Code Style](CODESTYLE.md) guide.

---------

# Additional Details

## [Examples](#examples)

### List Management

#### Retrieving Lists
A great place to start is reviewing all of the lists that are available to us through our API access.  It's important to note that our access is defined and controlled by LogRhythm's RBAC policies.

<code>
    PS C:\LogRhythm.Tools> get-lrlists

    listType        : GeneralValue
    status           : Active
    name            : LRT : Hash : Recently Quarantined Files
    shortDescription : List of file hashes populated in response to Anti-Virus quarantine actions.
    longDescription  :  This list is leveraged to identify any additional Information System that may have activity corresponding with the identified file hash.
    useContext       : {Hash}
    autoImportOption : @{enabled=False; usePatterns=False; replaceExisting=False}
    importFileName   :
    id               : 2001
    guid             : BC952970-2AF3-46B7-BB1F-4282102EB1FE
    dateCreated      : 2020-06-11T16:47:13.823Z
    dateUpdated      : 2020-06-11T16:47:14.677Z
    revisitDate      : 2030-06-11T10:47:14.677Z
    readAccess       : PublicRestrictedAdmin
    writeAccess      : PublicRestrictedAdmin
    restrictedRead   : False
    entityName       : Primary Site
    entryCount       : 12
    needToNotify     : False
    doesExpire       : False
    owner            : 1

     
    listType         : GeneralValue
    status            : Active
    name             : LRT : Domain : ConfLo : Blacklisted Dns Name
    shortDescription : List of URLs that have a low level of confidence associated with Blacklisted DNS names.
    longDescription  :  This list is leveraged to identify Information Systems that may have activity with suspicious domain names.
    useContext       : {URL}
    autoImportOption : @{enabled=False; usePatterns=False; replaceExisting=False}
    importFileName   :
    id               : 2019
    guid             : 7328F064-6E70-45E8-8881-B9917F15C9D3
    dateCreated      : 2020-06-12T14:23:01.853Z
    dateUpdated      : 2020-06-12T14:23:02.743Z
    revisitDate      : 2030-06-12T08:23:02.743Z
    readAccess       : PublicRestrictedAdmin
    writeAccess      : PublicRestrictedAdmin
    restrictedRead   : False
    entityName       : Primary Site
    entryCount       : 12
    needToNotify     : False
    doesExpire       : False
    owner            : 1
</code>

#### Retrieving list values
The list LRT : Domain : ConfLo : Blacklisted Dns Name appears interesting and we want to review only the list values populated on the list.  For this we'll make use of the Get-LrListItems cmdlet where we can reference our target list by its name, LRT : Domain : ConfLo : Blacklisted Dns Name or by its GUID 7328F064-6E70-45E8-8881-B9917F15C9D3.  This is thanks to the implementation design of the LogRhythm Tools cmdlets. 

<code>
    PS C:\LogRhythm.Tools> get-lrlistitems -Name "LRT : Domain : ConfLo : Blacklisted Dns Name" -ValuesOnly

    www.plxipr.com
    imagescmeraclub.com
    tutorialsalk.info
    buildingmsu.ac.th
    www.haecaklaw.com
    bolizarsspos.com
    logrhythm.com
    boilersadfurnaces.com
    appum.com
    avacarvisual.com.br
    amle-sun.eu
    icst.na.its.ac.id
</code>

#### Removing an item from a list
Reviewing the results from our Blacklisted Dns Name's it looks like a mistake has been introduced with the logrhythm.com entry.  This example will showcase how to remove a specific value from this list.  With this method we will change from referencing the list from the name property and instead reference the list by its GUID.

<code>
    PS C:\LogRhythm.Tools> Remove-LrListItem -Name '7328F064-6E70-45E8-8881-B9917F15C9D3' -Value "logrhythm.com"

    listType         : GeneralValue
    status           : Active
    name             : LRT : Domain : ConfLo : Blacklisted Dns Name
    shortDescription : List of URLs that have a low level of confidence associated with Blacklisted DNS names.
    longDescription  : This list is leveraged to identify Information Systems that may have activity with suspicious domain names.
    useContext       : {URL}
    autoImportOption : @{enabled=False; usePatterns=False; replaceExisting=False}
    importFileName   :
    id               : 2025
    guid             : 7328F064-6E70-45E8-8881-B9917F15C9D3
    dateCreated      : 2020-06-12T14:23:04.917Z
    dateUpdated      : 2020-06-22T20:32:09.853Z
    revisitDate      : 2030-06-22T14:32:09.857Z
    readAccess       : PublicRestrictedAdmin
    writeAccess      : PublicRestrictedAdmin
    restrictedRead   : False
    entityName       : Primary Site
    entryCount       : 11
    needToNotify     : False
    doesExpire       : False
    owner            : 1
    listItemsCount   : 0
</code>

To validate we can check our list's results to verify the removal.

<code>
    PS C:\LogRhythm.Tools> get-lrlistitems -Name "LRT : Domain : ConfLo : Blacklisted Dns Name" -ValuesOnly

    www.plxipr.com
    imagescmeraclub.com
    tutorialsalk.info
    buildingmsu.ac.th
    www.haecaklaw.com
    bolizarsspos.com
    boilersadfurnaces.com
    appum.com
    avacarvisual.com.br
    amle-sun.eu
    icst.na.its.ac.id
</code>

#### Remove all items from a list
Lets say we want to carry out some maintenance and clear out all the results from our Blacklisted Dns Name list.  For this example we'll utiize Powershell's pipeline processing and two LogRhythm Tools cmdlets.  The first cmdlet is from our earlier retrieving list items example that will be paired with the removing an item example.

<code>
    PS C:\LogRhythm.Tools> Get-LrListItems -name "LRT : Domain : ConfLo : Blacklisted Dns Name" -ValuesOnly | Remove-LrListItem -Name "LRT : Domain : ConfLo : Blacklisted Dns Name"

    listType         : GeneralValue
    status           : Active
    name             : LRT : Domain : ConfLo : Blacklisted Dns Name
    shortDescription : List of URLs that have a low level of confidence associated with Blacklisted DNS names.
    longDescription  : This list is leveraged to identify Information Systems that may have activity with suspicious domain names.
    useContext       : {URL}
    autoImportOption : @{enabled=False; usePatterns=False; replaceExisting=False}
    importFileName   :
    id               : 2025
    guid             : 7328F064-6E70-45E8-8881-B9917F15C9D3
    dateCreated      : 2020-06-12T14:23:04.917Z
    dateUpdated      : 2020-06-22T20:39:56.247Z
    revisitDate      : 2030-06-22T14:39:56.247Z
    readAccess       : PublicRestrictedAdmin
    writeAccess      : PublicRestrictedAdmin
    restrictedRead   : False
    entityName       : Primary Site
    entryCount       : 0
    needToNotify     : False
    doesExpire       : False
    owner            : 1
    listItemsCount   : 0
</code>

This example begins to show some of the flexibility and capability of the LogRhythm Tools PowerShell module.  The results show we successfully cleared out the number of entries contained in our target list through a single line of code with two cmdlets.  The same method we've applied for removing items from LogRhythm Lists can also be applied to adding items to lists. 

---

## [Cmdlet Version Requirements](#Cmdlet-Version-Requirements)
LogRhythm.Tools was developed and has undergone testing leveraging LogRhythm SIEM versions 7.4.X and 7.5.X.  Validate the SIEM version with the Minimum Version specification below prior to submitting Cmdlet issues.

|Cmdlet|API Endpoint|Category|Minimum Version|
|------|------------|--------|---------------|
|Get-LrAgentDetails|Admin|Agents|7.5.0|
|Get-LrAgentLogSources|Admin|Agents|7.5.0|
|Get-LrAgentsAccepted|Admin|Agents|7.5.0|
|Get-LrEntities|Admin|Entities|7.4.0|
|Get-LrEntityDetails|Admin|Entities|7.4.0|
|Get-LrHostDetails|Admin|Hosts|7.4.0|
|Get-LrHostIdentifiers|Admin|Hosts|7.4.0|
|Get-LrHosts|Admin|Hosts|7.4.0|
|New-LrHost|Admin|Hosts|7.4.0|
|Remove-LrHostIdentifier|Admin|Hosts|7.4.0|
|Update-LrHost|Admin|Hosts|7.4.0|
|Update-LrHostIdentifier|Admin|Hosts|7.4.0|
|Update-LrHostStatus|Admin|Hosts|7.4.0|
|Add-LrIdentitiy|Admin|Identity|7.4.0|
|Add-LrIdentityIdentifier|Admin|Identity|7.4.0|
|Disable-LrIdentity|Admin|Identity|7.4.0|
|Disable-LrIdentityIdentifier|Admin|Identity|7.4.0|
|Enable-LrIdentity|Admin|Identity|7.4.0|
|Enable-LrIdentityIdentifier|Admin|Identity|7.4.0|
|Find-LrIdentity|Admin|Identity|7.4.0|
|Find-LrIdentitySummaries|Admin|Identity|7.4.0|
|Format-LrIdentityPsObject|Admin|Identity|7.4.0|
|Get-LrIdentities|Admin|Identity|7.4.0|
|Get-LrIDentityById|Admin|Identity|7.4.0|
|Get-LrIdentityIdentifierConflicts|Admin|Identity|7.4.0|
|Merge-LrIDentities|Admin|Identity|7.4.0|
|Test-LrIdentifierType|Admin|Identity|7.4.0|
|Test-LrIdentityIDentifierId|Admin|Identity|7.4.0|
|Test-LrIdentityIdentifierValue|Admin|Identity|7.4.0|
|Add-LrListItem|Admin|Lists|7.4.0|
|Get-LrListGuidByName|Admin|Lists|7.4.0|
|Get-LrList|Admin|Lists|7.4.0|
|Get-LrListItems|Admin|Lists|7.4.0|
|Get-LrLists|Admin|Lists|7.4.0|
|New-LrList|Admin|Lists|7.4.0|
|Remove-LrListItem|Admin|Lists|7.4.0|
|Sync-LrListItems|Admin|Lists|7.4.0|
|Test-LrListType|Admin|Lists|7.4.0|
|Test-LrListValue|Admin|Lists|7.4.0|
|Get-LrLocations|Admin|Location|7.5.0|
|Show-LrLocations|Admin|Location|All versions|
|Get-LrLogSourceDetails|Admin|LogSources|7.5.0|
|Get-LrLogSources|Admin|LogSources|7.5.0|
|Find-LrNetworkByIP|Admin|Networks|7.4.0|
|Get-LrNetworkDetails|Admin|Networks|7.4.0|
|Get-LrNetworks|Admin|Networks|7.4.0|
|New-LrNetwork|Admin|Networks|7.4.0|
|Update-LrNetwork|Admin|Networks|7.4.0|
|Get-LrUserNumber|Admin|Users|7.4.0|
|Get-LrUsers|Admin|Users|7.4.0|
|Test-LrUserIdFormat|Admin|Users|7.4.0|
|Add-LrAlarmToCase|Evidence|General|7.4.0|
|Add-LrNoteToCase|Evidence|General|7.4.0|
|Add-LrCasePlaybook|Case|General|7.4.0|
|Add-LrCaseTags|Case|General|7.4.0|
|Format-LrCaseListSummary|Case|General|7.4.0|
|Get-LrCaseById|Case|General|7.4.0|
|Get-LrCaseEarliestEvidence|Case|General|7.4.0|
|Get-LrCasePlaybookProcedures|Case|General|7.4.0|
|Get-LrCasePlaybooks|Case|General|7.4.0|
|Get-LrCaseStatusTable|Case|General|7.4.0|
|Get-LrCases|Case|General|7.4.0|
|Get-PIFTypeName|Case|General|7.4.0|
|New-LrCase|Case|General|7.4.0|
|Remove-LrCasePlaybook|Case|General|7.4.0|
|Remove-LrCaseTags|Case|General|7.4.0|
|Test-LrCaseIdFormat|Case|General|7.4.0|
|Update-LrCaseEarliestEvidence|Case|General|7.4.0|
|Update-LrCaseEarliestEvidenceFromDrilldown|Case|General|7.4.0|
|Update-LrCasePlaybookProcedure|Case|General|7.4.0|
|Update-LrCaseStatus|Case|General|7.4.0|
|Get-LrCaseMetrics|Case|Metrics|7.4.0|
|Copy-LrPlaybook|Case|Playbooks|7.4.0|
|Get-LrPlaybookById|Case|Playbooks|7.4.0|
|Get-LrPlaybooks|Case|Playbooks|7.4.0|
|New-LrPlaybook|Case|Playbooks|7.4.0|
|Remove-LrPlaybook|Case|Playbooks|7.4.0|
|Update-LrPlaybook|Case|Playbooks|7.4.0|
|Get-LrPlaybookProcedure|Case|Procedures|7.4.0|
|Test-LrProcedureIdFormat|Case|Procedures|7.4.0|
|Update-LrPlaybookProcedure|Case|Procedures|7.4.0|
|Get-LrTag|Case|Tags|7.4.0|
|Get-LrTagNumber|Case|Tags|7.4.0|
|Get-LrTags|Case|Tags|7.4.0|
|New-LrTag|Case|Tags|7.4.0|
|Remove-LrTag|Case|Tags|7.4.0|
|Get-LrSearchResults|Search|Search|7.5.0|
|New-LrSearch|Search|Search|7.5.0|
|Test-LrFilterType|Search|Search|7.5.0|
|Get-LrAieDrilldown|AIE|AIE|7.4.0|

