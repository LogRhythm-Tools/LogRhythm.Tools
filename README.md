<!-- markdownlint-disable MD026 -->
# :dizzy: LogRhythm.Tools :dizzy:

LogRhythm.Tools is a powershell module containing commands (cmdlets) intended primarily for use in LogRhythm SmartResponse Plugin development, but can also be used interactively.  

This is an open source, community-driven project. Pull requests, are welcome and encouraged - please review the contribution guidelines below. Feel free to [submit an issue](https://github.com/LogRhythm-Tools/LogRhythm.Tools/issues) to discuss enhancements, design, bugs, questions or other feedback.

:fire: **Everyone is encouraged to read and contribute to [open design issues](https://github.com/LogRhythm-Tools/LogRhythm.Tools/issues).**

## News: February, 2020

I am working on a new major release which will streamline storing your LogRhythm bearer token, and generally make setup much easier and user friendly.

I am targeting this release for 3/15/2020!

## December, 2020


I've released the full set of LogRhythm Automation commands that I've created to date.  This gives you the building blocks to fully implement case creation automation, in addition to things like case metrics. Since results are returned as PowerShell objects, there are many ways you can use the data retrieved.

Here's an example of pulling case information.  There are quite a few more options than these, so be sure to check `Get-Help` on any command you want to use.

```powershell
PS> $Result = Get-LrCases -CreatedAfter "2019-10-01 00:00:00" -ExcludeTags @("Testing", "API Testing")
PS> Format-LrCaseListSummary -InputObject $Result

Count             : 183
Oldest            : 2019-10-01T16:43:59.0469619Z
Newest            : 2019-12-16T21:48:54.4880726Z
AvgCloseTimeDays  : 1.36330091726311
AvgCloseTimeHours : 32.7192220143147
TotalOpen         : 7
TotalClosed       : 176
DistinctTags      : 61
DistinctOwners    : 5
Tags              : {@{Name=Malware; Count=74}, @{Name=Phishing; Count=67}, @{Name=pdf; Count=26}, @{Name=Remediated Successfully; Count=40}...}
Status            : {@{Name=Completed; Count=154}, @{Name=Resolved; Count=20}, @{Name=Created; Count=7}, @{Name=Mitigated; Count=2}}
Owners            : {@{Name=Analyst Greg; Count=88}, @{Name=Analyst, Bob; Count=49}, @{Name=Analyst, Dwight; Count=11}, @{Name=Analyst, Ben; Count=25}...}
```

You'll probably want to use an alarm to create your cases.  The Alarm Id would be available at the time your alarm is triggered, otherwise you can find an Alarm ID in the web console, at the top of any alarm's detail. 

```powershell
PS> $Alarm = Get-LrAieDrilldown -AlarmId 2261194
```

Another example of creating a case:

```powershell
# Create an initial case
PS> $Case = New-LrCase -Name "Test Case" -Priority 2 -Summary "This is a new case!" -DueDate "2019-12-17 16:00:00" -AlarmNumbers $Alarm.AlarmID

# Add tags to the case, from an array of tag names (must be exact)
PS> Add-LrTagsToCase -Id $Case.id -Tags @("Tag1","Tag2","Tag3")

# Add a playbook by name (must be exact)
PS> Add-LrPlaybookToCase -Id $Case.id -Playbook "Name of Playbook"

# Turn the case into an incident
PS> Update-LrCaseStatus -Id $Case.id -Status 3

# Add a note to the case.
PS> Add-LrNoteToCase -Id $Case.id -Text "Adding a note to the case"
```

## Getting Started

Getting started is easy, if you have some familiarity with Git and PowerShell.

### Requirements

* OS Requirements: older versions *may* work, but have not been tested.
  * Windows 10 Build 1803 or newer
  * Windows Server 2012 R2 or newer
* PowerShell Version 5.1+
* Remote Server Administration Tools + ActiveDirectory PowerShell Module.

### Get and build the module

```powershell
PS> git clone https://github.com/LogRhythm-Tools/LogRhythm.Tools
PS> cd LogRhythm.Tools
```

Edit the preferences file (replace code with editor of your choice)

```powershell
PS> >>removed<<
```

There are a couple of ways to go about this, but the easiest by far is to save a copy of your LR API Token in an encrypted credentials file:

```powershell
PS> Get-Credential | Export-CliXml -Path <removed>
```

Now back to your terminal, build the module:

```powershell
PS> .\New-TestBuild.ps1
===========================================
> New-TestBuild.ps1 12/19/2019 9:47:52 AM
===========================================
Creating new build: [Success]
Import Build:       [Success]
Import LrApi Token: [Success]
===========================================
```

You should now have a working copy of the module in your current PowerShell environment!

Give this a shot to check that everything is working:

```powershell
PS> Get-LrTags
```

:hammer: For more on how **module builds** work, please review the [Build Process](build/readme.md).

### Configuration

Currently there is a little configuration required for some cmdlets to function properly. This design is [open to discussion here](https://github.com/LogRhythm-Tools/LogRhythm.Tools/issues/1).

The configuration file is located in the repository under >>removed<<.

In order for the LogRhythm API commands to work, you will need to fill out the following section, save the file, and rebuild the module with the `New-TestBuild.ps1` script.

```json
"LogRhythm": {
    "AdminBaseUrl": "https://server.domain.com:8501/lr-admin-api",
    "CaseBaseUrl": "https://server.domain.com:8501/lr-case-api",
    "ApiVaultId": "121212",
    "PlatformManager": "server.domain.com",
    "WebConsole": "logrhythm.domain.com",
    "SrpHost": "server.domain.com"
}
```


### Running a command

*An example of one of the LogRhythm Case Commands*

First we will need to get our API Token into a credential. The way I do this is by requesting the token from our SecretServer installation by way of the `Get-Secret` cmdlet in this module.  You can also do this by pasting your token into a PSCredential object like so:

```powershell
PS> $password = Read-Host -Prompt "token" -AsSecureString
token: *****(paste token)
$token = [pscredential]::new("lr", $password)
```

Then we can run one of the LogRhythm Case Commands. In this example, a playbook imported from the LogRhythm community about Malware is returned. Any playbooks with Malware in the name will also be returned in an array of playbook objects. You can also specify the `-Verbose` switch for a little more info.

```powershell
Get-LrPlaybooks -Credential $token -Name "Malware"

    id            : BC3B367A-28CB-4E65-BE74-3B4ED5077976
    name          : Malware Incident
    description   : Use this Playbook when responding to malicious events that use an exploit code targeting vulnerable services instead of using a compiled malicious binary, typically known as a virus.
    permissions   : @{read=publicAllUsers; write=publicGlobalAdmin}
    owner         : @{number=35; name=Smith, Bob; disabled=False}
    retired       : False
    entities      : {@{number=1; name=Primary Site}}
    dateCreated   : 2019-04-10T15:27:54.1499666Z
    dateUpdated   : 2019-09-11T14:30:53.1726298Z
    lastUpdatedBy : @{number=35; name=Smith, Bob; disabled=False}
    tags          : {@{number=66; text=APT}, @{number=5; text=Malware}}
```

Check out more info on the command with:

`PS> Get-Help Get-LrPlaybooks -Full`

---------

## Contributing

Contributions are welcome. Please review the [Contributing](CONTRIBUTING.md) guide and the [Code Style](CODESTYLE.md) guide.

