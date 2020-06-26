<!-- markdownlint-disable MD026 -->
# :hammer: LogRhythm.Tools :hammer:

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

## Requirements ##

** Operating Systems **

- Windows 7
- Windows 8.1
- Windows 10
- Windows Server 2008r2
- Windows Server 2012
- Windows Server 2012r2
- Windows Server 2019

** Software **

- Windows Management Framework 5.1
- Windows .Net Framework 4.5.2

** Permissions **

- Ability to download resources from Github.com
- Ability to extract archive files from zip
- User level privileges to run PowerShell
- User level privileges to install PowerShell modules

** Credentials **

*** Required ***

LogRhythm API Key

*** Optional ***

Recorded Future API Key
Shodan API Key
Urlscan API Key
VirusTotal API Key


## Installation ##

:construction: Coming soon :construction:

## Coming Soon

Our 1.0 release is just around the corner, and we will be publishing a pre-release candidate on June 29th, 2020.  Stay tuned for more information, documentation and other materials that will help you in getting started with the LogRhythm.Tools module!

---------

## Contributing

Contributions are welcome. Please review the [Contributing](CONTRIBUTING.md) guide and the [Code Style](CODESTYLE.md) guide.
