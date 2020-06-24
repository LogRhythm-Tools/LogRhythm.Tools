<!-- markdownlint-disable MD026 -->
# :hammer: LogRhythm.Tools

LogRhythm.Tools is a PowerShell module for interacting with LogRhythm APIs. The module is a powerful addition to a LogRhythm analyst's toolbox, and can be used interactively within PowerShell or as a framework for developing SmartResponse plugins - without requiring an understanding of LogRhythm's API layer.

**LogRhythm Components:**

- Admin (Agents, Entities, Hosts, Identities, lists, Locations, LogSources, Networks, Users)
- Cases (Evidence, Metrics, Playbooks, Tags)
- AI Engine Drilldown for Alarms
- LogRhythm Search (LR version 7.5 required)

**Third Party Integrations:**

- Virus Total
- Recorded Future
- Shodan
- Urlscan


Each command included in the LogRhythm.Tools module is deigned to be modular and built to leverage the power of the PowerShell pipeline.  The output of one LRT command can be sent for processing as input to the another command. And that output can be sent to yet another command. The result is a complex command chain or pipeline that is composed of a series of simple commands.

## Coming Soon

Our 1.0 release is just around the corner, and we will be publishing a pre-release candidate on June 29th, 2020.  Stay tuned for more information, documentation and other materials that will help you in getting started with the LogRhythm.Tools module!

---------

## Contributing

Contributions are welcome. Please review the [Contributing](CONTRIBUTING.md) guide and the [Code Style](CODESTYLE.md) guide.
