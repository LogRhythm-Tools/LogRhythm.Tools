# Contributing to LogRhythm.Tools

LogRhythm.Tools has a `master` branch for stable releases and a `develop` branch for daily development. New features and fixes are always submitted to the `develop` branch.

This project follows standard [GitHub flow](https://guides.github.com/introduction/flow/index.html). Please learn and be familiar with how to use Git, how to create a fork of the repository, and how to submit a Pull Request. Contributors are likely willing to help you with using Git if you [ask questions in our slack](https://logrhythmcommunity.slack.com) channel `#srf-community`.

After you submit a PR, Project maintainers and contributors will review and discuss your changes, and provide constructive feedback. Once reviewed successfully, your PR will be merged into the `development` branch.

## Commits

> Golen Rule: One change, one commit

- Commits should be atmomic.
- An atomic change is an indivisible change — it can succeed entirely or it can fail entirely, but it cannot partly succeed.  
- The change should represent a piece of functionality that can be replayed over and over against a specific set of premises.
- A change should be able to be reverted (git-revert) and not cause any side effects or conflicts in other parts of the system other than the one that is being reverted.

## Pull Requests

> Golden Rule: One pull request, one concern

- A Pull Request represents a way to deliver value to the application in the form of a set of changes that **together form a high-level concern**
- Pull Requests should address a single concern, should be atomic, changing only that which is required to address the topic.
- Pull Requests should not change things that are not directly concerned with the functionality that is being addressed. 
- If changes such as whitespace, typo fixes, variable renaming, and the like are not related to the topic of the PR, they should be done in a different one.

## Coding Conventions

For detailed information on code style and conventions, please review the [CODESTYLE.txt](https://github.com/LogRhythm-Tools/LogRhythm.Tools/issues) file.

## Quick Guidelines

Here are a few simple rules and suggestions to remember when contributing to LogRhythm.Tools.

:no_entry: Do not commit code that you didn't personally write.

:no_entry: [Do not use Write-Output](https://github.com/PoshCode/PowerShellPracticeAndStyle/issues/#issuecomment-236727676).

:ballot_box_with_check: File names must match the cmdlet name exactly, or will not be imported by the module.

:ballot_box_with_check: Always use [**approved PowerShell verbs**](https://docs.microsoft.com/en-us/powershell/developer/cmdlet/proved-verbs-for-windows-powershell-commands)!

:ballot_box_with_check: Try to include Pester tests along with your changes, or relevant updates to existing Pester tests.

:ballot_box_with_check: Add [comment-based help](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comment_based_help?view=powershell-5.1) for your commands.

:heavy_check_mark: Please try to keep your PRs focused on a single topic and of a reasonable size.

:heavy_check_mark: Please try to write simple and descriptive commit messages.

:heavy_check_mark: Use or follow the general style provided by the templates found in the `docs` directory.

:heavy_check_mark: Try to use [standard cmdlet parameter names](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/andard-cmdlet-parameter-names-and-types?view=powershell-5.1) wherever possible.

:heavy_check_mark: Generally avoid the use of `[trap]` - use try/catch blocks instead. For more information on error handling, [this post is highly recommended](https://powershellexplained.com/2017-04-10-Powershell-exceptions-everything-you-ever-wanted-to-know).

### About Command Output

For *displaying information to a user*, use `Write-Host` or, preferably, `Write-Verbose`. Never use `Write-Output` in any situation, unless there is a very specific reason to do so.

Use of `Write-Host` has been a controversial topic, in particular because of the limitations in doing anything with the output (redirect to `stdout`, etc) and confusion around what goes into the PowerShell pipeline. For the purposes of conveying information, we do **not** want that text getting into the pipeline.

Starting in Windows PowerShell 5.0, `Write-Host` is a wrapper for `Write-Information`, which is a structured information stream and can therefore can be used to transmit structured data between a script and its callers. This makes `Write-Host` useful for console messages without losing redirection functionality, and most importantly will not interfere with the PowerShell pipeline.

Example of redirecting `Write-Host`

```powershell
PS> Write-Host "Somebody said today that I’m lazy. I nearly answered him." 6> c:\tmp\out.txt
```

## Licensing

The LogRhythm.Tools project is under the Microsoft Public License unless a portion of code is explicitly stated elsewhere. See the [LICENSE.txt](LICENSE.txt) file for more details.

The project accepts contributions in "good faith" that they are not bound to a conflicting license. By submitting a PR you agree to distribute your work under the Project's license and copyright.
