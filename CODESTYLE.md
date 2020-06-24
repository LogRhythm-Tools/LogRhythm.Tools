<!-- markdownlint-disable MD041 -->

# Useful Links

* [Standard Cmdlet Parameter Names and Types](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/standard-cmdlet-parameter-names-and-types?view=powershell-5.1)
* [Approved Verbs for PowerShell Commands](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-5.1)
* [DSC Resource Style Guidelines](https://github.com/PowerShell/DscResources/blob/master/StyleGuidelines.md)

# Coding Guidelines

**NOTE:** The code style standard for LogRhythm.Tools is a work in progress - most of the code conforms to these standards, but some functions were written before this style guide was compiled.

For suggestions or discussion of code style please [open an issue](https://github.com/LogRhythm-Tools/LogRhythm.Tools/issues).

## Naming Conventions

*In regards to naming*, LogRhythm.Tools follows the [DSC Resource Style Guidelines](https://github.com/PowerShell/DscResources/blob/master/StyleGuidelines.md) - with the exception of **Variables, which use PascalCase**.

### Functions

Function / Cmdlet names should use PascalCase and follow Noun-Verb convention.

:boom: :boom: Only one function can be declared in a file, and the **file must be named exactly the same as the function**.

```powershell
# Get-TargetResource.ps1
function Get-TargetResource {
    # Right
}

function getTargetResource {
    # Wrong
}
```

#### Function Name Structure

Exported functions should observe the following naming structure.

`[Verb]-[Module][Class][Description]`

| Part      | Description |
| ----------- | ----------- |
| `Verb` | The first part of the function follows the [approved verb list](https://docs.microsoft.com/en-us/powershell/developer/cmdlet/approved-verbs-for-windows-powershell-commands) published by Microsoft. |
| `Module` | The second portion of the function name indicates that it is part of the LogRhythm.Tools module|
| `Classification` | The optional third part identifies if the function is related to PSRemoting, ActiveDirectory, Azure, or LogRhythm functionality.|
| `Name` | The remaining portion of the function name is descriptive.|

**Example**: `Add-SrfRMGroupMember`

> Adds a group member to a host using PSRemoting.

### Parameters

If possible, use [Standard Cmdlet Parameter Names and Types](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/standard-cmdlet-parameter-names-and-types?view=powershell-5.1).

Parameter names should use **PascalCase**.

```powershell

# Right
[Parameter(Mandatory = $true)]
[object] $SOURCEPATH

# Wrong
[Parameter(Mandatory = $true)]
[object] $SourcePath

```

### Variables

Variable names should use **PascalCase**.

```powershell
function New-Log {
    $Message = "New log message" # should start with lower case
    Write-Host $Message
}
```

## Tabs & Indenting

Tab characters (\0x09) should not be used in code. All indentation should be done with 4 space characters.

## Bracing

Open braces should be at the end of the line of the statement that begins the block. Contents of the brace should be indented by 4 spaces. Single statements do not have braces. For example:

```powershell
if (someExpression) {
   $Result = Invoke-Something
} else {
   Invoke-OtherThing
}
```

Very short `if` statements can be placed on a single line if the meaning is clear:

```powershell
if (someExpression) { Invoke-Something }
```

## Commenting

:heavy_check_mark: Insert a linebreak when a comment reaches 100 characters.

Comments should be used to describe intention, algorithmic overview, and/or logical flow.  It would be ideal if, from reading the comments alone, someone other than the author could understand a function's intended behavior and general operation. While there are no minimum comment requirements (and certainly some very small routines need no commenting at all), it is best that most routines have comments reflecting the programmer's intent and approach.

Comments must provide added value or explanation to the code. Simply describing the code is not helpful or useful.

```powershell
    # Wrong
    # Set count to 1
    count = 1;

    # Right
    # Set the initial count of connection attempts to record
    count = 1;

```

## Comment Based Help

All cmdlets should use [Comment Based Help](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comment_based_help?view=powershell-5.1).  Templates are available in the docs directory.

```powershell
    <#
    .SYNOPSIS
        One Sentence Description
    .DESCRIPTION
        Detailed description of cmdlet and how it operates.
    .PARAMETER param1
        Ensure to include every parameter, and any special information about
        how they are used.
    .INPUTS
        Document which parameters accept pipeline input.
    .OUTPUTS
        Often this should be a description of the object returned by the cmdlet,
        or null, or true/false. Generally avoid using strings such as "Complete"
        as command output - though you could possibly output something like a Guid
        as a string, providing an actual System.Guid object would much more preferable.
    .EXAMPLE
        Include at least one example and its output.
    .LINK
        Always include a link to the main repo (not to the file itself)
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>
```

## Spacing

Spaces improve readability by decreasing code density. Here are some guidelines for the use of space characters within code:

Do use a single space after a comma between function arguments.

```powershell
$Headers.Add("Authorization", "Bearer $Token")  # Right
$Headers.Add("Authorization","Bearer $Token")   # Wrong
```

Do not use a space after the parenthesis and function arguments.

```powershell
$Headers.Add("Content-Type", "application/json")    # Right
$Headers.Add( "Content-Type", "application/json" )  # Wrong
```

Do not use spaces between a function name and parentheses.

```powershell
$PSCmdlet.ThrowTerminatingError($PSItem)    # Right
$PSCmdlet.ThrowTerminatingError ($PSItem)   # Wrong
```

Do not use spaces inside brackets.

```powershell
$x = $dataArray[0];     # Right
$x = $dataArray[ 0 ];   # Wrong
```

Do use a single space before and after assignment operators.

```powershell
$x = 1  # Right
$x=1    # Wrong
```

Do not use a space between a unary operator and the operand.

```powershell
$i++;   # Right
$i ++;  # Wrong
```

Do not use a space before a semi-colon. Do use a space after a semi-colon if there is more on the same line.

```powershell
for ($i = 0; $i -lt 10; $i++)   # Right
for ($i=0 ; $i -lt 10 ; $i++)   # Wrong
```
