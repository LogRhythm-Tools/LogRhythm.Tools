function ConvertTo-MarkDown {
    <#
        .SYNOPSIS
            Gets the comment-based help of a command and converts to GitHub-style Markdown.
        .PARAMETER Command
            Specifies the name of a cmdlet that with comment-based help.
        .EXAMPLE
            ConvertTo-MarkDown Select-Object > .\SelectObject.md
            
            DESCRIPTION
            -----------
            This example gets comment-based help of `Select-Object` command, and converts GitHub Flavored Markdown format, 
            then saves it to `SelectObject.md` in the current directory.
        .INPUTS
            This cmdlet does not accept pipeline input.
        .OUTPUTS
            System.String
            Comment based help in Markdown format.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        $Command
    )

    try {
        if ($Host.UI.RawUI) {
          $rawUI = $Host.UI.RawUI
          $oldSize = $rawUI.BufferSize
          $typeName = $oldSize.GetType().FullName
          $newSize = New-Object $typeName (500, $oldSize.Height)
          $rawUI.BufferSize = $newSize
        }
        $full = Get-Help $Command -Full

@"
# $($full.Name)

## SYNOPSIS

$($full.Synopsis)

## SYNTAX

``````powershell
$((($full.syntax | Out-String) -replace "`r`n", "`r`n`r`n").Trim())
``````
## DESCRIPTION

$(($full.description | Out-String).Trim())

## PARAMETERS

"@ + $(foreach ($parameter in $full.parameters.parameter) {
@"

### -$($parameter.name) &lt;$($parameter.type.name)&gt;
$(($parameter.description | Out-String).Trim())
``````
$(((($parameter | Out-String).Trim() -split "`r`n")[-5..-1] | ForEach-Object { $_.Trim() }) -join "`r`n")
``````
"@
}) + @"
## INPUTS
$($full.inputTypes.inputType.type.name)
## OUTPUTS
$($full.returnValues.returnValue[0].type.name)
## NOTES
$(($full.alertSet.alert | Out-String).Trim())
## EXAMPLES
"@ + $(foreach ($example in $full.examples.example) {
@"
### $(($example.title -replace '-*', '').Trim())
``````powershell
$(GetCode $example)
``````
$(GetRemark $example)
"@
}) + @"
"@

    } finally {
        if ($Host.UI.RawUI) {
        $rawUI = $Host.UI.RawUI
        $rawUI.BufferSize = $oldSize
        }
    }
}

function GetCode {
    param (
        $Example
    )
    $codeAndRemarks = (($Example | Out-String) -replace ($Example.title), '').Trim() -split "`r`n"

    $code = New-Object "System.Collections.Generic.List[string]"
    for ($i = 0; $i -lt $codeAndRemarks.Length; $i++) {
        if ($codeAndRemarks[$i] -eq 'DESCRIPTION' -and $codeAndRemarks[$i + 1] -eq '-----------') {
            break
        }
        if (1 -le $i -and $i -le 2) {
            continue
        }
        $code.Add($codeAndRemarks[$i])
    }

    $code -join "`r`n"
}

function GetRemark {
    param (
        $Example
    )
    $codeAndRemarks = (($Example | Out-String) -replace ($Example.title), '').Trim() -split "`r`n"

    $isSkipped = $false
    $remark = New-Object "System.Collections.Generic.List[string]"
    for ($i = 0; $i -lt $codeAndRemarks.Length; $i++) {
        if (!$isSkipped -and $codeAndRemarks[$i - 2] -ne 'DESCRIPTION' -and $codeAndRemarks[$i - 1] -ne '-----------') {
            continue
        }
        $isSkipped = $true
        $remark.Add($codeAndRemarks[$i])
    }

    $remark -join "`r`n"
}




