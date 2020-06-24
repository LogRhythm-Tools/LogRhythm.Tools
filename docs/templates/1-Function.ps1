using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Set-YourFunctionName {
    <#
    .SYNOPSIS
        xxxx
    .DESCRIPTION
        xxxx
    .PARAMETER param1
        xxxx
    .PARAMETER param2
        xxxx
    .INPUTS
        xxxx
    .OUTPUTS
        xxxx
    .EXAMPLE
        xxxx
    .EXAMPLE
        xxxx
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0
        )]
        [string] $param1
    )


    Begin {
        # General Information Variables
        $SrcRoot = ([System.IO.DirectoryInfo]::new($PSScriptRoot)).Parent
        $SrcRootPath = $SrcRoot.FullName
        $MyName = $MyInvocation.MyCommand.Name
    }


    Process {

    }


    End { }
}