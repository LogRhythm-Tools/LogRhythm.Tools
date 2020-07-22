Function ConvertTo-IPv4NetMask {
    <#
    .SYNOPSIS
        Converts a int16 to an IPv4 Subnet string.
    .PARAMETER PrefixLength
        Number of bits enabled in IPv4 subnet.
    .INPUTS
        int16 -> PrefixLength
    .OUTPUTS
        String
    .EXAMPLE
        ConvertTo-IPv4NetMask -PrefixLength 9
        ---
        255.128.0.0
    .EXAMPLE
        ConvertTo-IPv4NetMask -PrefixLength 20
        ---
        255.255.240.0
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>
    [CmdletBinding()]
    Param([ValidateRange(0,32)]
      [int16]$PrefixLength=0
    )

    $bitString=('1' * $PrefixLength).PadRight(32,'0')
  
    $strBuilder=New-Object -TypeName Text.StringBuilder
  
    for($i=0;$i -lt 32;$i+=8){
      $8bitString=$bitString.Substring($i,8)
      [void]$strBuilder.Append("$([Convert]::ToInt32($8bitString,2)).")
    }
  
    return $strBuilder.ToString().TrimEnd('.')
}