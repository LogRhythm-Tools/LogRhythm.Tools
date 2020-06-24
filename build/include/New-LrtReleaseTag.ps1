using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function New-LrtReleaseTag {
    # Not sure if we should use it, but I figured we could give our releases a fun tag to identify it.
    # This command picks $Count number of random tags in the form of:
    # <Random Emotion> + <Random Animal>
    # Example: Fearful Hornet / Sad Porcupine

    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [int] $Count = 1
    )

    $ReleaseTags = [List[string]]::new()

    for ($i = 0; $i -lt $Count; $i++) {
        # Emotions
        $Emotions = Get-Content -Path "$PSScriptRoot\content\emotions.txt"
        $RandomId = Get-Random -Minimum 0 -Maximum ($Emotions.Count -1)
        $RandomEmotion = $Emotions[$RandomId]

        # Animals
        $Animals = Get-Content -Path "$PSScriptRoot\content\animals.txt"
        $RandomId = Get-Random -Minimum 0 -Maximum ($Animals.Count -1)
        $RandomAnimal = $Animals[$RandomId]

        $ReleaseTags.Add($RandomEmotion + " " + $RandomAnimal)
    }

    return $ReleaseTags
}