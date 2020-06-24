Function Extract-GzipByteArray{
	[CmdletBinding()]
    Param (
		[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [byte[]] $ByteArray = $(Throw("-byteArray is required"))
    )
	Process {
	    Write-Verbose "Get-DecompressedByteArray"
        $Input = New-Object System.IO.MemoryStream( , $ByteArray )
	    $Output = New-Object System.IO.MemoryStream
        $GzipStream = New-Object System.IO.Compression.GzipStream $Input, ([IO.Compression.CompressionMode]::Decompress)
	    $GzipStream.CopyTo( $Output )
        $GzipStream.Close()
		$Input.Close()
		[byte[]] $ByteOutArray = $Output.ToArray()
        return $ByteOutArray
    }
}