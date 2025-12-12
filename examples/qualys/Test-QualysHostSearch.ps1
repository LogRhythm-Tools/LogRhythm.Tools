# Test script to debug Qualys host asset search
Param(
    [Parameter(Mandatory = $true)]
    [string] $Hostname
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Testing Qualys Host Asset Search" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Searching for: $Hostname" -ForegroundColor White
Write-Host ""

# Try different search methods
Write-Host "[Test 1] Searching by Name (CONTAINS)" -ForegroundColor Yellow
$Result1 = Get-QualysHostAssets -Name $Hostname -Verbose
if ($Result1) {
    Write-Host "  FOUND: $($Result1.Count) result(s)" -ForegroundColor Green
    $Result1 | Select-Object id, name, dnsHostName, address | Format-Table -AutoSize
} else {
    Write-Host "  NOT FOUND" -ForegroundColor Red
}
Write-Host ""

Write-Host "[Test 2] Searching by DnsHostName (CONTAINS)" -ForegroundColor Yellow
$Result2 = Get-QualysHostAssets -DnsHostName $Hostname -Verbose
if ($Result2) {
    Write-Host "  FOUND: $($Result2.Count) result(s)" -ForegroundColor Green
    $Result2 | Select-Object id, name, dnsHostName, address | Format-Table -AutoSize
} else {
    Write-Host "  NOT FOUND" -ForegroundColor Red
}
Write-Host ""

Write-Host "[Test 3] Getting ALL assets and filtering locally" -ForegroundColor Yellow
Write-Host "  This may take a while..." -ForegroundColor DarkGray
$AllAssets = Get-QualysHostAssets
if ($AllAssets) {
    Write-Host "  Total assets retrieved: $($AllAssets.Count)" -ForegroundColor Cyan

    # Try exact match
    $ExactMatch = $AllAssets | Where-Object { $_.name -eq $Hostname }
    if ($ExactMatch) {
        Write-Host "  EXACT MATCH FOUND:" -ForegroundColor Green
        $ExactMatch | Select-Object id, name, dnsHostName, address | Format-Table -AutoSize
    }

    # Try case-insensitive match
    $CaseInsensitiveMatch = $AllAssets | Where-Object { $_.name -like $Hostname }
    if ($CaseInsensitiveMatch) {
        Write-Host "  CASE-INSENSITIVE MATCH FOUND:" -ForegroundColor Green
        $CaseInsensitiveMatch | Select-Object id, name, dnsHostName, address | Format-Table -AutoSize
    }

    # Try partial match
    $PartialMatch = $AllAssets | Where-Object { $_.name -like "*$Hostname*" }
    if ($PartialMatch) {
        Write-Host "  PARTIAL MATCH FOUND:" -ForegroundColor Green
        $PartialMatch | Select-Object id, name, dnsHostName, address | Format-Table -AutoSize
    }

    # Try dnsHostName match
    $DnsMatch = $AllAssets | Where-Object { $_.dnsHostName -like "*$Hostname*" }
    if ($DnsMatch) {
        Write-Host "  DNS HOSTNAME MATCH FOUND:" -ForegroundColor Green
        $DnsMatch | Select-Object id, name, dnsHostName, address | Format-Table -AutoSize
    }

    if (-not $ExactMatch -and -not $CaseInsensitiveMatch -and -not $PartialMatch -and -not $DnsMatch) {
        Write-Host "  NO MATCHES FOUND in local filtering" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Sample of asset names from Qualys:" -ForegroundColor DarkGray
        $AllAssets | Select-Object -First 10 -ExpandProperty name | ForEach-Object {
            Write-Host "    - $_" -ForegroundColor DarkGray
        }
    }
} else {
    Write-Host "  Failed to retrieve assets" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
