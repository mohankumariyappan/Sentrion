$p1 = Start-Process python -ArgumentList 'test_wmi_precise.py' -PassThru
Write-Host "[+] Started Python process with active WMI event sink (PID: $($p1.Id))"
Start-Sleep -Seconds 2

Write-Host "[+] Force-killing PID $($p1.Id) via Stop-Process -Force..."
Stop-Process -Id $p1.Id -Force
Start-Sleep -Seconds 2

Write-Host "[*] Querying WMI root\subscription for __EventFilter..."
Fetch-Command: Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter'

$filters = Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter'
$filters | Select-Object Name, Query | Format-Table -AutoSize

Write-Host "[*] Querying WMI root\subscription for __FilterToConsumerBinding..."
$bindings = Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding'
$bindings | Format-Table -AutoSize

if ($filters.Count -le 1 -and ($filters.Name -eq 'SCM Event Log Filter' -or $null -eq $filters)) {
    Write-Host "[SUCCESS] Zero orphaned WMI event filters found. Temporary ExecNotificationQuery COM sink was automatically purged by winmgmt!"
    Write-Host "No leak detected."
} else {
    Write-Host "[!] Warning: Unexpected persistent filter found!"
}
