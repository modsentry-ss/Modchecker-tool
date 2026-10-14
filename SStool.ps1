# ModSentry PowerShell companion — read-only local triage tool.
# Review this source before running it. It does not upload files or telemetry.
[CmdletBinding()]
param(
    [string]$ScanPath,
    [switch]$PcCheck,
    [switch]$WatchUsb
)
$ErrorActionPreference = 'SilentlyContinue'
$script:ReviewHashes = @{
 '0cc162bfaf5c17474f2ed5cc82591f101bf4b72bad26ba45e4e6736e604aa9d8' = 'VulkanMod-0.6.8+1.21.11.jar — verification required'
 'e436081e02fd23a7fc2ef85f5261b43b9097e73ce73d71be557341b3af788eb9' = 'voicechat-fabric-1.21.11-2.6.23.jar — verification required'
 '34ccdacf13bb9351fe43ce61912c2e09b72364e43e787d36ba3d2d04dec75a52' = 'fabric-language-kotlin-1.13.13+kotlin.2.4.10.jar — verification required'
}
$script:StrongPatterns = @(
 @{Name='Process injection APIs'; Pattern='WriteProcessMemory|CreateRemoteThread|NtWriteVirtualMemory|QueueUserAPC|VirtualAllocEx'; Weight=35},
 @{Name='Java agent / attach'; Pattern='java/lang/instrument/Instrumentation|com/sun/tools/attach/VirtualMachine|loadAgent|javaagent'; Weight=25},
 @{Name='Combat automation'; Pattern='KillAura|AimAssist|TriggerBot|AutoClicker|ClickAura|AutoTotem|ReachHack|Scaffold'; Weight=16},
 @{Name='Freecam / X-ray / ESP'; Pattern='FreeCam|FreeCamera|X.?Ray|OreESP|EntityESP|HealthIndicator|PlayerESP'; Weight=14},
 @{Name='Input simulation'; Pattern='SendInput|mouse_event|keybd_event|GetAsyncKeyState|java/awt/Robot'; Weight=10},
 @{Name='Memory classloader / payload'; Pattern='defineClass.{0,100}(getResourceAsStream|Base64|JarInputStream)|JarInputStream.{0,100}defineClass'; Weight=18}
)
$script:WeakPatterns = @(
 @{Name='JNI / native dependency (weak)'; Pattern='\.dll|\.so|sun/misc/Unsafe|com/sun/jna/'; Weight=1},
 @{Name='Obfuscator marker (weak)'; Pattern='Allatori|Zelix|Skidfuscator|ProGuard|Radon'; Weight=2}
)
function Get-Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Get-TextFromFile([string]$Path) {
    $chunks = [System.Collections.Generic.List[string]]::new()
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($ext -in @('.jar','.zip','.litemod')) {
        try {
            Add-Type -AssemblyName System.IO.Compression
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [IO.Compression.ZipFile]::OpenRead($Path)
            try {
                foreach ($entry in $zip.Entries) {
                    if ($entry.Length -gt 12MB -or $entry.Length -eq 0) { continue }
                    if ($entry.FullName -match '\.(class|json|mf|toml|cfg|properties|txt|xml)$') {
                        $stream = $entry.Open(); $ms = [IO.MemoryStream]::new()
                        try { $stream.CopyTo($ms); $bytes = $ms.ToArray(); $chunks.Add([Text.Encoding]::UTF8.GetString($bytes)); $chunks.Add([Text.Encoding]::ASCII.GetString($bytes)) }
                        finally { $stream.Dispose(); $ms.Dispose() }
                    } elseif ($entry.FullName -match '\.(dll|so|dylib)$') { $chunks.Add('native dependency ' + $entry.FullName) }
                }
            } finally { $zip.Dispose() }
        } catch { $chunks.Add('ARCHIVE_READ_ERROR: ' + $_.Exception.Message) }
    } else {
        try { $bytes = [IO.File]::ReadAllBytes($Path); $chunks.Add([Text.Encoding]::ASCII.GetString($bytes)) } catch {}
    }
    return ($chunks -join "`n")
}
function Invoke-ModScan([string]$Path) {
    $files = @()
    if (Test-Path -LiteralPath $Path -PathType Leaf) { $files = @(Get-Item -LiteralPath $Path) }
    elseif (Test-Path -LiteralPath $Path -PathType Container) { $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension.ToLowerInvariant() -in @('.jar','.zip','.litemod','.exe','.dll','.class') }) }
    else { Write-Host "Path not found: $Path" -ForegroundColor Red; return }
    $results = foreach ($file in $files) {
        Write-Progress -Activity 'ModSentry scan' -Status $file.FullName -PercentComplete 0
        $hash = Get-Hash $file.FullName
        $score = 0; $findings = [System.Collections.Generic.List[string]]::new(); $text = Get-TextFromFile $file.FullName
        foreach ($rule in $script:StrongPatterns) { if ($text -match $rule.Pattern) { $score += $rule.Weight; $findings.Add("+$($rule.Weight) $($rule.Name)") } }
        foreach ($rule in $script:WeakPatterns) { if ($text -match $rule.Pattern) { $score += $rule.Weight; $findings.Add("+$($rule.Weight) $($rule.Name)") } }
        if ($file.Name -match '(?i)free.?cam|x.?ray|killaura|aim.?assist|autototem|autoclicker|reachhack|cheatclient') { $score += 5; $findings.Add('+5 suspicious filename (weak)') }
        $score = [Math]::Min(100,$score)
        $verdict = if ($script:ReviewHashes.ContainsKey($hash)) { 'REVIEW — verification required' } elseif ($score -ge 55) { 'SUSPICIOUS — manual review' } elseif ($score -ge 20) { 'REVIEW' } else { 'No strong indicators found' }
        if ($script:ReviewHashes.ContainsKey($hash)) { $findings.Add($script:ReviewHashes[$hash]); $score = [Math]::Min(39,$score) }
        [pscustomobject]@{ Verdict=$verdict; Score=$score; File=$file.FullName; SHA256=$hash; Bytes=$file.Length; Findings=($findings -join '; ') }
    }
    Write-Progress -Activity 'ModSentry scan' -Completed
    $results | Format-Table Verdict,Score,File -AutoSize -Wrap
    $out = Join-Path (Get-Location) ('ModSentry-report-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.csv')
    $results | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $out
    Write-Host "`nReport saved: $out" -ForegroundColor Cyan
    Write-Host 'A low score is not proof of legitimacy; heuristics may miss renamed/obfuscated cheats.' -ForegroundColor Yellow
}
function Invoke-PCCheck {
    Write-Host "`n=== ModSentry PC Check (read-only) ===" -ForegroundColor Cyan
    Write-Host "`n[1] PowerShell/injector command-line indicators"
    $rx = '(?i)(-enc(odedcommand)?\b|frombase64string|downloadstring|invoke-expression|Add-Type|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtWriteVirtualMemory|QueueUserAPC|javaagent|agentlib|jdwp=|instrumentation)'
    $hits = Get-CimInstance Win32_Process | Where-Object { ($_.Name -match '(?i)powershell|pwsh|java|python|rundll32|regsvr32|wscript|cscript') -and (($_.CommandLine -as [string]) -match $rx) } | Select-Object ProcessId,ParentProcessId,Name,CommandLine
    if ($hits) { $hits | Format-List } else { Write-Host 'No command-line indicators matched (not proof of absence).' }
    Write-Host "`n[2] Windows memory-integrity posture"
    try { $dg = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard; "VBS status: $($dg.VirtualizationBasedSecurityStatus) (2=enabled/running)"; "Configured security services: $($dg.SecurityServicesConfigured -join ',')"; "Running security services: $($dg.SecurityServicesRunning -join ',')" } catch { Write-Host 'Device Guard status unavailable.' }
    Write-Host 'Note: this checks Windows security posture and process indicators; it does not certify all process/kernel memory.'
    Write-Host "`n[3] Boot/system disk health"
    try { $letter=$env:SystemDrive.TrimEnd(':'); Get-Partition -DriveLetter $letter | Get-Disk | Select-Object Number,FriendlyName,BusType,OperationalStatus,HealthStatus,IsBoot,IsSystem,PartitionStyle,Size | Format-List } catch { Write-Host "System disk query unavailable: $_" }
    try { Get-PhysicalDisk | Select-Object FriendlyName,MediaType,BusType,OperationalStatus,HealthStatus,Usage,Size | Format-Table -AutoSize } catch { Write-Host 'Physical disk health unavailable.' }
    try { "SecureBoot: $(Confirm-SecureBootUEFI -ErrorAction Stop)" } catch { Write-Host 'Secure Boot status unavailable (legacy BIOS/platform limitation).' }
    Write-Host "`n[4] Windows services and approximate start times"
    $services = Get-CimInstance Win32_Service
    $stopped = @($services | Where-Object State -eq 'Stopped')
    Write-Host "Stopped services: $($stopped.Count) (many are normally stopped; inventory only)"
    $stopped | Select-Object -First 40 Name,StartMode,DisplayName | Format-Table -AutoSize
    Write-Host 'Running service process creation times (approximate, not exact service start times):'
    $rows = foreach ($svc in ($services | Where-Object { $_.State -eq 'Running' -and $_.ProcessId -gt 0 } | Select-Object -First 100)) { $proc=Get-CimInstance Win32_Process -Filter "ProcessId=$($svc.ProcessId)"; if ($proc) { [pscustomobject]@{Service=$svc.Name;PID=$svc.ProcessId;ProcessStarted=$proc.CreationDate;StartMode=$svc.StartMode} } }
    $rows | Format-Table -AutoSize
    Write-Host "`n[5] USB devices"
    Get-PnpDevice -Class USB | Select-Object Status,FriendlyName,InstanceId | Format-Table -AutoSize -Wrap
    Write-Host "`nPrivacy: this script does not upload files, paths, process lists or reports. Results are local only." -ForegroundColor Green
}
function Watch-USB {
    Write-Host 'Watching USB device inventory for removals. Press Ctrl+C to stop.' -ForegroundColor Cyan
    $previous = @{}; Get-PnpDevice -Class USB | ForEach-Object { $previous[$_.InstanceId]=$_.FriendlyName }
    while ($true) {
        Start-Sleep -Seconds 2
        $current = @{}; Get-PnpDevice -Class USB | ForEach-Object { $current[$_.InstanceId]=$_.FriendlyName }
        foreach ($id in @($previous.Keys)) { if (-not $current.ContainsKey($id)) { $stamp=Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $msg="$stamp USB device disappeared: $($previous[$id]) [$id]"; Write-Warning $msg; Add-Content -LiteralPath (Join-Path $HOME 'ModSentry_USB_Alerts.log') -Value $msg } }
        $previous = $current
    }
}
if ($PcCheck) { Invoke-PCCheck; return }
if ($WatchUsb) { Watch-USB; return }
if ($ScanPath) { Invoke-ModScan $ScanPath; return }
while ($true) {
    Clear-Host
    Write-Host 'ModSentry PowerShell' -ForegroundColor Cyan
    Write-Host '1. PC Check (process indicators, memory-integrity posture, boot disk, services, USB inventory)'
    Write-Host '2. Scan a JAR/mod/file/folder'
    Write-Host '3. Watch USB removals (Ctrl+C to stop)'
    Write-Host '4. Exit'
    $choice = Read-Host 'Choose an option'
    switch ($choice) {
        '1' { Invoke-PCCheck; Read-Host 'Press Enter to return' | Out-Null }
        '2' { $path = Read-Host 'Path to a JAR, file or folder'; if ($path) { Invoke-ModScan $path }; Read-Host 'Press Enter to return' | Out-Null }
        '3' { Watch-USB }
        '4' { return }
        default { Write-Host 'Choose 1, 2, 3 or 4'; Start-Sleep -Seconds 1 }
    }
}
