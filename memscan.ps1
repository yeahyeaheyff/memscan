# memscan.ps1 - Scans process memory for known cheat/executor name strings.
# Read-only: never writes to or injects into any process.
# Run as Administrator. By default scans Roblox only; keep Roblox open while running.
# Usage:
#   irm .../memscan.ps1 | iex                    # scans Roblox processes
#   & { irm .../memscan.ps1 } | iex -AllProcs     # see note below for passing args

param(
    [switch]$AllProcs,   # scan every process's memory (slow, noisy)
    [switch]$WeakWords    # also search for the common/short words
)

$ErrorActionPreference = 'SilentlyContinue'

$Strong = @('xeno','matcha','severe','cosmic','crime.cc','crimecc','serotonin','photon','solara')
$Weak   = @('dx9','real','drift','cleaner','universal')

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host "WARNING: not running as Administrator. Memory reads will fail for most processes." -ForegroundColor Yellow }

Add-Type -Namespace Native -Name Mem -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
[DllImport("kernel32.dll")] public static extern int VirtualQueryEx(IntPtr h, IntPtr addr, out MEMORY_BASIC_INFORMATION mbi, int size);
[DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buffer, int size, out IntPtr read);

[StructLayout(LayoutKind.Sequential)]
public struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public IntPtr RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
}
'@

$PROCESS_QUERY_INFORMATION = 0x0400
$PROCESS_VM_READ = 0x0010
$MEM_COMMIT = 0x1000
$PAGE_NOACCESS = 0x01
$PAGE_GUARD = 0x100
$CHUNK = 4MB

function Get-WordVariants([string]$word, [bool]$bounded) {
    $asciiBytes = [Text.Encoding]::ASCII.GetBytes($word.ToLower())
    $uniBytes   = [Text.Encoding]::Unicode.GetBytes($word.ToLower())
    , $asciiBytes, $uniBytes
}

function Test-IsWordChar([byte]$b) {
    ($b -ge 48 -and $b -le 57) -or ($b -ge 65 -and $b -le 90) -or ($b -ge 97 -and $b -le 122)
}

function Find-Pattern([byte[]]$data, [byte[]]$pattern, [bool]$bounded) {
    $hits = New-Object System.Collections.Generic.List[int]
    $n = $data.Length; $m = $pattern.Length
    if ($m -eq 0 -or $n -lt $m) { return $hits }
    for ($i = 0; $i -le $n - $m; $i++) {
        $match = $true
        for ($j = 0; $j -lt $m; $j++) {
            $db = $data[$i + $j]
            if ($db -ge 65 -and $db -le 90) { $db += 32 }  # lowercase
            if ($db -ne $pattern[$j]) { $match = $false; break }
        }
        if ($match) {
            if ($bounded) {
                $beforeOk = ($i -eq 0) -or -not (Test-IsWordChar $data[$i - 1])
                $afterOk  = ($i + $m -ge $n) -or -not (Test-IsWordChar $data[$i + $m])
                if (-not ($beforeOk -and $afterOk)) { continue }
            }
            $hits.Add($i)
        }
    }
    return $hits
}

function ConvertTo-Printable([byte[]]$data, [int]$start, [int]$len) {
    $s = $start; if ($s -lt 0) { $s = 0 }
    $e = [Math]::Min($data.Length, $start + $len)
    $sb = New-Object Text.StringBuilder
    for ($i = $s; $i -lt $e; $i++) {
        $b = $data[$i]
        if ($b -eq 0) { continue }
        if ($b -ge 32 -and $b -le 126) { [void]$sb.Append([char]$b) } else { [void]$sb.Append('.') }
    }
    $sb.ToString()
}

function Search-ProcessMemory($proc, $patterns) {
    $h = [Native.Mem]::OpenProcess($PROCESS_QUERY_INFORMATION -bor $PROCESS_VM_READ, $false, $proc.Id)
    if ($h -eq [IntPtr]::Zero) { return }
    $found = @{}
    try {
        $addr = [IntPtr]::Zero
        $mbi = New-Object Native.Mem+MEMORY_BASIC_INFORMATION
        $mbiSize = [Runtime.InteropServices.Marshal]::SizeOf($mbi)
        while ([Native.Mem]::VirtualQueryEx($h, $addr, [ref]$mbi, $mbiSize) -ne 0) {
            $base = [int64]$mbi.BaseAddress
            $size = [int64]$mbi.RegionSize
            if ($size -le 0) { break }
            $readable = ($mbi.State -eq $MEM_COMMIT) -and (($mbi.Protect -band $PAGE_NOACCESS) -eq 0) -and (($mbi.Protect -band $PAGE_GUARD) -eq 0)
            if ($readable) {
                $off = 0
                while ($off -lt $size) {
                    $n = [Math]::Min($CHUNK, $size - $off)
                    $buf = New-Object byte[] $n
                    $readPtr = [IntPtr]::Zero
                    $readAddr = [IntPtr]($base + $off)
                    if ([Native.Mem]::ReadProcessMemory($h, $readAddr, $buf, $n, [ref]$readPtr)) {
                        $got = [int64]$readPtr
                        if ($got -gt 0) {
                            $data = if ($got -eq $buf.Length) { $buf } else { $buf[0..($got - 1)] }
                            foreach ($p in $patterns) {
                                $hits = Find-Pattern $data $p.Bytes $p.Bounded
                                foreach ($hi in $hits) {
                                    $ctx = ConvertTo-Printable $data ($hi - 40) 140
                                    $key = $p.Name
                                    if (-not $found.ContainsKey($key)) { $found[$key] = @{Count=0; Samples=New-Object System.Collections.Generic.List[string]} }
                                    $found[$key].Count++
                                    if ($found[$key].Samples.Count -lt 3) { $found[$key].Samples.Add($ctx) }
                                }
                            }
                        }
                    }
                    $off += $n
                }
            }
            $base2 = $base + $size
            if ($base2 -ge 0x7FFFFFFFFFFF -or $base2 -le $base) { break }
            $addr = [IntPtr]$base2
        }
    } finally {
        [Native.Mem]::CloseHandle($h) | Out-Null
    }
    return $found
}

# Build patterns
$patterns = @()
foreach ($w in $Strong) {
    $a, $u = Get-WordVariants $w $false
    $patterns += [pscustomobject]@{ Name = $w; Bytes = $a; Bounded = $false }
    $patterns += [pscustomobject]@{ Name = $w; Bytes = $u; Bounded = $false }
}
if ($WeakWords) {
    foreach ($w in $Weak) {
        $a, $u = Get-WordVariants $w $true
        $patterns += [pscustomobject]@{ Name = $w; Bytes = $a; Bounded = $true }
        $patterns += [pscustomobject]@{ Name = $w; Bytes = $u; Bounded = $true }
    }
}

Write-Host "=== Process memory string scan ===" -ForegroundColor Cyan
$targets = if ($AllProcs) {
    Get-Process | Where-Object { $_.Id -ne $PID -and $_.Id -gt 4 }
} else {
    Get-Process | Where-Object { $_.ProcessName -match 'roblox' }
}

if (-not $targets) {
    Write-Host "No matching processes running. (Default mode only scans Roblox - make sure it's open.)" -ForegroundColor Yellow
}

$anyHit = $false
foreach ($p in $targets) {
    Write-Host "  scanning $($p.ProcessName) (PID $($p.Id)) ..."
    $res = Search-ProcessMemory $p $patterns
    foreach ($key in $res.Keys) {
        $anyHit = $true
        $info = $res[$key]
        Write-Host "[HIGH] MEMORY STRING: $($p.ProcessName) (PID $($p.Id)) '$key' x$($info.Count)" -ForegroundColor Red
        foreach ($s in $info.Samples) {
            Write-Host "        ...$s..." -ForegroundColor DarkGray
        }
    }
}
if (-not $anyHit -and $targets) { Write-Host "  No matches found in scanned process memory." -ForegroundColor Green }

Write-Host "`nDone."
