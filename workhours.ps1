# Get first login and last logout per day for the last 5 days
# Requires access to the Security event log

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "This script requires administrator privileges to read the Security event log."
    Write-Host "Re-run PowerShell as Administrator and execute the script again." -ForegroundColor Yellow
    exit 1
}

$daysToShow = 15
$startDate = (Get-Date).Date.AddDays(-($daysToShow - 1))

# Event IDs:
#   4624 = Successful logon (LogonType 2=Interactive, 10=RemoteInteractive/RDP)
#   4801 = Workstation unlocked (user returns to locked screen)
#   4634 = Logoff (noisy — fires for all sessions, not used)
#   4647 = User-initiated logoff
#   4800 = Workstation locked (user leaves)

# We consider LogonType 2, 7 and 10 as active use.
$logonTypes = @(2, 7, 10)

Write-Host "Fetching event log entries since $($startDate.ToString('yyyy-MM-dd'))..." -ForegroundColor Cyan

# Use XPath filter to efficiently query logon events with specific LogonTypes and time range
$startDateStr = $startDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$logonTypeFilter = ($logonTypes | ForEach-Object { "EventData[Data[@Name='LogonType']='$_']" }) -join ' or '

# Combined XPath: 4801 (unlock) OR 4624 with matching LogonType
$xpathFilter = "*[(System[EventID=4801 and TimeCreated[@SystemTime>='$startDateStr']]) or " +
               "(System[EventID=4624 and TimeCreated[@SystemTime>='$startDateStr']] and ($logonTypeFilter))]"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$loginEvents = Get-WinEvent -FilterXPath $xpathFilter -LogName 'Security' `
    -ErrorAction SilentlyContinue | Select-Object TimeCreated
$sw.Stop()
Write-Host "Login query:  $($sw.ElapsedMilliseconds) ms" -ForegroundColor DarkGray

# Combined query: 4647 (user logoff) + 4800 (workstation locked)
$sw.Restart()
$logoutEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = @(4647, 4800)
    StartTime = $startDate
} -ErrorAction SilentlyContinue | Select-Object TimeCreated
$sw.Stop()
Write-Host "Logout query: $($sw.ElapsedMilliseconds) ms" -ForegroundColor DarkGray

# Group events by date and find the first active use per day
$loginsByDay = $loginEvents |
    Group-Object { $_.TimeCreated.Date.ToString('yyyy-MM-dd') } |
    ForEach-Object {
        [PSCustomObject]@{
            Date       = $_.Name
            FirstUse   = ($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
        }
    }

# Group logouts by date and find the last per day
$logoutsByDay = $logoutEvents |
    Group-Object { $_.TimeCreated.Date.ToString('yyyy-MM-dd') } |
    ForEach-Object {
        [PSCustomObject]@{
            Date        = $_.Name
            LastLogout  = ($_.Group | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated
        }
    }

# Merge and display results
$days = 0..($daysToShow - 1) | ForEach-Object { (Get-Date).Date.AddDays(-$_) } | Sort-Object

Write-Host ""
Write-Host ("=" * 57)
Write-Host ("{0,-12} {1,-10} {2,-7} {3,-7} {4,-9} {5,-9}" -f "Date", "Day", "Begins", "Ends", "Duration", "Hours")
Write-Host ("=" * 57)

foreach ($day in $days) {
    $dayKey = $day.ToString('yyyy-MM-dd')
    $login  = ($loginsByDay  | Where-Object { $_.Date -eq $dayKey }).FirstUse
    $logout = ($logoutsByDay | Where-Object { $_.Date -eq $dayKey }).LastLogout
    if ($day.Date -eq (Get-Date).Date -and $login) { $logout = Get-Date }

    $loginStr  = if ($login)  { $login.ToString("HH:mm")  } else { "---" }
    $logoutStr = if ($logout) { $logout.ToString("HH:mm") } else { "---" }

    $durationStr = if ($login -and $logout -and $logout -gt $login) {
        $span = $logout - $login
        "{0}h {1:D2}m" -f [math]::Floor($span.TotalHours), $span.Minutes
    } else { "---" }

    # Subtract 30 minutes for lunch break
    $hoursStr = if ($login -and $logout -and $logout -gt $login) {
        $span = ($logout - $login) - [TimeSpan]::FromMinutes(30)
        if ($span.TotalMinutes -gt 0) {
            "{0}h {1:D2}m" -f [math]::Floor($span.TotalHours), $span.Minutes
        } else { "0h 00m" }
    } else { "---" }

    $dayOfWeek = $day.ToString("dddd")
    Write-Host ("{0,-12} {1,-10} {2,-7} {3,-7} {4,-9} {5,-9}" -f $day.ToString("yyyy-MM-dd"), $dayOfWeek, $loginStr, $logoutStr, $durationStr, $hoursStr)
}

Write-Host ("=" * 57)
