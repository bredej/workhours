# workhours

A PowerShell script that estimates your daily work hours by reading Windows Security event log entries.

## How it works

The script looks at the last 15 days and, for each day, finds:

- **First active use** — earliest logon (event 4624, interactive/RDP) or workstation unlock (event 4801)
- **Last active use** — latest user-initiated logoff (event 4647) or workstation lock (event 4800)

For the current day it uses the current time as the end time.

## Requirements

- Windows with the Security event log enabled
- **Administrator privileges** — the Security event log is not readable by standard users

## Usage

Run PowerShell as Administrator, then:

```powershell
.\workhours.ps1
```

An alternative way to run the script is to create a shortcut with "Run as Administrator" enabled.  
The shortcut target should look something like this:


`powershell.exe -NoExit -ExecutionPolicy Bypass -File "<path>\workhours.ps1"`

*To make this script runs a bit faster try PowerShell 7*

### Example output

```
================================================
Date         Day        Begins  Ends    Duration
================================================
2026-04-06   Monday     08:14   17:32   9h 18m
2026-04-07   Tuesday    07:58   16:45   8h 47m
2026-04-08   Wednesday  ---     ---     ---
...
```

Days without any matching events (weekends, holidays, or days the machine was off) show `---` for all fields.

## Notes

- The duration is wall-clock time from first login to last lock/logoff, not net active time.
- LogonType 2 (interactive), 7 (unlock), and 10 (remote/RDP) are all treated as active use.
- Auditing of logon/logoff events must be enabled in the local security policy for data to be available.
