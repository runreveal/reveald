# Windows Event Log Collection with Reveald

This guide covers setting up reveald to collect Windows event logs and ship them to RunReveal.

## Prerequisites

- Windows Server 2019+ or Windows 10+
- Administrator access
- A RunReveal workspace with a reveald webhook source

## 1. Install Sysmon

Sysmon provides detailed system telemetry that goes well beyond the built-in
Windows event logs. It captures process creation with full command lines, network
connections tied to processes, DNS queries, file and registry changes, and more.

Download and install Sysmon with the
[sysmon-modular](https://github.com/olafhartong/sysmon-modular) config:

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon" -Force

# Download sysmon-modular config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -OutFile "$env:TEMP\Sysmon\sysmonconfig.xml"

# Install
& "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i "$env:TEMP\Sysmon\sysmonconfig.xml"
```

Verify it's running:

```powershell
Get-Service Sysmon64
```

## 2. Enable Windows Audit Policies

These policies enable the built-in Windows security events that complement Sysmon.

```powershell
# Process tracking
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable

# Logon/Logoff
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

# Object access
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable

# Privilege use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# Account management
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# Policy change
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable

# System events
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

# Include command line in process creation events (4688)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

## 3. Enable PowerShell Logging

```powershell
# Module logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name EnableModuleLogging -Value 1
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*"

# Script block logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1
```

## 4. Increase Event Log Sizes

The defaults are too small for meaningful retention:

```powershell
wevtutil sl Security /ms:1073741824                                # 1 GB
wevtutil sl System /ms:268435456                                   # 256 MB
wevtutil sl Application /ms:268435456                              # 256 MB
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824  # 1 GB
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:268435456  # 256 MB
wevtutil sl "Windows PowerShell" /ms:268435456                     # 256 MB
```

## 5. Install Reveald

Download the latest Windows release from the
[releases page](https://github.com/runreveal/reveald/releases):

```powershell
# Create install directory
New-Item -Path "C:\reveald" -ItemType Directory -Force | Out-Null

# Download and extract (replace VERSION with the latest release)
Invoke-WebRequest -Uri "https://github.com/runreveal/reveald/releases/download/VERSION/reveald-windows-amd64.zip" -OutFile "$env:TEMP\reveald.zip"
Expand-Archive -Path "$env:TEMP\reveald.zip" -DestinationPath "C:\reveald" -Force
```

## 6. Configure Reveald

Create `C:\reveald\config.json`. See
[config_windows.json](config_windows.json) for a full example.

Replace `{{YOUR_WEBHOOK_URL}}` with your RunReveal reveald source webhook URL:

```json
{
  "sources": {
    "sysmon": {
      "type": "eventlog",
      "channel": "Microsoft-Windows-Sysmon/Operational",
      "query": "*"
    },
    "security": {
      "type": "eventlog",
      "channel": "Security",
      "query": "*"
    },
    "system": {
      "type": "eventlog",
      "channel": "System",
      "query": "*"
    },
    "powershell": {
      "type": "eventlog",
      "channel": "Microsoft-Windows-PowerShell/Operational",
      "query": "*"
    },
    "powershell_classic": {
      "type": "eventlog",
      "channel": "Windows PowerShell",
      "query": "*"
    }
  },
  "destinations": {
    "runreveal": {
      "type": "runreveal",
      "webhookURL": "YOUR_WEBHOOK_URL",
      "batchSize": 100,
      "flushFreq": "10s"
    }
  }
}
```

The `query` field accepts XPath 1.0 expressions if you want to filter events at
the source. For example, to collect only interactive logon events:

```
*[EventData[Data[@Name='LogonType']='2'] and System[(EventID=4624)]]
```

## 7. Test

Verify the config works before installing as a service:

```powershell
C:\reveald\reveald.exe run --config C:\reveald\config.json
```

You should see log output indicating each event log channel is configured and
events should start appearing in your RunReveal workspace within seconds.

## 8. Install as a Windows Service

Reveald implements the Windows Service Control Manager (SCM) protocol natively
and can be registered directly with `sc.exe`:

```powershell
sc.exe create reveald binPath= "C:\reveald\reveald.exe run --config C:\reveald\config.json" start= auto DisplayName= "RunReveal reveald"
sc.exe description reveald "RunReveal log collection agent"
sc.exe failure reveald reset= 60 actions= restart/5000/restart/10000/restart/30000

Start-Service reveald
```

Verify it's running:

```powershell
Get-Service reveald
```

## What You Get

| Source | Key Events |
|--------|-----------|
| Sysmon | Process creation with command lines and parent chains, network connections tied to processes, DNS queries, file/registry changes, DLL loads, named pipes, WMI activity |
| Security | Logon/logoff (4624/4634), process creation (4688) with command lines, privilege use, account and group changes, audit policy changes |
| System | Service installs, driver loads, system errors |
| PowerShell | Script block execution, module loading |

## Troubleshooting

Check the Windows System event log for service start/stop errors:

```powershell
Get-WinEvent -LogName System -FilterXPath "*[System[Provider[@Name='Service Control Manager'] and EventData[Data='reveald']]]" -MaxEvents 10
```

Verify Sysmon is generating events:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

Restart the service after config changes:

```powershell
Restart-Service reveald
```
