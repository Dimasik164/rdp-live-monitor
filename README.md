# RDP Live Monitor

A small Windows desktop tool for watching live RDP sessions, recent RDP events, and Windows Firewall blacklist rules.

The project started as a practical Windows Server hardening helper: quickly see who is connected over RDP, inspect recent reconnect/disconnect events, and block suspicious addresses without opening multiple admin consoles.

## Features

- Shows current RDP sessions from `query session`.
- Shows active TCP connections on local port `3389`.
- Shows recent RDP logon, reconnect, and disconnect events.
- Displays firewall blacklist entries created by the tool.
- Blocks or unblocks:
  - single IP addresses, for example `109.205.211.17`
  - CIDR subnets, for example `109.205.211.0/24`
  - IP ranges, for example `109.205.211.1-109.205.211.50`
- Clears local RDP event history from the UI.
- Includes a custom embedded icon.
- Built with PowerShell and WinForms, compiled to `.exe` with PS2EXE.

## Screenshots

Add screenshots here after uploading images to the repository, for example:

```md
![RDP Live Monitor](docs/screenshot.png)
```

## Download

The compiled executable is included in:

```text
dist/RdpLiveMonitor.exe
```

For best results, run it as Administrator. Firewall rule changes and event log cleanup require elevated permissions.

## Usage

1. Start `RdpLiveMonitor.exe`.
2. Review the current session summary at the top.
3. Check active `3389` connections and recent RDP events.
4. Select or type an address in the input field.
5. Use `Add Blacklist` or `Remove IP`.

Supported blacklist input formats:

```text
109.205.211.17
109.205.211.0/24
109.205.211.1-109.205.211.50
```

## Build

The source script is in:

```text
src/RdpLiveMonitor.ps1
```

This project was compiled with PS2EXE:

```powershell
Invoke-ps2exe `
  -inputFile .\src\RdpLiveMonitor.ps1 `
  -outputFile .\dist\RdpLiveMonitor.exe `
  -noConsole `
  -STA `
  -iconFile .\assets\RdpLiveMonitor.ico `
  -title 'RDP Live Monitor' `
  -description 'RDP monitor with blacklist controls'
```

## Notes

- The tool creates Windows Firewall rules named `Blacklist_<address>_IN` and `Blacklist_<address>_OUT`.
- It reads Terminal Services event logs for recent RDP activity.
- It is intended for defensive administration on systems you own or manage.

## License

MIT
