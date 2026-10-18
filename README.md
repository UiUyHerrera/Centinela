# Centinela

A threat analyzer for Windows. It checks processes, network connections, persistence, Windows Defender and the `hosts` file, groups what it finds by program and gives each one a score. Anything suspicious can be sent to quarantine and restored later.

I built it with crypto miners in mind, and the everyday malware that sets itself up to start with Windows.

![Centinela with a report: a miner disguised as svchost, a Run key with hidden PowerShell and a Defender exclusion](docs/centinela.png)

<sub>The screenshot uses demo data, not a real scan. The interface is in Spanish.</sub>

## What it checks

- **Processes**: system binaries running from user folders, parents that don't fit (an `svchost.exe` not started by `services.exe`, or PowerShell opened by Word or the browser), miner names and arguments, and abuse of PowerShell or other script hosts.
- **Network**: connections to ports used by mining pools.
- **Persistence**: the Run, Winlogon and IFEO registry keys, Startup folders, scheduled tasks, services and WMI subscriptions. Each executable's signature is checked with PowerShell.
- **Defender**: real-time or tamper protection turned off, and excluded folders, processes or extensions.
- **hosts**: Microsoft, antivirus or GitHub domains redirected somewhere else.
- **Watch mode**: some miners stop when you open Task Manager. Centinela measures CPU before and after a process monitor opens and flags the ones that quit or suddenly go quiet.

Every finding adds points along with its reason, and the total sets the program's severity. That way the report shows a few entries with the why behind each one, instead of a long list of loose alerts.

## Using it

It needs Windows and Python 3.11 or newer.

```bash
pip install -e .[dev]
centinela             # graphical interface
centinela --report    # report in the console
```

Run it as administrator to check services, other users' tasks and the quarantine. The quarantine lives in `%ProgramData%\Centinela\cuarentena` and keeps what it needs to restore each file or registry value.

## Executable

```bash
python build.py
```

Builds `dist/Centinela.exe` with PyInstaller. GitHub Actions runs the tests and builds the executable on Windows on every push.

## Tests

```bash
python -m pytest
```

The scanners take already-collected data, so the tests use factories of fake processes, connections and startup entries and never touch the real system.
