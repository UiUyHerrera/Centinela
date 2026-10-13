import glob
import ntpath
import os
import time
import psutil

from centinela import powershell, registry
from centinela.models import AutorunEntry, ConnectionSnapshot, ProcessSnapshot, SignatureState, Target, TargetKind
from centinela.paths import normalize
from centinela.rules import WMI_EXECUTING_CONSUMERS
from centinela.scanners.persistence import files_for_command

RUN_KEYS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
)
WINLOGON_KEY = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
IFEO_KEY = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
STARTUP_SCRIPT_EXTENSIONS = (".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".ps1", ".scr", ".hta")
SIGNATURE_BATCH_SIZE = 200
SIGNATURE_STATES = {
    "Valid": SignatureState.VALID,
    "NotSigned": SignatureState.UNSIGNED,
    "NotTrusted": SignatureState.UNTRUSTED,
    "HashMismatch": SignatureState.TAMPERED,
}


def collect_processes(sample_seconds: float = 1.0) -> list[ProcessSnapshot]:
    processes = list(psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "create_time"]))
    for process in processes:
        try:
            process.cpu_percent(None)
        except psutil.Error:
            pass
    time.sleep(sample_seconds)
    return [snapshot for process in processes if (snapshot := _snapshot(process)) is not None]


def _snapshot(process: psutil.Process) -> ProcessSnapshot | None:
    try:
        cpu = process.cpu_percent(None) / (psutil.cpu_count() or 1)
    except psutil.NoSuchProcess:
        return None
    except psutil.Error:
        cpu = 0.0
    info = process.info
    exe = info.get("exe") or None
    return ProcessSnapshot(
        pid=info["pid"],
        ppid=info.get("ppid") or 0,
        name=info.get("name") or "",
        exe=exe,
        cmdline=tuple(info.get("cmdline") or ()),
        create_time=info.get("create_time") or 0.0,
        cpu_percent=cpu,
        exe_exists=os.path.exists(exe) if exe else True,
    )


class ProcessSampler:
    def __init__(self):
        self._processes: dict[int, psutil.Process] = {}

    def sample(self) -> dict[int, ProcessSnapshot]:
        current = {}
        for process in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "create_time"]):
            known = self._processes.get(process.pid)
            if known is None or known.info.get("create_time") != process.info.get("create_time"):
                known = process
                try:
                    known.cpu_percent(None)
                except psutil.Error:
                    continue
            current[process.pid] = known
        self._processes = current
        return {pid: snapshot for pid, process in current.items() if (snapshot := _snapshot(process)) is not None}


def collect_connections() -> list[ConnectionSnapshot]:
    return [
        ConnectionSnapshot(connection.pid, connection.raddr.ip, connection.raddr.port)
        for connection in psutil.net_connections(kind="inet")
        if connection.raddr and connection.pid
    ]


def collect_signatures(paths: list[str]) -> dict[str, SignatureState]:
    states = {}
    for start in range(0, len(paths), SIGNATURE_BATCH_SIZE):
        for item in powershell.run_powershell(powershell.SIGNATURES, paths[start:start + SIGNATURE_BATCH_SIZE]):
            states[normalize(item["path"])] = SIGNATURE_STATES.get(item.get("status"), SignatureState.UNKNOWN)
    return states


def _registry_target(hive: str, key: str, value: str, command: str, mechanism: str) -> Target:
    return Target(
        kind=TargetKind.REGISTRY,
        identifier=f"{hive}\\{key}\\{value}",
        label=f"{hive}\\{key} → {value}",
        files=files_for_command(command),
        details=(("hive", hive), ("key", key), ("value", value), ("mechanism", mechanism)),
    )


def _user_hives() -> list[str]:
    return [f"HKU\\{sid}" for sid in registry.subkeys("HKU", "") if not sid.endswith("_Classes")]


def collect_registry_autoruns() -> list[AutorunEntry]:
    entries = []
    for hive in ["HKLM", *_user_hives()]:
        for key in RUN_KEYS:
            for name, command in registry.string_values(hive, key):
                entries.append(AutorunEntry(_registry_target(hive, key, name, command, "run"), command, "run"))
    for name, command in registry.string_values("HKLM", WINLOGON_KEY):
        if name.lower() in ("shell", "userinit"):
            mechanism = f"winlogon_{name.lower()}"
            entries.append(AutorunEntry(_registry_target("HKLM", WINLOGON_KEY, name, command, mechanism), command, mechanism))
    for image in registry.subkeys("HKLM", IFEO_KEY):
        key = f"{IFEO_KEY}\\{image}"
        for name, command in registry.string_values("HKLM", key):
            if name.lower() == "debugger":
                entries.append(AutorunEntry(_registry_target("HKLM", key, name, command, "ifeo"), command, "ifeo"))
    return entries


def startup_folders() -> list[str]:
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    system_drive = os.environ.get("SystemDrive", "C:")
    folders = [ntpath.join(program_data, r"Microsoft\Windows\Start Menu\Programs\StartUp")]
    folders += glob.glob(ntpath.join(system_drive + "\\", "Users", "*", r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"))
    return folders


def collect_startup_entries() -> list[AutorunEntry]:
    files = [entry.path for folder in startup_folders() if os.path.isdir(folder) for entry in os.scandir(folder) if entry.is_file()]
    shortcuts = [path for path in files if path.lower().endswith(".lnk")]
    commands = {normalize(item["path"]): item["command"] for item in powershell.run_powershell(powershell.SHORTCUT_TARGETS, shortcuts)} if shortcuts else {}
    entries = []
    for path in files:
        is_script = path.lower().endswith(STARTUP_SCRIPT_EXTENSIONS)
        if not is_script and normalize(path) not in commands:
            continue
        command = f'"{path}"' if is_script else commands[normalize(path)]
        target = Target(TargetKind.STARTUP, path, f"Inicio: {ntpath.basename(path)}", path=path, files=files_for_command(command))
        entries.append(AutorunEntry(target, command, "startup_script" if is_script else "startup"))
    return entries


def collect_scheduled_tasks() -> list[AutorunEntry]:
    entries = []
    for item in powershell.run_powershell(powershell.SCHEDULED_TASKS):
        command = f'"{item["execute"]}" {item["arguments"]}'.strip()
        full_name = f"{item['task_path']}{item['task_name']}"
        target = Target(
            TargetKind.TASK,
            full_name,
            full_name,
            files=files_for_command(command),
            details=(("task_path", item["task_path"]), ("task_name", item["task_name"]), ("hidden", str(item["hidden"]).lower())),
        )
        entries.append(AutorunEntry(target, command, "task"))
    return entries


def collect_services() -> list[AutorunEntry]:
    entries = []
    for service in psutil.win_service_iter():
        try:
            info = service.as_dict()
        except psutil.Error:
            continue
        command = info.get("binpath") or ""
        target = Target(
            TargetKind.SERVICE,
            info["name"],
            f"{info.get('display_name') or info['name']} ({info['name']})",
            files=files_for_command(command),
        )
        entries.append(AutorunEntry(target, command, "service"))
    return entries


def collect_wmi_consumers() -> list[AutorunEntry]:
    entries = []
    for item in powershell.run_powershell(powershell.WMI_CONSUMERS):
        if item["type"] not in WMI_EXECUTING_CONSUMERS:
            continue
        target = Target(TargetKind.WMI, f"{item['type']}:{item['name']}", f"WMI {item['type']}: {item['name']}", files=files_for_command(item["command"]))
        entries.append(AutorunEntry(target, item["command"], "wmi"))
    return entries


def collect_defender_settings() -> list[tuple[str, str]]:
    return [
        (item["setting"], item["value"])
        for item in powershell.run_powershell(powershell.DEFENDER_SETTINGS)
        if not item["value"].startswith("N/A")
    ]


def hosts_file_path() -> str:
    return ntpath.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\drivers\etc\hosts")


def collect_hosts_lines() -> list[str]:
    with open(hosts_file_path(), encoding="utf-8", errors="replace") as hosts:
        return hosts.read().splitlines()
