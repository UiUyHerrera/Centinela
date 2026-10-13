import ctypes
import subprocess

import psutil

from centinela import powershell, registry
from centinela.quarantine import RemediationError

SERVICE_START_TYPES = {"automatic": "auto", "manual": "demand", "disabled": "disabled"}


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def restrict_to_administrators(directory: str) -> None:
    for arguments in (
        ["/setowner", "*S-1-5-32-544", "/T", "/C"],
        ["/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "/T", "/C"],
    ):
        completed = subprocess.run(
            ["icacls", directory, *arguments],
            capture_output=True, text=True, errors="replace", creationflags=powershell.CREATE_NO_WINDOW,
        )
        if completed.returncode != 0:
            raise RemediationError("No se pudo proteger la carpeta de cuarentena")


class WindowsOperations:
    def kill_process_tree(self, pid: int, create_time: float) -> None:
        try:
            root = psutil.Process(pid)
            if root.create_time() != create_time:
                raise RemediationError(f"El PID {pid} ya pertenece a otro proceso")
            processes = [*root.children(recursive=True), root]
        except psutil.NoSuchProcess:
            return
        except psutil.AccessDenied as error:
            raise RemediationError(f"Sin permisos para detener el PID {pid}") from error
        for process in processes:
            try:
                process.terminate()
            except psutil.NoSuchProcess:
                continue
        _, alive = psutil.wait_procs(processes, timeout=5)
        for process in alive:
            try:
                process.kill()
            except psutil.NoSuchProcess:
                continue

    def read_registry_value(self, hive: str, key: str, value: str) -> tuple[object, int]:
        import winreg

        with registry.open_key(hive, key) as handle:
            return winreg.QueryValueEx(handle, value)

    def write_registry_value(self, hive: str, key: str, value: str, data: object, value_type: int) -> None:
        import winreg

        with registry.open_key(hive, key, writable=True) as handle:
            winreg.SetValueEx(handle, value, 0, value_type, data)

    def delete_registry_value(self, hive: str, key: str, value: str) -> None:
        import winreg

        with registry.open_key(hive, key, writable=True) as handle:
            winreg.DeleteValue(handle, value)

    def set_task_enabled(self, task_path: str, task_name: str, enabled: bool) -> None:
        powershell.run_powershell(powershell.SET_TASK_ENABLED, {"task_path": task_path, "task_name": task_name, "enabled": enabled})

    def get_service_start_type(self, name: str) -> str:
        return SERVICE_START_TYPES.get(psutil.win_service_get(name).start_type(), "demand")

    def set_service_start_type(self, name: str, start_type: str) -> None:
        self._run_sc("config", name, "start=", start_type)

    def stop_service(self, name: str) -> None:
        if psutil.win_service_get(name).status() != "stopped":
            self._run_sc("stop", name)

    def remove_defender_exclusion(self, setting: str, value: str) -> None:
        powershell.run_powershell(powershell.CHANGE_DEFENDER_EXCLUSION, {"setting": setting, "value": value, "add": False})

    def add_defender_exclusion(self, setting: str, value: str) -> None:
        powershell.run_powershell(powershell.CHANGE_DEFENDER_EXCLUSION, {"setting": setting, "value": value, "add": True})

    @staticmethod
    def _run_sc(*arguments: str) -> None:
        completed = subprocess.run(
            ["sc.exe", *arguments], capture_output=True, text=True, errors="replace",
            creationflags=powershell.CREATE_NO_WINDOW,
        )
        if completed.returncode != 0:
            raise RemediationError(f"sc.exe {arguments[0]} falló con código {completed.returncode}")
