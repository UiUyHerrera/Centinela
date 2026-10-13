from dataclasses import dataclass
from enum import Enum

from centinela.models import TargetKind, Threat
from centinela.paths import is_protected_path, normalize
from centinela.rules import CRITICAL_PROCESSES
from centinela.scanners.defender import EXCLUSION_LABELS
from centinela.scanners.persistence import default_winlogon_value
from centinela.scanners.processes import expected_locations


class ActionKind(str, Enum):
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    DELETE_REGISTRY_VALUE = "delete_registry_value"
    RESET_REGISTRY_VALUE = "reset_registry_value"
    DISABLE_TASK = "disable_task"
    DISABLE_SERVICE = "disable_service"
    REMOVE_DEFENDER_EXCLUSION = "remove_defender_exclusion"
    REMOVE_HOSTS_LINE = "remove_hosts_line"


@dataclass(frozen=True)
class Action:
    kind: ActionKind
    description: str
    params: tuple[tuple[str, str], ...]

    def param(self, name: str) -> str:
        return dict(self.params)[name]


def plan_remediation(threat: Threat, system_root: str) -> list[Action]:
    target = threat.target
    actions: list[Action] = []

    if target.kind is TargetKind.PROCESS and target.pid is not None:
        name = target.detail("name") or ""
        genuine_critical = (
            name in CRITICAL_PROCESSES
            and target.path is not None
            and normalize(target.path) in expected_locations(name, system_root)
        )
        if not genuine_critical:
            actions.append(Action(ActionKind.KILL_PROCESS, f"Detener {target.label} y sus procesos hijos", (
                ("pid", str(target.pid)), ("created", target.detail("created") or "0.0"),
            )))

    elif target.kind is TargetKind.REGISTRY:
        registry = (("hive", target.detail("hive")), ("key", target.detail("key")), ("value", target.detail("value")))
        default = default_winlogon_value(target.detail("mechanism") or "", system_root)
        if default is None:
            actions.append(Action(ActionKind.DELETE_REGISTRY_VALUE, f"Borrar del registro {target.label}", registry))
        else:
            actions.append(Action(ActionKind.RESET_REGISTRY_VALUE, f"Restablecer {target.label} a {default}", (*registry, ("default", default))))

    elif target.kind is TargetKind.TASK:
        actions.append(Action(ActionKind.DISABLE_TASK, f"Desactivar la tarea {target.label}", (
            ("task_path", target.detail("task_path")), ("task_name", target.detail("task_name")),
        )))

    elif target.kind is TargetKind.SERVICE:
        actions.append(Action(ActionKind.DISABLE_SERVICE, f"Detener y desactivar el servicio {target.label}", (("name", target.identifier),)))

    elif target.kind is TargetKind.DEFENDER and target.detail("setting") in EXCLUSION_LABELS:
        actions.append(Action(ActionKind.REMOVE_DEFENDER_EXCLUSION, f"Quitar de Defender: {target.label}", (
            ("setting", target.detail("setting")), ("value", target.detail("value")),
        )))

    elif target.kind is TargetKind.HOSTS:
        actions.append(Action(ActionKind.REMOVE_HOSTS_LINE, f"Quitar del archivo hosts: {target.detail('line')}", (("line", target.detail("line")),)))

    candidate_files = [target.path] if target.kind is TargetKind.STARTUP and target.path else []
    candidate_files.extend(target.files)
    planned: set[str] = set()
    for path in candidate_files:
        if normalize(path) in planned or is_protected_path(path, system_root):
            continue
        planned.add(normalize(path))
        actions.append(Action(ActionKind.QUARANTINE_FILE, f"Mover a cuarentena {path}", (("path", path),)))

    return actions
