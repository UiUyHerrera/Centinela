import hashlib
import json
import os
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from centinela.remediation import Action, ActionKind

NEUTRALIZE_KEY = b"centinela-cuarentena"
CHUNK_SIZE = len(NEUTRALIZE_KEY) * 65536
REG_SZ = 1


class RemediationError(Exception):
    pass


class SystemOperations(Protocol):
    def kill_process_tree(self, pid: int, create_time: float) -> None: ...
    def read_registry_value(self, hive: str, key: str, value: str) -> tuple[object, int]: ...
    def write_registry_value(self, hive: str, key: str, value: str, data: object, value_type: int) -> None: ...
    def delete_registry_value(self, hive: str, key: str, value: str) -> None: ...
    def set_task_enabled(self, task_path: str, task_name: str, enabled: bool) -> None: ...
    def get_service_start_type(self, name: str) -> str: ...
    def set_service_start_type(self, name: str, start_type: str) -> None: ...
    def stop_service(self, name: str) -> None: ...
    def remove_defender_exclusion(self, setting: str, value: str) -> None: ...
    def add_defender_exclusion(self, setting: str, value: str) -> None: ...


@dataclass
class QuarantineRecord:
    id: str
    created: str
    description: str
    kind: str
    undo: dict | None
    restored: bool = False

    @property
    def restorable(self) -> bool:
        return self.undo is not None and not self.restored


def _xor(chunk: bytes) -> bytes:
    key = (NEUTRALIZE_KEY * (len(chunk) // len(NEUTRALIZE_KEY) + 1))[: len(chunk)]
    return (int.from_bytes(chunk, "big") ^ int.from_bytes(key, "big")).to_bytes(len(chunk), "big")


def _xor_copy(source: Path, destination: Path) -> tuple[str, str]:
    source_hash, destination_hash = hashlib.sha256(), hashlib.sha256()
    with source.open("rb") as reader, destination.open("xb") as writer:
        while chunk := reader.read(CHUNK_SIZE):
            transformed = _xor(chunk)
            source_hash.update(chunk)
            destination_hash.update(transformed)
            writer.write(transformed)
    return source_hash.hexdigest(), destination_hash.hexdigest()


def _encode_registry_data(data: object) -> object:
    return {"hex": data.hex()} if isinstance(data, bytes) else data


def _decode_registry_data(data: object) -> object:
    return bytes.fromhex(data["hex"]) if isinstance(data, dict) else data


class QuarantineVault:
    def __init__(self, root: Path, system: SystemOperations, hosts_path: Path):
        self._root = root
        self._files = root / "files"
        self._manifest = root / "manifest.json"
        self._system = system
        self._hosts_path = hosts_path
        self._lock = threading.Lock()
        self._handlers = {
            ActionKind.KILL_PROCESS: self._kill_process,
            ActionKind.QUARANTINE_FILE: self._quarantine_file,
            ActionKind.DELETE_REGISTRY_VALUE: self._delete_registry_value,
            ActionKind.RESET_REGISTRY_VALUE: self._reset_registry_value,
            ActionKind.DISABLE_TASK: self._disable_task,
            ActionKind.DISABLE_SERVICE: self._disable_service,
            ActionKind.REMOVE_DEFENDER_EXCLUSION: self._remove_defender_exclusion,
            ActionKind.REMOVE_HOSTS_LINE: self._remove_hosts_line,
        }
        self._restorers = {
            ActionKind.QUARANTINE_FILE: self._restore_file,
            ActionKind.DELETE_REGISTRY_VALUE: self._restore_registry_value,
            ActionKind.RESET_REGISTRY_VALUE: self._restore_registry_value,
            ActionKind.DISABLE_TASK: lambda undo: self._system.set_task_enabled(undo["task_path"], undo["task_name"], True),
            ActionKind.DISABLE_SERVICE: lambda undo: self._system.set_service_start_type(undo["name"], undo["start_type"]),
            ActionKind.REMOVE_DEFENDER_EXCLUSION: lambda undo: self._system.add_defender_exclusion(undo["setting"], undo["value"]),
            ActionKind.REMOVE_HOSTS_LINE: self._restore_hosts_line,
        }

    def records(self) -> list[QuarantineRecord]:
        if not self._manifest.exists():
            return []
        raw = json.loads(self._manifest.read_text(encoding="utf-8"))
        return [QuarantineRecord(**item) for item in raw]

    def execute(self, action: Action) -> QuarantineRecord:
        with self._lock:
            undo = self._handlers[action.kind](action)
            record = QuarantineRecord(
                id=uuid.uuid4().hex,
                created=datetime.now().isoformat(timespec="seconds"),
                description=action.description,
                kind=action.kind.value,
                undo=undo,
            )
            self._save([*self.records(), record])
            return record

    def restore(self, record_id: str) -> None:
        with self._lock:
            records = self.records()
            record = next((item for item in records if item.id == record_id), None)
            if record is None or not record.restorable:
                raise RemediationError("Esta acción no se puede deshacer")
            self._restorers[ActionKind(record.kind)](record.undo)
            record.restored = True
            self._save(records)

    def _save(self, records: list[QuarantineRecord]) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        temporary = self._manifest.with_suffix(".tmp")
        temporary.write_text(json.dumps([asdict(record) for record in records], ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary, self._manifest)

    def _kill_process(self, action: Action) -> None:
        pid = int(action.param("pid"))
        if pid in (0, 4, os.getpid()):
            raise RemediationError("Proceso protegido")
        self._system.kill_process_tree(pid, float(action.param("created")))

    def _quarantine_file(self, action: Action) -> dict:
        original = Path(action.param("path"))
        if not original.is_file():
            raise RemediationError(f"El archivo ya no existe: {original}")
        self._files.mkdir(parents=True, exist_ok=True)
        stored = self._files / f"{uuid.uuid4().hex}.bin"
        original_hash, _ = _xor_copy(original, stored)
        try:
            original.unlink()
        except OSError as error:
            stored.unlink(missing_ok=True)
            raise RemediationError(f"No se pudo mover {original}: archivo en uso o sin permisos") from error
        return {"original": str(original), "stored": stored.name, "sha256": original_hash}

    def _restore_file(self, undo: dict) -> None:
        original = Path(undo["original"])
        stored = self._files / undo["stored"]
        if original.exists():
            raise RemediationError(f"Ya existe un archivo en {original}")
        original.parent.mkdir(parents=True, exist_ok=True)
        _, restored_hash = _xor_copy(stored, original)
        if restored_hash != undo["sha256"]:
            original.unlink()
            raise RemediationError("El archivo en cuarentena está dañado")
        stored.unlink()

    def _delete_registry_value(self, action: Action) -> dict:
        hive, key, value = action.param("hive"), action.param("key"), action.param("value")
        data, value_type = self._system.read_registry_value(hive, key, value)
        self._system.delete_registry_value(hive, key, value)
        return {"hive": hive, "key": key, "value": value, "data": _encode_registry_data(data), "type": value_type}

    def _reset_registry_value(self, action: Action) -> dict:
        hive, key, value = action.param("hive"), action.param("key"), action.param("value")
        data, value_type = self._system.read_registry_value(hive, key, value)
        self._system.write_registry_value(hive, key, value, action.param("default"), REG_SZ)
        return {"hive": hive, "key": key, "value": value, "data": _encode_registry_data(data), "type": value_type}

    def _restore_registry_value(self, undo: dict) -> None:
        self._system.write_registry_value(undo["hive"], undo["key"], undo["value"], _decode_registry_data(undo["data"]), undo["type"])

    def _disable_task(self, action: Action) -> dict:
        task_path, task_name = action.param("task_path"), action.param("task_name")
        self._system.set_task_enabled(task_path, task_name, False)
        return {"task_path": task_path, "task_name": task_name}

    def _disable_service(self, action: Action) -> dict:
        name = action.param("name")
        previous = self._system.get_service_start_type(name)
        self._system.stop_service(name)
        self._system.set_service_start_type(name, "disabled")
        return {"name": name, "start_type": previous}

    def _remove_defender_exclusion(self, action: Action) -> dict:
        setting, value = action.param("setting"), action.param("value")
        self._system.remove_defender_exclusion(setting, value)
        return {"setting": setting, "value": value}

    def _remove_hosts_line(self, action: Action) -> dict:
        line = action.param("line")
        lines = self._hosts_path.read_text(encoding="utf-8", errors="surrogateescape").splitlines()
        kept = [current for current in lines if current.strip() != line]
        if len(kept) == len(lines):
            raise RemediationError("La línea ya no está en el archivo hosts")
        self._hosts_path.write_text("\n".join(kept) + "\n", encoding="utf-8", errors="surrogateescape")
        return {"line": line}

    def _restore_hosts_line(self, undo: dict) -> None:
        content = self._hosts_path.read_text(encoding="utf-8", errors="surrogateescape")
        separator = "" if content.endswith("\n") or not content else "\n"
        self._hosts_path.write_text(f"{content}{separator}{undo['line']}\n", encoding="utf-8", errors="surrogateescape")
