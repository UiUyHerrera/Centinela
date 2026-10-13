from dataclasses import dataclass, field
from enum import Enum


class TargetKind(str, Enum):
    PROCESS = "proceso"
    REGISTRY = "registro"
    TASK = "tarea"
    SERVICE = "servicio"
    STARTUP = "inicio"
    WMI = "wmi"
    DEFENDER = "defender"
    HOSTS = "hosts"


class SignatureState(str, Enum):
    VALID = "valida"
    UNSIGNED = "sin firma"
    UNTRUSTED = "no confiable"
    TAMPERED = "alterada"
    UNKNOWN = "desconocida"


class Severity(str, Enum):
    HIGH = "alta"
    MEDIUM = "media"
    LOW = "baja"


@dataclass(frozen=True)
class Target:
    kind: TargetKind
    identifier: str
    label: str
    path: str | None = None
    pid: int | None = None
    files: tuple[str, ...] = ()
    details: tuple[tuple[str, str], ...] = ()

    @property
    def key(self) -> tuple[TargetKind, str]:
        return self.kind, self.identifier.lower()

    def detail(self, name: str) -> str | None:
        return dict(self.details).get(name)


@dataclass(frozen=True)
class Finding:
    target: Target
    reason: str
    score: int


@dataclass
class Threat:
    target: Target
    reasons: list[str]
    score: int

    @property
    def severity(self) -> Severity:
        if self.score >= 70:
            return Severity.HIGH
        if self.score >= 40:
            return Severity.MEDIUM
        return Severity.LOW


@dataclass(frozen=True)
class ProcessSnapshot:
    pid: int
    ppid: int
    name: str
    exe: str | None
    cmdline: tuple[str, ...]
    create_time: float
    cpu_percent: float = 0.0
    exe_exists: bool = True


@dataclass(frozen=True)
class ConnectionSnapshot:
    pid: int
    remote_ip: str
    remote_port: int


@dataclass(frozen=True)
class AutorunEntry:
    target: Target
    command: str
    mechanism: str


@dataclass
class ScanReport:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
