from collections.abc import Callable, Iterator, Mapping

from centinela.models import AutorunEntry, Finding, SignatureState
from centinela.paths import normalize, referenced_files, system_path
from centinela.scanners.indicators import Reason, command_reasons, file_reasons

MECHANISM_REASONS = {
    "ifeo": ("Secuestra la ejecución de otro programa mediante un depurador (IFEO)", 60),
    "wmi": ("Suscripción WMI que ejecuta comandos de forma invisible", 70),
    "startup_script": ("Script ejecutable en la carpeta de Inicio", 40),
}


def default_winlogon_value(mechanism: str, system_root: str) -> str | None:
    if mechanism == "winlogon_shell":
        return "explorer.exe"
    if mechanism == "winlogon_userinit":
        return system_path(system_root, "system32", "userinit.exe") + ","
    return None


def analyze_autoruns(
    entries: list[AutorunEntry],
    signatures: Mapping[str, SignatureState],
    file_exists: Callable[[str], bool],
    system_root: str,
) -> list[Finding]:
    findings = []
    for entry in entries:
        for reason, score in _autorun_reasons(entry, signatures, file_exists, system_root):
            findings.append(Finding(entry.target, reason, score))
    return findings


def _autorun_reasons(
    entry: AutorunEntry,
    signatures: Mapping[str, SignatureState],
    file_exists: Callable[[str], bool],
    system_root: str,
) -> Iterator[Reason]:
    default = default_winlogon_value(entry.mechanism, system_root)
    if default is not None:
        if normalize(entry.command).rstrip(",") != normalize(default).rstrip(","):
            yield f"Valor de Winlogon modificado: se esperaba {default}", 80
        else:
            return

    if entry.mechanism in MECHANISM_REASONS:
        yield MECHANISM_REASONS[entry.mechanism]

    files_trusted = bool(entry.target.files) and all(
        signatures.get(normalize(path)) is SignatureState.VALID for path in entry.target.files
    )
    if entry.target.detail("hidden") == "true" and not files_trusted:
        yield "Tarea programada marcada como oculta", 20

    yield from command_reasons(entry.command)

    for path in entry.target.files:
        if not file_exists(path):
            yield f"Apunta a un archivo que no existe: {path}", 10
            continue
        yield from file_reasons(path, signatures.get(normalize(path), SignatureState.UNKNOWN))


def files_for_command(command: str) -> tuple[str, ...]:
    return tuple(referenced_files(command))
