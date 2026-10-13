from collections.abc import Iterator, Mapping

from centinela.models import Finding, ProcessSnapshot, SignatureState, Target, TargetKind
from centinela.paths import normalize, system_path
from centinela.rules import DOCUMENT_AND_BROWSER_APPS, EXPECTED_PARENTS, SCRIPT_HOSTS, SYSTEM_BINARIES
from centinela.scanners.indicators import Reason, command_reasons, file_reasons

HIGH_CPU_PERCENT = 50.0


def process_target(snapshot: ProcessSnapshot) -> Target:
    return Target(
        kind=TargetKind.PROCESS,
        identifier=str(snapshot.pid),
        label=f"{snapshot.name} (PID {snapshot.pid})",
        path=snapshot.exe,
        pid=snapshot.pid,
        files=(snapshot.exe,) if snapshot.exe else (),
        details=(("name", snapshot.name.lower()), ("created", repr(snapshot.create_time))),
    )


def expected_locations(name: str, system_root: str) -> set[str]:
    return {system_path(system_root, folder, name) for folder in SYSTEM_BINARIES.get(name, ())}


def edit_distance(first: str, second: str) -> int:
    rows = [[row + column if row == 0 or column == 0 else 0 for column in range(len(second) + 1)] for row in range(len(first) + 1)]
    for row in range(1, len(first) + 1):
        for column in range(1, len(second) + 1):
            rows[row][column] = min(
                rows[row - 1][column] + 1,
                rows[row][column - 1] + 1,
                rows[row - 1][column - 1] + (first[row - 1] != second[column - 1]),
            )
            if row > 1 and column > 1 and first[row - 1] == second[column - 2] and first[row - 2] == second[column - 1]:
                rows[row][column] = min(rows[row][column], rows[row - 2][column - 2] + 1)
    return rows[-1][-1]


def lookalike_system_name(name: str) -> str | None:
    if name in SYSTEM_BINARIES or len(name) < 7:
        return None
    return next((system_name for system_name in SYSTEM_BINARIES if edit_distance(name, system_name) == 1), None)


def analyze_processes(
    snapshots: list[ProcessSnapshot],
    signatures: Mapping[str, SignatureState],
    system_root: str,
    own_pid: int,
) -> list[Finding]:
    by_pid = {snapshot.pid: snapshot for snapshot in snapshots}
    findings = []
    for snapshot in snapshots:
        if snapshot.pid in (0, 4, own_pid):
            continue
        parent = by_pid.get(snapshot.ppid)
        parent_name = parent.name.lower() if parent and parent.create_time <= snapshot.create_time else None
        target = process_target(snapshot)
        for reason, score in _process_reasons(snapshot, parent_name, signatures, system_root):
            findings.append(Finding(target, reason, score))
    return findings


def _process_reasons(
    snapshot: ProcessSnapshot,
    parent_name: str | None,
    signatures: Mapping[str, SignatureState],
    system_root: str,
) -> Iterator[Reason]:
    name = snapshot.name.lower()
    signature = signatures.get(normalize(snapshot.exe), SignatureState.UNKNOWN) if snapshot.exe else SignatureState.UNKNOWN

    expected = expected_locations(name, system_root)
    if expected and snapshot.exe and normalize(snapshot.exe) not in expected:
        yield f"Se hace pasar por {name} pero corre desde {snapshot.exe}", 90

    lookalike = lookalike_system_name(name)
    if lookalike:
        yield f"Nombre casi idéntico al proceso de sistema {lookalike}", 80

    parents = EXPECTED_PARENTS.get(name)
    if parents and parent_name and parent_name not in parents:
        yield f"{name} fue lanzado por {parent_name}; lo normal es {', '.join(sorted(parents))}", 70

    if name in SCRIPT_HOSTS and parent_name in DOCUMENT_AND_BROWSER_APPS:
        yield f"{parent_name} lanzó {name}, patrón típico de documentos o webs maliciosas", 50

    yield from command_reasons(" ".join(snapshot.cmdline))

    if snapshot.exe and not snapshot.exe_exists:
        yield "El ejecutable se borró del disco después de iniciar", 40
    elif snapshot.exe:
        yield from file_reasons(snapshot.exe, signature)

    if snapshot.cpu_percent >= HIGH_CPU_PERCENT and signature is not SignatureState.VALID:
        yield f"Consume {snapshot.cpu_percent:.0f}% de CPU sin firma válida", 25
