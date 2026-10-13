from collections.abc import Iterator

from centinela.models import Finding, Target, TargetKind
from centinela.paths import is_user_writable, normalize
from centinela.rules import RISKY_EXCLUSION_EXTENSIONS
from centinela.scanners.indicators import Reason

EXCLUSION_LABELS = {"path": "ruta", "process": "proceso", "extension": "extensión"}


def defender_target(kind: str, value: str) -> Target:
    label = f"Exclusión de {EXCLUSION_LABELS[kind]}: {value}" if kind in EXCLUSION_LABELS else f"Defender: {kind}"
    return Target(
        kind=TargetKind.DEFENDER,
        identifier=f"{kind}:{value}",
        label=label,
        details=(("setting", kind), ("value", value)),
    )


def analyze_defender(settings: list[tuple[str, str]]) -> list[Finding]:
    findings = []
    for kind, value in settings:
        for reason, score in _setting_reasons(kind, value):
            findings.append(Finding(defender_target(kind, value), reason, score))
    return findings


def _setting_reasons(kind: str, value: str) -> Iterator[Reason]:
    if kind == "path":
        normalized = normalize(value).rstrip("\\")
        if len(normalized) <= 2 or is_user_writable(normalized + "\\"):
            yield "Defender ignora una carpeta donde suele esconderse malware", 70
        else:
            yield "Defender tiene una carpeta excluida del análisis", 40
    elif kind == "process":
        yield "Defender ignora todo lo que haga este proceso", 50
    elif kind == "extension":
        extension = value.lower().lstrip("*").lstrip(".")
        if extension in RISKY_EXCLUSION_EXTENSIONS:
            yield f"Defender ignora todos los archivos .{extension}", 70
        else:
            yield "Defender tiene una extensión excluida del análisis", 40
    elif kind == "realtime" and value.lower() == "false":
        yield "La protección en tiempo real de Defender está apagada", 40
    elif kind == "tamper" and value.lower() == "false":
        yield "La protección contra alteraciones de Defender está apagada", 15
