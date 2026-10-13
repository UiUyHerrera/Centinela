from collections.abc import Iterator

from centinela.models import SignatureState
from centinela.paths import basename, is_user_writable
from centinela.rules import DECOY_EXTENSIONS, MINER_COMMAND_PATTERNS, MINER_NAMES, SCRIPT_ABUSE_PATTERNS

Reason = tuple[str, int]

SIGNATURE_REASONS = {
    SignatureState.TAMPERED: ("Firma digital alterada: el archivo fue modificado", 60),
    SignatureState.UNTRUSTED: ("Firma digital no confiable", 30),
    SignatureState.UNSIGNED: ("Sin firma digital", 15),
}


def command_reasons(command: str) -> Iterator[Reason]:
    if any(pattern.search(command) for pattern in MINER_COMMAND_PATTERNS):
        yield "Argumentos típicos de un minero de criptomonedas", 90
    for pattern, description in SCRIPT_ABUSE_PATTERNS:
        if pattern.search(command):
            yield description, 50


def file_reasons(path: str, signature: SignatureState) -> Iterator[Reason]:
    name = basename(path)
    stem = name.rpartition(".")[0]
    if stem in MINER_NAMES:
        yield f"Nombre de minero conocido: {name}", 90
    if "." in stem and stem.rpartition(".")[2] in DECOY_EXTENSIONS:
        yield f"Extensión doble para engañar: {name}", 50
    if signature in SIGNATURE_REASONS:
        yield SIGNATURE_REASONS[signature]
    if signature is not SignatureState.VALID and is_user_writable(path):
        yield "Ejecutable sin firma válida en carpeta de usuario o temporal", 30
