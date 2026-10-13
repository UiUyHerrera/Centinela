import ntpath
import re

from centinela.rules import EXECUTABLE_EXTENSIONS, USER_WRITABLE_MARKERS

_REFERENCED_FILE = re.compile(
    r"([a-z]:\\[^\"<>|*?\r\n]*?\.(?:" + "|".join(EXECUTABLE_EXTENSIONS) + r"))(?=$|[\s\",])",
    re.IGNORECASE,
)


def normalize(path: str) -> str:
    return path.strip().strip('"').replace("/", "\\").lower()


def basename(path: str) -> str:
    return ntpath.basename(normalize(path))


def is_user_writable(path: str) -> bool:
    normalized = normalize(path)
    return any(marker in normalized for marker in USER_WRITABLE_MARKERS)


def system_path(system_root: str, *parts: str) -> str:
    return normalize(ntpath.join(system_root, *[part for part in parts if part]))


def is_protected_path(path: str, system_root: str) -> bool:
    normalized = normalize(path)
    protected_dirs = (system_path(system_root, "system32") + "\\", system_path(system_root, "syswow64") + "\\")
    return normalized.startswith(protected_dirs) or normalized == system_path(system_root, "explorer.exe")


def expand_environment(command: str) -> str:
    return ntpath.expandvars(command.replace("\\SystemRoot\\", "%SystemRoot%\\"))


def referenced_files(command: str) -> list[str]:
    expanded = expand_environment(command)
    seen: list[str] = []
    for match in _REFERENCED_FILE.finditer(expanded):
        candidate = match.group(1)
        if normalize(candidate) not in (normalize(path) for path in seen):
            seen.append(candidate)
    return seen
