from centinela.models import AutorunEntry, ProcessSnapshot, Target, TargetKind
from centinela.scanners.persistence import files_for_command

SYSTEM_ROOT = r"C:\Windows"


def process(pid, name, exe=None, ppid=1, cmdline=(), create_time=100.0, cpu=0.0, exe_exists=True):
    return ProcessSnapshot(pid, ppid, name, exe, tuple(cmdline), create_time, cpu, exe_exists)


def autorun(command, mechanism="run", kind=TargetKind.REGISTRY, details=()):
    target = Target(kind, f"entry:{command}", "entrada", files=files_for_command(command), details=tuple(details))
    return AutorunEntry(target, command, mechanism)
