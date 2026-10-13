import argparse
import os
import sys
from pathlib import Path

from centinela.engine import ScanEngine
from centinela.scoring import aggregate


def quarantine_directory() -> Path:
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Centinela" / "cuarentena"


def print_report(engine: ScanEngine) -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    report = engine.scan(lambda text: print(f"... {text}", file=sys.stderr))
    for threat in aggregate(report.findings):
        print(f"[{threat.severity.value.upper():5}] {threat.score:3}  {threat.target.kind.value:9} {threat.target.label}")
        for reason in threat.reasons:
            print(f"{'':20}- {reason}")
    for error in report.errors:
        print(f"AVISO: {error}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(prog="centinela", description="Analizador de amenazas para Windows")
    parser.add_argument("--report", action="store_true", help="escanea y muestra el informe en la consola")
    arguments = parser.parse_args()
    if sys.platform != "win32":
        parser.exit(1, "Centinela solo funciona en Windows.\n")

    from centinela.collectors import hosts_file_path
    from centinela.quarantine import QuarantineVault
    from centinela.winops import WindowsOperations, is_admin, restrict_to_administrators

    engine = ScanEngine()
    if arguments.report:
        print_report(engine)
        return

    from centinela.ui import run_gui

    admin = is_admin()
    directory = quarantine_directory()
    if admin:
        directory.mkdir(parents=True, exist_ok=True)
        restrict_to_administrators(str(directory.parent))
    vault = QuarantineVault(directory, WindowsOperations(), Path(hosts_file_path()))
    run_gui(engine, vault, admin)


if __name__ == "__main__":
    main()
