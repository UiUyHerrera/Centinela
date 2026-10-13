import os
import threading
import time
from collections.abc import Callable

from centinela import collectors
from centinela.models import AutorunEntry, Finding, ScanReport
from centinela.paths import normalize
from centinela.scanners.defender import analyze_defender
from centinela.scanners.hosts import analyze_hosts
from centinela.scanners.network import analyze_connections
from centinela.scanners.persistence import analyze_autoruns
from centinela.scanners.processes import analyze_processes
from centinela.watch import EvasionDetector, SustainedLoadDetector

Progress = Callable[[str], None]

AUTORUN_SOURCES = (
    ("registro (Run, Winlogon, IFEO)", collectors.collect_registry_autoruns),
    ("carpetas de Inicio", collectors.collect_startup_entries),
    ("tareas programadas", collectors.collect_scheduled_tasks),
    ("servicios", collectors.collect_services),
    ("suscripciones WMI", collectors.collect_wmi_consumers),
)


def system_root() -> str:
    return os.environ.get("SystemRoot", r"C:\Windows")


class ScanEngine:
    def scan(self, progress: Progress) -> ScanReport:
        started = time.monotonic()
        report = ScanReport()

        progress("Midiendo procesos en ejecución")
        processes = self._attempt(report, "procesos", collectors.collect_processes) or []

        autoruns: list[AutorunEntry] = []
        for label, collect in AUTORUN_SOURCES:
            progress(f"Revisando {label}")
            autoruns.extend(self._attempt(report, label, collect) or [])

        progress("Verificando firmas digitales")
        paths = sorted({normalize(path) for path in self._paths_to_verify(processes, autoruns)})
        signatures = self._attempt(report, "firmas digitales", lambda: collectors.collect_signatures(paths)) or {}

        progress("Analizando conexiones de red")
        connections = self._attempt(report, "conexiones de red", collectors.collect_connections) or []

        progress("Revisando Windows Defender")
        defender = self._attempt(report, "Windows Defender", collectors.collect_defender_settings) or []

        progress("Revisando archivo hosts")
        hosts = self._attempt(report, "archivo hosts", collectors.collect_hosts_lines) or []

        root = system_root()
        report.findings = [
            *analyze_processes(processes, signatures, root, os.getpid()),
            *analyze_connections(connections, {process.pid: process for process in processes}),
            *analyze_autoruns(autoruns, signatures, os.path.exists, root),
            *analyze_defender(defender),
            *analyze_hosts(hosts),
        ]
        report.duration_seconds = time.monotonic() - started
        return report

    @staticmethod
    def _paths_to_verify(processes, autoruns) -> list[str]:
        paths = [process.exe for process in processes if process.exe and process.exe_exists]
        paths += [path for entry in autoruns for path in entry.target.files if os.path.exists(path)]
        return paths

    @staticmethod
    def _attempt(report: ScanReport, label: str, action):
        try:
            return action()
        except Exception as error:
            report.errors.append(f"No se pudo revisar {label}: {error}")
            return None

    @staticmethod
    def watch(stop: threading.Event, on_findings: Callable[[list[Finding]], None], interval: float = 1.0) -> None:
        sampler = collectors.ProcessSampler()
        detectors = (EvasionDetector(), SustainedLoadDetector())
        sampler.sample()
        while not stop.wait(interval):
            samples = sampler.sample()
            findings = [finding for detector in detectors for finding in detector.feed(samples)]
            if findings:
                on_findings(findings)
