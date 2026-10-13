from collections.abc import Mapping

from centinela.models import Finding, ProcessSnapshot
from centinela.rules import MONITOR_PROCESSES
from centinela.scanners.processes import process_target

Samples = Mapping[int, ProcessSnapshot]


class EvasionDetector:
    def __init__(self, busy_percent: float = 20.0, quiet_percent: float = 2.0, window_ticks: int = 3):
        self._busy_percent = busy_percent
        self._quiet_percent = quiet_percent
        self._window_ticks = window_ticks
        self._previous: Samples = {}
        self._monitor_open = False
        self._suspects: dict[int, ProcessSnapshot] = {}
        self._ticks_left = 0

    def feed(self, samples: Samples) -> list[Finding]:
        monitor_open = any(sample.name.lower() in MONITOR_PROCESSES for sample in samples.values())
        if monitor_open and not self._monitor_open:
            self._suspects = {
                pid: sample for pid, sample in self._previous.items()
                if sample.cpu_percent >= self._busy_percent and sample.name.lower() not in MONITOR_PROCESSES
            }
            self._ticks_left = self._window_ticks
        self._monitor_open = monitor_open
        self._previous = samples
        return self._check_suspects(samples)

    def _check_suspects(self, samples: Samples) -> list[Finding]:
        if self._ticks_left <= 0:
            return []
        self._ticks_left -= 1
        findings = []
        for pid, before in list(self._suspects.items()):
            now = samples.get(pid)
            if now is None:
                reason = f"Se cerró justo al abrir el monitor de procesos (usaba {before.cpu_percent:.0f}% de CPU)"
            elif now.cpu_percent <= self._quiet_percent:
                reason = f"Bajó de {before.cpu_percent:.0f}% a {now.cpu_percent:.0f}% de CPU al abrir el monitor de procesos"
            else:
                continue
            findings.append(Finding(process_target(before), reason, 80))
            del self._suspects[pid]
        return findings


class SustainedLoadDetector:
    def __init__(self, busy_percent: float = 50.0, required_ticks: int = 30):
        self._busy_percent = busy_percent
        self._required_ticks = required_ticks
        self._streaks: dict[int, int] = {}

    def feed(self, samples: Samples) -> list[Finding]:
        findings = []
        streaks = {}
        for pid, sample in samples.items():
            if sample.cpu_percent < self._busy_percent or sample.name.lower() in MONITOR_PROCESSES:
                continue
            streaks[pid] = self._streaks.get(pid, 0) + 1
            if streaks[pid] == self._required_ticks:
                findings.append(Finding(
                    process_target(sample),
                    f"CPU sostenida sobre {self._busy_percent:.0f}% durante {self._required_ticks} muestras seguidas",
                    20,
                ))
        self._streaks = streaks
        return findings
