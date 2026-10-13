from collections.abc import Mapping

from centinela.models import ConnectionSnapshot, Finding, ProcessSnapshot
from centinela.rules import MINING_PORTS
from centinela.scanners.processes import process_target


def analyze_connections(
    connections: list[ConnectionSnapshot],
    processes_by_pid: Mapping[int, ProcessSnapshot],
) -> list[Finding]:
    findings = []
    for connection in connections:
        process = processes_by_pid.get(connection.pid)
        if process and connection.remote_port in MINING_PORTS:
            findings.append(Finding(
                process_target(process),
                f"Conectado a {connection.remote_ip}:{connection.remote_port}, puerto típico de pools de minería",
                50,
            ))
    return findings
