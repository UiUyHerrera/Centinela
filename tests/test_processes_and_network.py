from centinela.models import ConnectionSnapshot, SignatureState
from centinela.scanners.network import analyze_connections
from centinela.scanners.processes import analyze_processes, lookalike_system_name
from tests.factories import SYSTEM_ROOT, process

SVCHOST = r"C:\Windows\System32\svchost.exe"
SERVICES = r"C:\Windows\System32\services.exe"
OWN_PID = 999


def reasons_for(snapshots, signatures=None, pid=None):
    findings = analyze_processes(snapshots, signatures or {}, SYSTEM_ROOT, OWN_PID)
    return [finding.reason for finding in findings if pid is None or finding.target.pid == pid]


def test_genuine_system_process_is_clean():
    snapshots = [
        process(500, "services.exe", SERVICES, create_time=1.0),
        process(800, "svchost.exe", SVCHOST, ppid=500, create_time=2.0),
    ]
    signatures = {SVCHOST.lower(): SignatureState.VALID, SERVICES.lower(): SignatureState.VALID}
    assert reasons_for(snapshots, signatures) == []


def test_impersonated_svchost_outside_system32():
    fake = r"C:\Users\ana\AppData\Roaming\svchost.exe"
    found = reasons_for([process(10, "svchost.exe", fake)], pid=10)
    assert found[0] == f"Se hace pasar por svchost.exe pero corre desde {fake}"


def test_wrong_parent_for_lsass():
    snapshots = [
        process(1, "cmd.exe", r"C:\Windows\System32\cmd.exe", create_time=1.0),
        process(2, "lsass.exe", r"C:\Windows\System32\lsass.exe", ppid=1, create_time=2.0),
    ]
    assert "lsass.exe fue lanzado por cmd.exe; lo normal es wininit.exe" in reasons_for(snapshots, pid=2)


def test_reused_parent_pid_is_ignored():
    snapshots = [
        process(1, "cmd.exe", r"C:\Windows\System32\cmd.exe", create_time=50.0),
        process(2, "lsass.exe", r"C:\Windows\System32\lsass.exe", ppid=1, create_time=2.0),
    ]
    assert reasons_for(snapshots, {r"c:\windows\system32\lsass.exe": SignatureState.VALID}, pid=2) == []


def test_word_spawning_powershell():
    snapshots = [
        process(1, "WINWORD.EXE", r"C:\Program Files\Microsoft Office\WINWORD.EXE", create_time=1.0),
        process(2, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", ppid=1, create_time=2.0),
    ]
    assert "winword.exe lanzó powershell.exe, patrón típico de documentos o webs maliciosas" in reasons_for(snapshots, pid=2)


def test_lookalike_names():
    assert lookalike_system_name("scvhost.exe") == "svchost.exe"
    assert lookalike_system_name("svch0st.exe") == "svchost.exe"
    assert lookalike_system_name("svchost.exe") is None
    assert lookalike_system_name("iexplore.exe") is None


def test_hidden_miner_with_high_cpu_and_deleted_binary():
    miner = process(
        77, "audiodg.exe", r"C:\ProgramData\cache\audiodg.exe",
        cmdline=("audiodg.exe", "-o", "stratum+tcp://xmr.pool:4444"), cpu=92.0, exe_exists=False,
    )
    found = reasons_for([miner], pid=77)
    assert "Argumentos típicos de un minero de criptomonedas" in found
    assert "El ejecutable se borró del disco después de iniciar" in found
    assert "Consume 92% de CPU sin firma válida" in found


def test_own_process_and_system_idle_are_skipped():
    snapshots = [process(OWN_PID, "xmrig.exe", r"C:\x\xmrig.exe"), process(0, "System Idle Process", cpu=99.0)]
    assert reasons_for(snapshots) == []


def test_connection_to_mining_port():
    miner = process(5, "x.exe", r"C:\x.exe")
    findings = analyze_connections(
        [ConnectionSnapshot(5, "1.2.3.4", 3333), ConnectionSnapshot(5, "1.2.3.4", 443), ConnectionSnapshot(6, "1.2.3.4", 3333)],
        {5: miner},
    )
    assert [finding.reason for finding in findings] == ["Conectado a 1.2.3.4:3333, puerto típico de pools de minería"]
    assert findings[0].target.pid == 5
