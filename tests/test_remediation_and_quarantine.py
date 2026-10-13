import pytest

from centinela.models import Target, TargetKind, Threat
from centinela.quarantine import NEUTRALIZE_KEY, QuarantineVault, RemediationError
from centinela.remediation import Action, ActionKind, plan_remediation
from tests.factories import SYSTEM_ROOT


class FakeSystem:
    def __init__(self):
        self.registry = {("HKLM", "Run", "evil"): ("C:\\evil.exe", 1)}
        self.killed = []
        self.tasks = {}
        self.services = {"EvilSvc": "auto"}
        self.exclusions = {("path", "C:\\")}

    def kill_process_tree(self, pid, create_time):
        self.killed.append((pid, create_time))

    def read_registry_value(self, hive, key, value):
        return self.registry[(hive, key, value)]

    def write_registry_value(self, hive, key, value, data, value_type):
        self.registry[(hive, key, value)] = (data, value_type)

    def delete_registry_value(self, hive, key, value):
        del self.registry[(hive, key, value)]

    def set_task_enabled(self, task_path, task_name, enabled):
        self.tasks[(task_path, task_name)] = enabled

    def get_service_start_type(self, name):
        return self.services[name]

    def set_service_start_type(self, name, start_type):
        self.services[name] = start_type

    def stop_service(self, name):
        pass

    def remove_defender_exclusion(self, setting, value):
        self.exclusions.remove((setting, value))

    def add_defender_exclusion(self, setting, value):
        self.exclusions.add((setting, value))


@pytest.fixture
def system():
    return FakeSystem()


@pytest.fixture
def hosts(tmp_path):
    path = tmp_path / "hosts"
    path.write_text("127.0.0.1 localhost\n0.0.0.0 virustotal.com\n", encoding="utf-8")
    return path


@pytest.fixture
def vault(tmp_path, system, hosts):
    return QuarantineVault(tmp_path / "vault", system, hosts)


def action(kind, **params):
    return Action(kind, "prueba", tuple(params.items()))


def threat(target):
    return Threat(target, ["motivo"], 90)


def test_plan_for_fake_process_kills_and_quarantines(tmp_path):
    target = Target(TargetKind.PROCESS, "10", "svchost.exe (PID 10)", path=r"C:\Users\Public\svchost.exe", pid=10,
                    files=(r"C:\Users\Public\svchost.exe",), details=(("name", "svchost.exe"), ("created", "12.5")))
    kinds = [(planned.kind, dict(planned.params)) for planned in plan_remediation(threat(target), SYSTEM_ROOT)]
    assert kinds == [
        (ActionKind.KILL_PROCESS, {"pid": "10", "created": "12.5"}),
        (ActionKind.QUARANTINE_FILE, {"path": r"C:\Users\Public\svchost.exe"}),
    ]


def test_plan_never_kills_genuine_critical_process_nor_touches_system32():
    target = Target(TargetKind.PROCESS, "600", "lsass.exe (PID 600)", path=r"C:\Windows\System32\lsass.exe", pid=600,
                    files=(r"C:\Windows\System32\lsass.exe",), details=(("name", "lsass.exe"),))
    assert plan_remediation(threat(target), SYSTEM_ROOT) == []


def test_plan_resets_winlogon_instead_of_deleting():
    target = Target(TargetKind.REGISTRY, "x", "Userinit", details=(
        ("hive", "HKLM"), ("key", "Winlogon"), ("value", "Userinit"), ("mechanism", "winlogon_userinit")))
    planned = plan_remediation(threat(target), SYSTEM_ROOT)
    assert planned[0].kind is ActionKind.RESET_REGISTRY_VALUE
    assert planned[0].param("default") == r"c:\windows\system32\userinit.exe,"


def test_plan_for_wmi_requires_manual_review():
    assert plan_remediation(threat(Target(TargetKind.WMI, "x", "wmi")), SYSTEM_ROOT) == []


def test_quarantine_file_neutralizes_and_restores(vault, tmp_path):
    original = tmp_path / "evil.exe"
    content = b"MZ" + bytes(range(256)) * 50
    original.write_bytes(content)

    record = vault.execute(action(ActionKind.QUARANTINE_FILE, path=str(original)))
    assert not original.exists()
    stored = (tmp_path / "vault" / "files" / record.undo["stored"]).read_bytes()
    assert stored != content and len(stored) == len(content)
    assert not stored.startswith(b"MZ")

    vault.restore(record.id)
    assert original.read_bytes() == content
    assert vault.records()[0].restored
    with pytest.raises(RemediationError):
        vault.restore(record.id)


def test_quarantine_handles_files_larger_than_one_chunk(vault, tmp_path):
    original = tmp_path / "big.bin"
    content = bytes(range(256)) * (len(NEUTRALIZE_KEY) * 600)
    original.write_bytes(content)
    record = vault.execute(action(ActionKind.QUARANTINE_FILE, path=str(original)))
    vault.restore(record.id)
    assert original.read_bytes() == content


def test_restore_refuses_to_overwrite_and_detects_corruption(vault, tmp_path):
    original = tmp_path / "evil.exe"
    original.write_bytes(b"payload")
    record = vault.execute(action(ActionKind.QUARANTINE_FILE, path=str(original)))
    original.write_bytes(b"nuevo")
    with pytest.raises(RemediationError):
        vault.restore(record.id)
    assert original.read_bytes() == b"nuevo"

    original.unlink()
    (tmp_path / "vault" / "files" / record.undo["stored"]).write_bytes(b"xxxxxxx")
    with pytest.raises(RemediationError):
        vault.restore(record.id)
    assert not original.exists()


def test_missing_file_fails_without_record(vault, tmp_path):
    with pytest.raises(RemediationError):
        vault.execute(action(ActionKind.QUARANTINE_FILE, path=str(tmp_path / "nada.exe")))
    assert vault.records() == []


def test_registry_delete_and_restore(vault, system):
    record = vault.execute(action(ActionKind.DELETE_REGISTRY_VALUE, hive="HKLM", key="Run", value="evil"))
    assert ("HKLM", "Run", "evil") not in system.registry
    vault.restore(record.id)
    assert system.registry[("HKLM", "Run", "evil")] == ("C:\\evil.exe", 1)


def test_binary_registry_values_survive_the_manifest(tmp_path, system, hosts):
    system.registry[("HKLM", "Run", "blob")] = (b"\x00\xff", 3)
    vault = QuarantineVault(tmp_path / "vault", system, hosts)
    record = vault.execute(action(ActionKind.DELETE_REGISTRY_VALUE, hive="HKLM", key="Run", value="blob"))
    QuarantineVault(tmp_path / "vault", system, hosts).restore(record.id)
    assert system.registry[("HKLM", "Run", "blob")] == (b"\x00\xff", 3)


def test_service_task_and_defender_round_trip(vault, system):
    service = vault.execute(action(ActionKind.DISABLE_SERVICE, name="EvilSvc"))
    task = vault.execute(action(ActionKind.DISABLE_TASK, task_path="\\", task_name="Updater"))
    exclusion = vault.execute(action(ActionKind.REMOVE_DEFENDER_EXCLUSION, setting="path", value="C:\\"))
    assert system.services["EvilSvc"] == "disabled"
    assert system.tasks[("\\", "Updater")] is False
    assert system.exclusions == set()
    for record in (service, task, exclusion):
        vault.restore(record.id)
    assert system.services["EvilSvc"] == "auto"
    assert system.tasks[("\\", "Updater")] is True
    assert system.exclusions == {("path", "C:\\")}


def test_hosts_line_removed_and_restored(vault, hosts):
    record = vault.execute(action(ActionKind.REMOVE_HOSTS_LINE, line="0.0.0.0 virustotal.com"))
    assert hosts.read_text(encoding="utf-8") == "127.0.0.1 localhost\n"
    with pytest.raises(RemediationError):
        vault.execute(action(ActionKind.REMOVE_HOSTS_LINE, line="0.0.0.0 virustotal.com"))
    vault.restore(record.id)
    assert hosts.read_text(encoding="utf-8") == "127.0.0.1 localhost\n0.0.0.0 virustotal.com\n"


def test_kill_is_recorded_but_not_restorable(vault, system):
    record = vault.execute(action(ActionKind.KILL_PROCESS, pid="321", created="5.0"))
    assert system.killed == [(321, 5.0)]
    assert not record.restorable
    with pytest.raises(RemediationError):
        vault.execute(action(ActionKind.KILL_PROCESS, pid="4", created="0.0"))
