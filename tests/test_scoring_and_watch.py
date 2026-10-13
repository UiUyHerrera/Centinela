from centinela.models import Finding, Severity, Target, TargetKind
from centinela.scoring import aggregate
from centinela.watch import EvasionDetector, SustainedLoadDetector
from tests.factories import process


def target(identifier):
    return Target(TargetKind.PROCESS, identifier, identifier)


def test_aggregate_merges_by_target_dedups_and_caps():
    findings = [
        Finding(target("1"), "a", 60),
        Finding(target("1"), "a", 60),
        Finding(target("1"), "b", 70),
        Finding(target("2"), "c", 15),
    ]
    threats = aggregate(findings)
    assert [(threat.target.identifier, threat.reasons, threat.score) for threat in threats] == [
        ("1", ["a", "b"], 100),
        ("2", ["c"], 15),
    ]
    assert threats[0].severity is Severity.HIGH
    assert threats[1].severity is Severity.LOW


def test_evasion_detector_catches_process_that_stops_when_task_manager_opens():
    detector = EvasionDetector()
    miner = process(10, "helper.exe", r"C:\x\helper.exe", cpu=85.0)
    quitter = process(11, "other.exe", r"C:\x\other.exe", cpu=40.0)
    honest = process(12, "game.exe", r"C:\x\game.exe", cpu=70.0)
    assert detector.feed({10: miner, 11: quitter, 12: honest}) == []

    task_manager = process(20, "Taskmgr.exe", cpu=3.0)
    findings = detector.feed({10: process(10, "helper.exe", r"C:\x\helper.exe", cpu=0.5), 12: honest, 20: task_manager})
    assert sorted((finding.target.pid, finding.score) for finding in findings) == [(10, 80), (11, 80)]
    assert detector.feed({10: miner, 12: honest, 20: task_manager}) == []


def test_evasion_detector_window_expires():
    detector = EvasionDetector(window_ticks=1)
    busy = process(10, "x.exe", cpu=50.0)
    detector.feed({10: busy})
    task_manager = process(20, "taskmgr.exe")
    assert detector.feed({10: busy, 20: task_manager}) == []
    assert detector.feed({20: task_manager}) == []


def test_sustained_load_reports_once_per_streak():
    detector = SustainedLoadDetector(busy_percent=50.0, required_ticks=3)
    busy = {1: process(1, "x.exe", cpu=90.0)}
    results = [detector.feed(busy) for _ in range(5)]
    assert [len(result) for result in results] == [0, 0, 1, 0, 0]
    detector.feed({1: process(1, "x.exe", cpu=1.0)})
    assert [len(detector.feed(busy)) for _ in range(3)] == [0, 0, 1]
