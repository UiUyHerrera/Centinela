from centinela.models import Finding, Threat

MAX_SCORE = 100


def aggregate(findings: list[Finding]) -> list[Threat]:
    threats: dict[tuple, Threat] = {}
    for finding in findings:
        threat = threats.get(finding.target.key)
        if threat is None:
            threats[finding.target.key] = Threat(finding.target, [finding.reason], min(finding.score, MAX_SCORE))
            continue
        if finding.reason in threat.reasons:
            continue
        threat.reasons.append(finding.reason)
        threat.score = min(threat.score + finding.score, MAX_SCORE)
    return sorted(threats.values(), key=lambda threat: (-threat.score, threat.target.label.lower()))
