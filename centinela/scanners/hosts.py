from centinela.models import Finding, Target, TargetKind
from centinela.rules import SECURITY_DOMAINS


def analyze_hosts(lines: list[str]) -> list[Finding]:
    findings = []
    for line in lines:
        content = line.split("#", 1)[0].strip()
        fields = content.split()
        if len(fields) < 2:
            continue
        blocked = [host for host in fields[1:] if _is_security_domain(host.lower())]
        if blocked:
            target = Target(
                kind=TargetKind.HOSTS,
                identifier=line.strip(),
                label=f"hosts: {content}",
                details=(("line", line.strip()),),
            )
            findings.append(Finding(target, f"Redirige sitios de seguridad o actualizaciones: {', '.join(blocked)}", 60))
    return findings


def _is_security_domain(host: str) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in SECURITY_DOMAINS)
