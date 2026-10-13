import re

SYSTEM_BINARIES = {
    "svchost.exe": ("system32", "syswow64"),
    "lsass.exe": ("system32",),
    "csrss.exe": ("system32",),
    "winlogon.exe": ("system32",),
    "wininit.exe": ("system32",),
    "services.exe": ("system32",),
    "smss.exe": ("system32",),
    "spoolsv.exe": ("system32",),
    "taskhostw.exe": ("system32",),
    "sihost.exe": ("system32",),
    "dwm.exe": ("system32",),
    "conhost.exe": ("system32",),
    "dllhost.exe": ("system32", "syswow64"),
    "runtimebroker.exe": ("system32",),
    "rundll32.exe": ("system32", "syswow64"),
    "explorer.exe": ("",),
}

CRITICAL_PROCESSES = {"csrss.exe", "lsass.exe", "smss.exe", "wininit.exe", "winlogon.exe", "services.exe"}

EXPECTED_PARENTS = {
    "lsass.exe": {"wininit.exe"},
    "services.exe": {"wininit.exe"},
    "svchost.exe": {"services.exe"},
    "spoolsv.exe": {"services.exe"},
    "taskhostw.exe": {"svchost.exe"},
    "runtimebroker.exe": {"svchost.exe"},
}

SCRIPT_HOSTS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
}

DOCUMENT_AND_BROWSER_APPS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "acrord32.exe",
    "acrobat.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
}

MINER_NAMES = {
    "xmrig", "xmr-stak", "nbminer", "t-rex", "phoenixminer", "lolminer", "ethminer", "gminer",
    "teamredminer", "srbminer", "srbminer-multi", "cpuminer", "ccminer", "nanominer", "bminer",
    "miniz", "claymore", "nicehashminer", "excavator", "xmrminer", "wildrig",
}

MINER_COMMAND_PATTERNS = [
    re.compile(r"stratum\+(tcp|ssl|tls)://", re.IGNORECASE),
    re.compile(r"--donate-level", re.IGNORECASE),
    re.compile(r"--cpu-max-threads-hint", re.IGNORECASE),
    re.compile(r"--(algo|coin)[= ](rx/0|randomx|cryptonight|cn/\w+|kawpow|ethash|etchash|autolykos2|xmr|monero)\b", re.IGNORECASE),
    re.compile(r"\b(supportxmr|moneroocean|nanopool|2miners|f2pool|hashvault|herominers|unmineable|minexmr|nicehash)\b", re.IGNORECASE),
]

SCRIPT_ABUSE_PATTERNS = [
    (re.compile(r"\s-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}", re.IGNORECASE), "PowerShell con comando codificado"),
    (re.compile(r"frombase64string", re.IGNORECASE), "Decodifica contenido en base64"),
    (re.compile(r"downloadstring|downloadfile|invoke-webrequest|\biwr\s|start-bitstransfer", re.IGNORECASE), "Descarga contenido de internet"),
    (re.compile(r"\biex\b|invoke-expression", re.IGNORECASE), "Ejecuta texto como código"),
    (re.compile(r"\s-w(indowstyle)?\s+h(idden)?\b", re.IGNORECASE), "Se ejecuta con ventana oculta"),
    (re.compile(r"mshta(\.exe)?\s+[\"']?(https?|javascript|vbscript):", re.IGNORECASE), "mshta ejecutando código remoto"),
    (re.compile(r"certutil(\.exe)?.*-urlcache", re.IGNORECASE), "certutil usado para descargar archivos"),
    (re.compile(r"regsvr32(\.exe)?.*/i:https?", re.IGNORECASE), "regsvr32 cargando scripts remotos"),
    (re.compile(r"bitsadmin(\.exe)?.*/transfer", re.IGNORECASE), "bitsadmin usado para descargar archivos"),
]

MINING_PORTS = {3333, 3357, 4444, 5555, 5556, 7777, 10128, 14433, 14444, 20128, 45560, 45700}

USER_WRITABLE_MARKERS = (
    "\\appdata\\", "\\temp\\", "\\tmp\\", "\\programdata\\", "\\users\\public\\",
    "\\downloads\\", "\\$recycle.bin\\", "\\perflogs\\",
)

EXECUTABLE_EXTENSIONS = ("exe", "dll", "com", "bat", "cmd", "scr", "ps1", "vbs", "vbe", "js", "jse", "hta", "msi", "cpl")

DECOY_EXTENSIONS = ("pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "mp3", "mp4", "zip")

MONITOR_PROCESSES = {
    "taskmgr.exe", "procexp.exe", "procexp64.exe", "processhacker.exe", "systeminformer.exe",
    "perfmon.exe", "resmon.exe", "procmon.exe", "procmon64.exe",
}

SECURITY_DOMAINS = (
    "microsoft.com", "windowsupdate.com", "windows.com", "live.com", "virustotal.com",
    "malwarebytes.com", "kaspersky.com", "eset.com", "avast.com", "avg.com", "bitdefender.com",
    "mcafee.com", "norton.com", "sophos.com", "trendmicro.com", "github.com",
)

RISKY_EXCLUSION_EXTENSIONS = {"exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "scr"}

WMI_EXECUTING_CONSUMERS = {"CommandLineEventConsumer", "ActiveScriptEventConsumer"}
