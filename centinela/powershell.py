import base64
import json
import os
import subprocess
import tempfile

CREATE_NO_WINDOW = 0x08000000

_PREAMBLE = """
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
$payload = Get-Content -LiteralPath $env:CENTINELA_PAYLOAD -Raw -Encoding UTF8 | ConvertFrom-Json
"""

_EPILOGUE = """
ConvertTo-Json -InputObject @($result) -Compress -Depth 4
"""

SIGNATURES = """
$result = foreach ($path in @($payload)) {
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        [pscustomobject]@{ path = $path; status = [string]$signature.Status }
    } catch {
        [pscustomobject]@{ path = $path; status = 'UnknownError' }
    }
}
"""

SCHEDULED_TASKS = """
$result = foreach ($task in Get-ScheduledTask) {
    foreach ($action in @($task.Actions)) {
        if ($action.Execute) {
            [pscustomobject]@{
                task_path = [string]$task.TaskPath
                task_name = [string]$task.TaskName
                execute = [string]$action.Execute
                arguments = [string]$action.Arguments
                hidden = [bool]$task.Settings.Hidden
            }
        }
    }
}
"""

WMI_CONSUMERS = """
$result = foreach ($consumer in Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer) {
    [pscustomobject]@{
        name = [string]$consumer.Name
        type = [string]$consumer.CimClass.CimClassName
        command = ('{0} {1}' -f $consumer.CommandLineTemplate, $consumer.ScriptText).Trim()
    }
}
"""

DEFENDER_SETTINGS = """
$preferences = Get-MpPreference
$status = Get-MpComputerStatus
$result = @(
    foreach ($value in @($preferences.ExclusionPath)) { if ($value) { [pscustomobject]@{ setting = 'path'; value = [string]$value } } }
    foreach ($value in @($preferences.ExclusionProcess)) { if ($value) { [pscustomobject]@{ setting = 'process'; value = [string]$value } } }
    foreach ($value in @($preferences.ExclusionExtension)) { if ($value) { [pscustomobject]@{ setting = 'extension'; value = [string]$value } } }
    [pscustomobject]@{ setting = 'realtime'; value = [string]$status.RealTimeProtectionEnabled }
    [pscustomobject]@{ setting = 'tamper'; value = [string]$status.IsTamperProtected }
)
"""

SHORTCUT_TARGETS = """
$shell = New-Object -ComObject WScript.Shell
$result = foreach ($path in @($payload)) {
    $shortcut = $shell.CreateShortcut($path)
    [pscustomobject]@{ path = $path; command = ('"{0}" {1}' -f $shortcut.TargetPath, $shortcut.Arguments).Trim() }
}
"""

SET_TASK_ENABLED = """
if ($payload.enabled) { Enable-ScheduledTask -TaskPath $payload.task_path -TaskName $payload.task_name | Out-Null }
else { Disable-ScheduledTask -TaskPath $payload.task_path -TaskName $payload.task_name | Out-Null }
$result = @()
"""

CHANGE_DEFENDER_EXCLUSION = """
$parameters = @{}
switch ($payload.setting) {
    'path' { $parameters.ExclusionPath = $payload.value }
    'process' { $parameters.ExclusionProcess = $payload.value }
    'extension' { $parameters.ExclusionExtension = $payload.value }
    default { throw 'Tipo de exclusion desconocido' }
}
if ($payload.add) { Add-MpPreference @parameters } else { Remove-MpPreference @parameters }
$result = @()
"""


class PowerShellError(Exception):
    pass


def _child_environment(payload_path: str) -> dict[str, str]:
    environment = {name: value for name, value in os.environ.items() if name.upper() != "PSMODULEPATH"}
    environment["CENTINELA_PAYLOAD"] = payload_path
    return environment


def run_powershell(script: str, payload: object = None, timeout: int = 300) -> list[dict]:
    encoded = base64.b64encode((_PREAMBLE + script + _EPILOGUE).encode("utf-16-le")).decode("ascii")
    with tempfile.TemporaryDirectory(prefix="centinela-") as directory:
        payload_path = os.path.join(directory, "payload.json")
        with open(payload_path, "w", encoding="utf-8") as payload_file:
            json.dump(payload, payload_file, ensure_ascii=True)
        try:
            completed = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                creationflags=CREATE_NO_WINDOW,
                env=_child_environment(payload_path),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise PowerShellError(f"PowerShell no respondió: {error}") from error
    if completed.returncode != 0:
        raise PowerShellError(completed.stderr.strip().splitlines()[0] if completed.stderr.strip() else "PowerShell falló")
    output = completed.stdout.strip().lstrip("﻿")
    data = json.loads(output) if output else []
    items = data if isinstance(data, list) else [data]
    return [item for item in items if isinstance(item, dict)]
