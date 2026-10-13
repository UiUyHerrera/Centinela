from centinela.models import SignatureState
from centinela.paths import is_protected_path, is_user_writable, referenced_files
from centinela.scanners.indicators import command_reasons, file_reasons


def reasons(iterator):
    return [reason for reason, _ in iterator]


def test_referenced_files_finds_quoted_and_payload_paths():
    command = r'"C:\Windows\System32\rundll32.exe" C:\Users\ana\AppData\Roaming\x\payload.dll,Start'
    assert referenced_files(command) == [
        r"C:\Windows\System32\rundll32.exe",
        r"C:\Users\ana\AppData\Roaming\x\payload.dll",
    ]


def test_referenced_files_handles_spaces_and_no_paths():
    assert referenced_files(r"C:\Program Files\App Name\app.exe --minimized") == [r"C:\Program Files\App Name\app.exe"]
    assert referenced_files("explorer.exe") == []
    assert referenced_files("") == []


def test_referenced_files_ignores_duplicates_case_insensitively():
    assert referenced_files(r"C:\a\b.exe C:\A\B.EXE") == [r"C:\a\b.exe"]


def test_user_writable_and_protected_paths():
    assert is_user_writable(r"C:\Users\ana\AppData\Local\Temp\x.exe")
    assert not is_user_writable(r"C:\Program Files\App\app.exe")
    assert is_protected_path(r"C:\Windows\System32\svchost.exe", r"C:\Windows")
    assert not is_protected_path(r"C:\Windows\Temp\svchost.exe", r"C:\Windows")
    assert not is_protected_path(r"C:\Windows\System32x\evil.exe", r"C:\Windows")


def test_miner_command_detected():
    found = reasons(command_reasons("xmr.exe -o stratum+tcp://pool.supportxmr.com:3333 -u wallet --donate-level 1"))
    assert found == ["Argumentos típicos de un minero de criptomonedas"]


def test_encoded_powershell_detected():
    found = reasons(command_reasons("powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"))
    assert "PowerShell con comando codificado" in found
    assert "Se ejecuta con ventana oculta" in found


def test_benign_command_has_no_reasons():
    assert reasons(command_reasons(r'"C:\Program Files\Mozilla Firefox\firefox.exe" -osint -url https://example.com')) == []


def test_file_reasons_for_unsigned_file_in_temp_with_double_extension():
    found = reasons(file_reasons(r"C:\Users\ana\Downloads\factura.pdf.exe", SignatureState.UNSIGNED))
    assert found == [
        "Extensión doble para engañar: factura.pdf.exe",
        "Sin firma digital",
        "Ejecutable sin firma válida en carpeta de usuario o temporal",
    ]


def test_signed_file_in_appdata_is_clean():
    assert reasons(file_reasons(r"C:\Users\ana\AppData\Local\Discord\app\Discord.exe", SignatureState.VALID)) == []


def test_known_miner_name_flagged_even_if_signed():
    assert reasons(file_reasons(r"D:\tools\xmrig.exe", SignatureState.VALID)) == ["Nombre de minero conocido: xmrig.exe"]
