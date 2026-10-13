from collections.abc import Iterator


def open_key(hive: str, key: str, writable: bool = False):
    import winreg

    root, _, user = hive.partition("\\")
    base = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKU": winreg.HKEY_USERS}[root]
    access = (winreg.KEY_READ | winreg.KEY_SET_VALUE if writable else winreg.KEY_READ) | winreg.KEY_WOW64_64KEY
    return winreg.OpenKey(base, "\\".join(part for part in (user, key) if part), 0, access)


def string_values(hive: str, key: str) -> Iterator[tuple[str, str]]:
    import winreg

    try:
        handle = open_key(hive, key)
    except OSError:
        return
    with handle:
        index = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(handle, index)
            except OSError:
                return
            index += 1
            if isinstance(data, str):
                yield name, data


def subkeys(hive: str, key: str) -> list[str]:
    import winreg

    try:
        handle = open_key(hive, key)
    except OSError:
        return []
    names = []
    with handle:
        index = 0
        while True:
            try:
                names.append(winreg.EnumKey(handle, index))
            except OSError:
                return names
            index += 1
