import PyInstaller.__main__

PyInstaller.__main__.run([
    "centinela/__main__.py",
    "--name=Centinela",
    "--paths=.",
    "--onefile",
    "--windowed",
    "--uac-admin",
    "--clean",
    "--noconfirm",
])
