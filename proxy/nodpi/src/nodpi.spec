# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['nodpi.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'active_bypass',
        'scapy',
        'scapy.arch',
        'scapy.arch.windows',
        'scapy.layers',
        'scapy.layers.inet',
        'scapy.layers.l2',
        'scapy.packet',
        'scapy.utils',
        'scapy.config',
        'scapy.error',
        'scapy.all',
        'pydivert',          # если используется, удалите если нет
        'winreg',             # для автозапуска
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='nodpi',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,                # Показывать окно консоли
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico',              # если есть иконка, иначе удалите
    uac_admin=True,               # Запрос прав администратора при запуске
    uac_uiaccess=False,
)