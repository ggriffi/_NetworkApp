# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all, collect_submodules

datas    = [('ui', 'ui'), ('core', 'core')]
binaries = [
    ('iperf3.exe',      '.'),
    ('cygwin1.dll',     '.'),
    ('cygcrypto-3.dll', '.'),
    ('cygz.dll',        '.'),
]
hiddenimports = [
    # Scapy
    'scapy.layers.all', 'scapy.route', 'scapy.arch.windows',
    # DNS
    'dns.resolver', 'dns.rdatatype', 'dns.rdataclass',
    'dns.query', 'dns.name', 'dns.rdata',
    # psutil
    'psutil._pswindows', 'psutil._psutil_windows',
    # cryptography (SSL inspection fallback)
    'cryptography', 'cryptography.x509', 'cryptography.hazmat.primitives',
    'cryptography.hazmat.backends',
    # stdlib used dynamically
    'ipaddress', 'ssl', 'urllib.request', 'urllib.parse',
    'socket', 'json', 'csv', 'queue', 'threading',
    'subprocess', 'struct', 'hmac', 'hashlib',
]

for pkg in ('scapy', 'dns', 'psutil', 'cryptography'):
    tmp = collect_all(pkg)
    datas     += tmp[0]
    binaries  += tmp[1]
    hiddenimports += tmp[2]

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib', 'numpy', 'pandas', 'PIL', 'wx',
        'PyQt5', 'PyQt6', 'PySide2', 'PySide6',
        'IPython', 'jupyter', 'notebook',
        'test', 'unittest', 'doctest',
    ],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='NetProbe',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=['vcruntime140.dll', 'python3*.dll'],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='NetProbe.ico',
)
