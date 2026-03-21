# -*- mode: python ; coding: utf-8 -*-
# NetProbe Server — PyInstaller spec
#
# Build:
#   pip install pyinstaller
#   pyinstaller NetProbeServer.spec --clean
#
# Output: dist/NetProbeServer.exe  (~30 MB)
# Run:    NetProbeServer.exe
#         NetProbeServer.exe --port 9000
#
# The .exe is self-contained — no Python installation required on the host.
# Place a .env file next to NetProbeServer.exe to configure it.

from PyInstaller.utils.hooks import collect_all, collect_submodules

datas = [
    ('core',   'core'),
    ('server', 'server'),
]
binaries = []
hiddenimports = [
    # FastAPI / Starlette internals loaded dynamically
    'uvicorn.logging',
    'uvicorn.loops',
    'uvicorn.loops.auto',
    'uvicorn.loops.asyncio',
    'uvicorn.protocols',
    'uvicorn.protocols.http',
    'uvicorn.protocols.http.auto',
    'uvicorn.protocols.http.h11_impl',
    'uvicorn.protocols.websockets',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.protocols.websockets.websockets_impl',
    'uvicorn.lifespan',
    'uvicorn.lifespan.on',
    'fastapi',
    'starlette',
    'starlette.routing',
    'starlette.middleware',
    'starlette.middleware.cors',
    'websockets',
    'websockets.legacy',
    'websockets.legacy.server',
    'h11',
    # Network engine
    'scapy.layers.all',
    'scapy.route',
    'scapy.arch.windows',
    'dns.resolver',
    'dns.rdatatype',
    'dns.rdataclass',
    'dns.query',
    'dns.name',
    'dns.rdata',
    'psutil._pswindows',
    'psutil._psutil_windows',
    'cryptography',
    'cryptography.x509',
    'cryptography.hazmat.primitives',
    'cryptography.hazmat.backends',
    # stdlib used dynamically
    'ipaddress',
    'ssl',
    'urllib.request',
    'urllib.parse',
    'socket',
    'json',
    'queue',
    'threading',
    'subprocess',
    'struct',
    'asyncio',
    'concurrent.futures',
]

for pkg in ('scapy', 'dns', 'psutil', 'cryptography', 'uvicorn', 'fastapi', 'starlette'):
    tmp = collect_all(pkg)
    datas          += tmp[0]
    binaries       += tmp[1]
    hiddenimports  += tmp[2]

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
        'tkinter', 'matplotlib', 'numpy', 'pandas', 'PIL',
        'wx', 'PyQt5', 'PyQt6', 'PySide2', 'PySide6',
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
    name='NetProbeServer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=['vcruntime140.dll', 'python3*.dll'],
    runtime_tmpdir=None,
    console=True,                # server needs a console window / stdout
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
