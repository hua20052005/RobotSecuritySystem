import sys
from pathlib import Path

ROOT = Path(SPECPATH).parent.parent
CONDA_BIN = Path(sys.executable).resolve().parent / "Library" / "bin"

binaries = [
    (str(CONDA_BIN / name), ".")
    for name in (
        "ffi.dll",
        "libbz2.dll",
        "libcrypto-3-x64.dll",
        "libexpat.dll",
        "liblzma.dll",
        "libmpdec-4.dll",
        "libssl-3-x64.dll",
        "sqlite3.dll",
    )
]

datas = [
    (str(ROOT / "web" / "dist"), "web/dist"),
    (str(ROOT / "models"), "models"),
    (str(ROOT / "motion"), "motion"),
    (str(ROOT / "payload-detection" / "config"), "payload-detection/config"),
    (str(ROOT / "payload-detection" / "models"), "payload-detection/models"),
    (str(ROOT / "payload-detection" / "modules"), "payload-detection/modules"),
    (str(ROOT / "payload-detection" / "scripts"), "payload-detection/scripts"),
    (str(ROOT / "ET-BERT-main" / "models"), "ET-BERT-main/models"),
]

hiddenimports = [
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
    "multipart",
    "python_multipart",
    "scapy.all",
    "sklearn.ensemble._forest",
    "sklearn.ensemble._iforest",
    "sklearn.tree._classes",
    "sklearn.feature_selection._univariate_selection",
    "sklearn.preprocessing._data",
]

a = Analysis(
    [str(ROOT / "desktop_launcher.py")],
    pathex=[
        str(ROOT),
        str(ROOT / "backend" / "motion_recognition"),
        str(ROOT / "motion" / "motion"),
    ],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "torch",
        "tensorflow",
        "xgboost",
        "lightgbm",
        "streamlit",
        "jupyter",
        "IPython",
        "cv2",
        "tkinter",
        "_tkinter",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="RoboGuard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=str(ROOT / "packaging" / "version_info.txt"),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="RoboGuard",
)
