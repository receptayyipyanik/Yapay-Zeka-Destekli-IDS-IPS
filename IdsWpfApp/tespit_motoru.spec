# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['tespit_csharp.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'sklearn.ensemble._stacking',
        'sklearn.ensemble._forest',
        'sklearn.tree._classes',
        'sklearn.linear_model._logistic',
        'sklearn.cluster._kmeans',
        'sklearn.neighbors._classification',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='tespit_motoru',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
