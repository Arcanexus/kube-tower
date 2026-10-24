import subprocess
import sys

# The Dockerfile deletes these packages from the image (kubernetes asyncio client and its aiohttp stack)
REMOVED_FROM_IMAGE = ("aiohttp", "aiohttp_retry", "yarl", "multidict", "frozenlist", "attr", "attrs")


def test_app_does_not_import_packages_removed_from_the_image():
    code = (
        "import importlib, pkgutil, sys, kube_tower\n"
        "for mod in pkgutil.walk_packages(kube_tower.__path__, 'kube_tower.'):\n"
        "    importlib.import_module(mod.name)\n"
        f"print(sorted(m for m in sys.modules if m.split('.')[0] in {REMOVED_FROM_IMAGE!r} or m.startswith('kubernetes.aio')))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True, cwd="src")
    assert out.stdout.splitlines()[-1] == "[]"
