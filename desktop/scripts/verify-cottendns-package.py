"""Verify the pinned CottenDNS inputs and exact helper embedded in a desktop app."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

repo = Path(__file__).resolve().parents[2]
core = repo / "CottenDNS"
receipt = json.loads((repo / "vendor/cottendns.json").read_text())
snapshot = json.loads((core / "COTTEN_CORE_SNAPSHOT.json").read_text())
pin = receipt["commit"]
if snapshot["commit"] != pin:
    raise SystemExit("CottenDNS vendor and snapshot pins disagree")
for entry in snapshot["files"]:
    source = core / entry["path"]
    if not source.resolve().is_relative_to(core.resolve()):
        raise SystemExit("CottenDNS snapshot path escapes the source directory")
    data = source.read_bytes().replace(b"\r\n", b"\n")
    if hashlib.sha256(data).hexdigest() != entry["sha256_lf"]:
        raise SystemExit("CottenDNS source differs from its snapshot: " + entry["path"])

goos, arch = sys.argv[1:3]
helper_name = f"cottendns-client-{goos}-{arch}" + (".exe" if goos == "windows" else "")
helper = repo / "desktop/clients" / helper_name
metadata = subprocess.check_output(["go", "version", "-m", str(helper)], text=True)
required = {"\tpath\tcottendns-go/cmd/client", "\tbuild\tGOOS=" + goos, "\tbuild\tGOARCH=" + arch}
if not required.issubset(set(metadata.splitlines())):
    raise SystemExit("CottenDNS helper has the wrong build target: " + metadata)
raw = helper.read_bytes()
if pin.encode("ascii") + b"\x00" not in raw:
    raise SystemExit("CottenDNS helper does not contain the pinned core version")

app_dir = repo / "desktop/build/bin"
if goos == "darwin":
    app = app_dir / "WhiteDNS Desktop.app/Contents/MacOS/WhiteDNS Desktop"
elif goos == "windows":
    app = app_dir / "WhiteDNS Desktop.exe"
else:
    app = app_dir / "WhiteDNS Desktop"
if raw not in app.read_bytes():
    raise SystemExit("Desktop app does not embed the freshly built CottenDNS helper")
print(f"Verified {len(snapshot['files'])} CottenDNS source inputs and embedded {helper_name} at {pin}")
print("CottenDNS helper SHA256:", hashlib.sha256(raw).hexdigest())
