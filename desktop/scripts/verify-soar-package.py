"""Check that the built desktop binary contains the target's embedded Soar helper."""
import pathlib
import sys

root = pathlib.Path("desktop/build/bin")
goos, arch = sys.argv[1:3]
name = "soar-client-" + goos + "-" + arch + (".exe" if goos == "windows" else "")
if goos == "darwin":
    binary = root / "WhiteDNS Desktop.app/Contents/MacOS/WhiteDNS Desktop"
elif goos == "windows":
    binary = root / "WhiteDNS Desktop.exe"
else:
    binary = root / "WhiteDNS Desktop"
data = binary.read_bytes()
assert name.encode() in data, "Missing embedded helper: " + name
assert b"WhiteDNS Soar engine" in data, "Missing pinned Soar engine contents"
print("Verified embedded Soar helper:", name, "in", binary)
