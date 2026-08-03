import os
import subprocess
import shutil
import time
from pathlib import Path

def get_version():
    try:
        # Try to get short commit hash
        commit = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], text=True).strip()
        return f"local-{commit}"
    except Exception:
        return "local-dev"

def build(goos, goarch, goarm, component, output_name):
    print(f"Building {component} for {goos}/{goarch}...")
    
    env = os.environ.copy()
    env["GOOS"] = goos
    env["GOARCH"] = goarch
    if goarm:
        env["GOARM"] = goarm
    env["CGO_ENABLED"] = "0"
    
    version = get_version()
    ldflags = f"-s -w -X cottendns-go/internal/version.BuildVersion={version}"
    
    cmd = [
        "go", "build",
        "-trimpath",
        "-ldflags", ldflags,
        "-o", output_name,
        f"./cmd/{component}"
    ]
    
    try:
        subprocess.run(cmd, env=env, check=True)
        print(f"Successfully built: {output_name}")
        return "ok"
    except subprocess.CalledProcessError as e:
        print(f"Failed to build {component} for {goos}/{goarch}: {e}")
        return "failed"

def main():
    dist_dir = Path("dist")
    if not dist_dir.exists():
        dist_dir.mkdir()
        
    targets = [
        {"os": "linux", "arch": "amd64", "ext": "", "platform": "Linux"},
        {"os": "windows", "arch": "amd64", "ext": ".exe", "platform": "Windows"},
    ]

    failed = []
    for t in targets:
        for component in ["client", "server"]:
            output_name = f"dist/CottenDns_{component.capitalize()}_{t['platform']}_{t['arch']}{t['ext']}"
            result = build(
                t["os"],
                t["arch"],
                t.get("goarm"),
                component,
                output_name,
            )
            if result == "failed":
                failed.append(f"{component}:{t['os']}/{t['arch']}")

    if failed:
        print("Build failed for:", ", ".join(failed))
        exit(1)
            
    print("Copying config files...")
    shutil.copy("client_config.toml.simple", dist_dir / "client_config.toml")
    shutil.copy("client_resolvers.simple", dist_dir / "client_resolvers.txt")
    shutil.copy("server_config.toml.simple", dist_dir / "server_config.toml")
    for preset in Path(".").glob("client_config.*.toml"):
        shutil.copy(preset, dist_dir / preset.name)
    for preset in Path(".").glob("server_config.*.toml"):
        shutil.copy(preset, dist_dir / preset.name)
    if Path("CONFIG_PRESETS.md").exists():
        shutil.copy("CONFIG_PRESETS.md", dist_dir / "CONFIG_PRESETS.md")
    if Path("assets/cottendns.png").exists():
        shutil.copy("assets/cottendns.png", dist_dir / "cottendns.png")

    print("Copying README files...")
    if Path("README.MD").exists():
        shutil.copy("README.MD", dist_dir / "README.MD")
    if Path("README_FA.MD").exists():
        shutil.copy("README_FA.MD", dist_dir / "README_FA.MD")
    engineering_notes = Path("docs") / "ENGINEERING_CHANGES.md"
    if engineering_notes.exists():
        shutil.copy(engineering_notes, dist_dir / "ENGINEERING_CHANGES.md")
        
    print("Build complete.")

if __name__ == "__main__":
    main()
