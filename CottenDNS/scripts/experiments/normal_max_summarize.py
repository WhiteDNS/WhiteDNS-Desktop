#!/usr/bin/env python3
"""Export graph data from the verified Normal/Max JSON summaries."""
import argparse
import csv
import json
import pathlib


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", nargs="+", required=True, help="matrix result directories")
    p.add_argument("--output", required=True)
    a = p.parse_args()
    rows = []
    for directory in a.input:
        for value in json.loads((pathlib.Path(directory)/"summary.json").read_text(encoding="utf-8")):
            rows.append(dict(value, source=directory))
    lookup = {(r["profile"], r["mode"]): r for r in rows}
    fields = ["profile", "mode", "successes", "failures", "mbps_median", "mbps_min", "mbps_max", "dns_qps_median", "percent_full_mbps", "percent_speed_loss_vs_full", "ratio_normal_android_mbps", "ratio_normal_desktop_mbps", "source"]
    out = pathlib.Path(a.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fields)
        writer.writeheader()
        for r in rows:
            row = {k: r[k] for k in ("profile", "mode", "successes", "failures", "source")}
            if "goodput_mbps" in r:
                speed = r["goodput_mbps"]["median"]
                for key, raw in (("median", "mbps_median"), ("min", "mbps_min"), ("max", "mbps_max")):
                    row[raw] = r["goodput_mbps"][key]
                row["dns_qps_median"] = r["query_starts_per_second"]["median"]
                full = lookup.get((r["profile"], "max-full"))
                if full and full.get("goodput_mbps"):
                    row["percent_full_mbps"] = speed/full["goodput_mbps"]["median"]*100
                    row["percent_speed_loss_vs_full"] = 100-row["percent_full_mbps"]
                for mode, key in (("normal-android", "ratio_normal_android_mbps"), ("normal-desktop", "ratio_normal_desktop_mbps")):
                    normal = lookup.get((r["profile"], mode))
                    if normal and normal.get("goodput_mbps"):
                        row[key] = speed/normal["goodput_mbps"]["median"]
            writer.writerow(row)


if __name__ == "__main__":
    main()
