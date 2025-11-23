#!/usr/bin/env python3
import argparse
import csv
import subprocess
import statistics
from pathlib import Path


def run_once(count, batch):
    cmd = ["./bin/siov", "--count", str(count), "--verify", "on", "--trace", "off", "--batch", "on" if batch else "off"]
    out = subprocess.check_output(cmd, text=True)
    for line in out.splitlines():
        if line.startswith("Signed"):
            parts = line.split()
            return float(parts[-2])
    return None


def main():
    parser = argparse.ArgumentParser(description="Benchmark SIOV")
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--batch", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("bench.csv"))
    args = parser.parse_args()

    times = []
    for _ in range(args.repeat):
        t = run_once(args.count, args.batch)
        if t is not None:
            times.append(t)
            print(f"run time: {t:.2f} ms")

    if not times:
        print("No timings collected")
        return

    with args.output.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["verify_ms"])
        for t in times:
            w.writerow([t])

    print(f"min/avg/max: {min(times):.2f}/{statistics.mean(times):.2f}/{max(times):.2f} ms")


if __name__ == "__main__":
    main()
