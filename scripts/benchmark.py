#!/usr/bin/env python3
import argparse, subprocess, statistics, shlex, re, time

def run_once(cmd, use_time=True):
    if use_time:
        full = f"/usr/bin/time -v {cmd}"
        p = subprocess.run(full, shell=True, capture_output=True, text=True)
        # wall time 取 Python 度量較準確
        mem = None
        m = re.search(r"Maximum resident set size \(kbytes\): (\d+)", p.stderr)
        if m: mem = int(m.group(1))
        ok = (p.returncode == 0)
        return ok, mem
    else:
        t0 = time.perf_counter()
        ok = (subprocess.call(cmd, shell=True) == 0)
        _ = time.perf_counter() - t0
        return ok, None

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeat", type=int, default=5)
    ap.add_argument("--message-size", type=int, default=64)
    ap.add_argument("--verify", choices=["on","off"], default="on")
    ap.add_argument("--trace",  choices=["on","off"], default="off")
    ap.add_argument("--count", type=int, default=20, help="簽章數（每回合）")
    ap.add_argument("--rbits", type=int, default=160)
    ap.add_argument("--qbits", type=int, default=512)
    args = ap.parse_args()

    base = f"./bin/siov --count {args.count} --message-size {args.message_size} " \
           f"--verify {args.verify} --trace {args.trace} --rbits {args.rbits} --qbits {args.qbits}"

    print(f"[BENCH] repeat={args.repeat} count={args.count} msg={args.message_size} verify={args.verify} trace={args.trace}")
    times, mems = [], []
    for i in range(args.repeat):
        t0 = time.perf_counter()
        ok, mem = run_once(base, use_time=True)
        dt = time.perf_counter() - t0
        if not ok:
            print(f"  run #{i+1}: FAIL")
        else:
            print(f"  run #{i+1}: {dt:.4f}s  RSS={mem} KB")
        times.append(dt); 
        if mem is not None: mems.append(mem)

    print("\n[RESULT]")
    print(f"  total: {sum(times):.4f}s")
    print(f"  avg  : {statistics.mean(times):.4f}s")
    print(f"  min  : {min(times):.4f}s")
    print(f"  max  : {max(times):.4f}s")
    if mems:
        print(f"  RSS  : avg={statistics.mean(mems):.0f} KB  max={max(mems)} KB")
