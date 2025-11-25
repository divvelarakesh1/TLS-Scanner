import time
import sys
import subprocess
import shutil
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

from runners import sequential, parallel
from core.models import ScanTarget

GRAPH_DIR = "."
TARGET_FILE = "targets.txt"


# ==========================================
# LOAD TARGETS FROM FILE
# ==========================================
def load_targets_from_file(file_path=TARGET_FILE):
    targets = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                entry = line.strip()
                if not entry or entry.startswith("#"):
                    continue

                # Format: hostname or hostname:port
                if ":" in entry:
                    host, port = entry.split(":", 1)
                    port = int(port)
                else:
                    host, port = entry, 443

                targets.append(ScanTarget(host, port))

    except FileNotFoundError:
        print(f"[!] ERROR: targets.txt not found.")
        sys.exit(1)

    return targets


def run_sslyze_scan(targets):
    start = time.time()
    target_strs = [t.hostname for t in targets]
    try:
        cmd = ["sslyze", "--regular"] + target_strs
        subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception as e:
        print(f"  [!] SSLyze failed: {e}")
    return time.time() - start


# ==========================================
# EXPERIMENT 1: Sequential vs Parallel
# ==========================================
def exp_scaling(all_targets):
    print("\n[1/4] Running Scalability Benchmark (Seq vs Par)...")

    # Limit test sizes to avoid exceeding available targets
    target_counts = [5, 10, 20]
    target_counts = [n for n in target_counts if n <= len(all_targets)]

    seq_times = []
    par_times = []

    for n in target_counts:
        print(f"   Testing N={n} targets...")
        targets = all_targets[:n]

        s = time.time()
        sequential.run_scan(targets)
        seq_times.append(time.time() - s)

        s = time.time()
        parallel.run_scan(targets, pool_size=10)
        par_times.append(time.time() - s)

    plt.figure(figsize=(10, 6))
    plt.plot(target_counts, seq_times, 'r-o', label='Sequential')
    plt.plot(target_counts, par_times, 'g-o', label='Parallel')
    plt.title('Scalability: Execution Time vs Load')
    plt.xlabel('Number of Targets')
    plt.ylabel('Time (seconds)')
    plt.legend()
    plt.grid(True)
    plt.savefig(f"{GRAPH_DIR}/benchmark_1_scaling.png")
    print("   -> Saved benchmark_1_scaling.png")


# ==========================================
# EXPERIMENT 2: Worker Pool Tuning
# ==========================================
def exp_workers(all_targets):
    print("\n[2/4] Running Concurrency Tuning (Varying Workers)...")

    targets = all_targets[:20] if len(all_targets) >= 20 else all_targets
    worker_counts = [1, 5, 10, 20]
    times = []

    for w in worker_counts:
        print(f"   Testing Workers={w}...")
        s = time.time()
        parallel.run_scan(targets, pool_size=w)
        times.append(time.time() - s)

    plt.figure(figsize=(10, 6))
    plt.bar([str(w) for w in worker_counts], times, color='skyblue')
    plt.plot([str(w) for w in worker_counts], times, 'r-o')
    plt.title(f'Concurrency Tuning: Time for {len(targets)} Targets')
    plt.xlabel('Worker Processes')
    plt.ylabel('Time (seconds)')
    plt.savefig(f"{GRAPH_DIR}/benchmark_2_workers.png")
    print("   -> Saved benchmark_2_workers.png")


# ==========================================
# EXPERIMENT 3: Resilience Test
# ==========================================
def exp_timeouts(all_targets):
    print("\n[3/4] Running Resilience Test (Dead Hosts)...")

    if len(all_targets) < 5:
        print("   [!] Need at least 5 targets for this test.")
        return

    # any one invalid entry should be added manually in the file if required
    targets = all_targets[:4] + [ScanTarget("192.0.2.1", 443)]

    print("   Testing Lazy Timeout (10s)...")
    s = time.time()
    parallel.run_scan(targets, pool_size=5, connection_timeout=10.0)
    t_lazy = time.time() - s

    print("   Testing Aggressive Timeout (2s)...")
    s = time.time()
    parallel.run_scan(targets, pool_size=5, connection_timeout=2.0)
    t_agg = time.time() - s

    plt.figure(figsize=(8, 6))
    plt.bar(['Lazy (10s)', 'Aggressive (2s)'], [t_lazy, t_agg],
            color=['#ff9999', '#66b3ff'])
    plt.title('Resilience: Impact of Dead Hosts')
    plt.ylabel('Time (seconds)')
    plt.savefig(f"{GRAPH_DIR}/benchmark_3_timeouts.png")
    print("   -> Saved benchmark_3_timeouts.png")


# ==========================================
# EXPERIMENT 4: SSLyze Comparison
# ==========================================
def exp_competitor(all_targets):
    if not shutil.which("sslyze"):
        print("\n[!] Skipping Exp 4: SSLyze not installed.")
        return

    print("\n[4/4] Running Industry Comparison...")

    targets = all_targets[:10]

    print("   Running Our Scanner...")
    s = time.time()
    parallel.run_scan(targets, pool_size=10)
    t_mine = time.time() - s

    print("   Running SSLyze...")
    t_sslyze = run_sslyze_scan(targets)

    plt.figure(figsize=(8, 6))
    plt.bar(['Our Scanner', 'SSLyze'], [t_mine, t_sslyze],
            color=['#90EE90', '#D3D3D3'])
    plt.title('Head-to-Head Performance (3 Hosts)')
    plt.ylabel('Time (seconds)')
    plt.savefig(f"{GRAPH_DIR}/benchmark_4_competitor.png")

    print("   -> Saved benchmark_4_competitor.png")


# ==========================================
# MAIN
# ==========================================
if __name__ == "__main__":
    print("========================================")
    print("   STARTING COMPREHENSIVE BENCHMARK     ")
    print("========================================")

    all_targets = load_targets_from_file()

    #exp_scaling(all_targets)
    #exp_workers(all_targets)
    #exp_timeouts(all_targets)
    exp_competitor(all_targets)

    print("\n[+] Done! Check the PNG files in the folder.")
