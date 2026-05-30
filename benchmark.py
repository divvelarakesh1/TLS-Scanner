import time
import sys
import subprocess
import shutil
import matplotlib
# Force headless backend
matplotlib.use('Agg') 
import matplotlib.pyplot as plt
import numpy as np

# --- CHANGED IMPORTS ---
# Importing from the 'runners' package
from runners import sequential, parallel
from core.models import ScanTarget

# --- CONFIGURATION ---
GRAPH_DIR = "." 
FAST_TARGET = "google.com"
DEAD_TARGET = "192.0.2.1" 

def generate_targets(count, host=FAST_TARGET):
    return [ScanTarget(host, 443) for _ in range(count)]

def run_sslyze_scan(targets):
    """Runs external sslyze tool."""
    start = time.time()
    target_strs = [t.hostname for t in targets]
    try:
        cmd = ["sslyze", "--regular"] + target_strs
        # Short timeout for benchmark speed
        subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception as e:
        print(f"  [!] SSLyze failed: {e}")
    return time.time() - start

# ==========================================
# EXPERIMENT 1: Sequential vs Parallel (Scaling)
# ==========================================
def exp_scaling():
    print("\n[1/4] Running Scalability Benchmark (Seq vs Par)...")
    target_counts = [5, 10, 20] 
    seq_times = []
    par_times = []

    for n in target_counts:
        print(f"   Testing N={n} targets...")
        targets = generate_targets(n)
        
        # Sequential
        s = time.time()
        sequential.run_scan(targets)
        seq_times.append(time.time() - s)
        
        # Parallel (Fixed 10 workers)
        s = time.time()
        parallel.run_scan(targets, pool_size=10)
        par_times.append(time.time() - s)

    # Plot
    plt.figure(figsize=(10, 6))
    plt.plot(target_counts, seq_times, 'r-o', label='Sequential (Linear)')
    plt.plot(target_counts, par_times, 'g-o', label='Parallel (O(1))')
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
def exp_workers():
    print("\n[2/4] Running Concurrency Tuning (Varying Workers)...")
    n_targets = 20
    worker_counts = [1, 5, 10, 20]
    times = []
    targets = generate_targets(n_targets)

    for w in worker_counts:
        print(f"   Testing Workers={w}...")
        s = time.time()
        parallel.run_scan(targets, pool_size=w)
        times.append(time.time() - s)

    # Plot
    plt.figure(figsize=(10, 6))
    plt.bar([str(w) for w in worker_counts], times, color='skyblue')
    plt.plot([str(w) for w in worker_counts], times, 'r-o')
    plt.title(f'Concurrency Tuning: Time to Scan {n_targets} Targets')
    plt.xlabel('Number of Worker Processes')
    plt.ylabel('Time (seconds)')
    plt.savefig(f"{GRAPH_DIR}/benchmark_2_workers.png")
    print("   -> Saved benchmark_2_workers.png")

# ==========================================
# EXPERIMENT 3: Resilience
# ==========================================
def exp_timeouts():
    print("\n[3/4] Running Resilience Test (Dead Hosts)...")
    targets = generate_targets(4) + [ScanTarget(DEAD_TARGET, 443)]
    
    # Run with Standard Timeout (10s)
    print("   Testing Lazy Timeout (10s)...")
    s = time.time()
    parallel.run_scan(targets, pool_size=5, connection_timeout=10.0)
    t_lazy = time.time() - s
    
    # Run with Aggressive Timeout (2s)
    print("   Testing Aggressive Timeout (2s)...")
    s = time.time()
    parallel.run_scan(targets, pool_size=5, connection_timeout=2.0)
    t_agg = time.time() - s

    # Plot
    plt.figure(figsize=(8, 6))
    labels = ['Lazy (10s)', 'Aggressive (2s)']
    values = [t_lazy, t_agg]
    bars = plt.bar(labels, values, color=['#ff9999', '#66b3ff'])
    
    plt.title('Resilience: Impact of Dead Hosts')
    plt.ylabel('Total Time (seconds)')
    
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height, f'{height:.2f}s', ha='center', va='bottom')
        
    plt.savefig(f"{GRAPH_DIR}/benchmark_3_timeouts.png")
    print("   -> Saved benchmark_3_timeouts.png")

# ==========================================
# EXPERIMENT 4: Industry Comparison
# ==========================================
def exp_competitor():
    print("\n[1/4] Running Scalability Benchmark (Seq vs Par)...")
    target_counts = [1,5, 10, 20,50,100] 
    par_times = []

    for n in target_counts:
        print(f"   Testing N={n} targets...")
        targets = generate_targets(n)        
        # Parallel (Fixed 10 workers)
        s = time.time()
        parallel.run_scan(targets, pool_size=10)
        par_times.append(time.time() - s)

    # Plot
    plt.figure(figsize=(10, 6))
    plt.plot(target_counts, par_times, 'g-o', label='Parallel (O(1))')
    plt.title('Scalability: Execution Time vs Load')
    plt.xlabel('Number of Targets')
    plt.ylabel('Time (seconds)')
    plt.legend()
    plt.grid(True)
    plt.savefig(f"{GRAPH_DIR}/benchmark_4_scaling.png")
    print("   -> Saved benchmark_5_scaling.png")
if __name__ == "__main__":
    print("========================================")
    print("   STARTING COMPREHENSIVE BENCHMARK     ")
    print("========================================")
    
  #  exp_scaling()
   # exp_workers()
   # exp_timeouts()
    exp_competitor()
    
    print("\n[+] Done! Check the .png files in your folder.")