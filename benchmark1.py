import time
import matplotlib.pyplot as plt
from runners import parallel

GRAPH_DIR = "."
BASE = "targets"

# --------------------------------------
# Load targets from file
# --------------------------------------
def load_targets(n):
    filename = f"{BASE}/targets{n}.txt"
    targets = []
    with open(filename, "r") as f:
        for line in f:
            host = line.strip()
            if host:
                # Create your ScanTarget object
                targets.append(host)   # If you use ScanTarget: ScanTarget(host, 443)
    return targets


# --------------------------------------
# Parallel Benchmark
# --------------------------------------
def benchmark_parallel():
    print("\n[Parallel Benchmark] Running...")

    target_counts = [1, 5, 10, 20, 50]
    parallel_times = []

    for n in target_counts:
        print(f"  -> Loading targets{n}.txt ...")
        targets = load_targets(n)

        print(f"     Running parallel scan on {n} targets...")
        start = time.time()

        # FIXED POOL SIZE = 10
        parallel.run_scan(targets, pool_size=10)

        duration = time.time() - start
        parallel_times.append(duration)

        print(f"     Done in {duration:.2f}s")

    # --------------------------------------
    # Plot graph
    # --------------------------------------
    plt.figure(figsize=(10, 6))
    plt.plot(target_counts, parallel_times, 'g-o', label="Parallel (10 threads)")

    plt.title("Parallel Scan Scalability")
    plt.xlabel("Number of Targets")
    plt.ylabel("Time (seconds)")
    plt.grid(True)
    plt.legend()

    outfile = f"{GRAPH_DIR}/parallel_scalability.png"
    plt.savefig(outfile)
    print(f"\nSaved graph to: {outfile}")


# --------------------------------------
# Main
# --------------------------------------
if __name__ == "__main__":
    benchmark_parallel()
