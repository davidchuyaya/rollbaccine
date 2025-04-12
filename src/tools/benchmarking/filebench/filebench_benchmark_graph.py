import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import glob

configs = ["UNREPLICATED", "DM", "REPLICATED", "ROLLBACCINE"]
file_systems = ["ext4", "xfs"]
benchmarks = ["varmail", "webserver"]

# Returns throughput, latency
def extract_data(config, file_system, benchmark):
    matched_files = glob.glob(f"../../../../results/{config}_{file_system}_*_{benchmark}_*.txt")
    config_throughputs = []
    config_latencies = []
    for matched_file in matched_files:
        with open(matched_file, 'r') as file:
            for line in file:
                if "IO Summary:" in line:
                    words = line.split()
                    config_throughputs.append(float(words[5]))
                    config_latencies.append(float(words[-1].replace("ms/op", "")))

    avg_throughput = sum(config_throughputs) / len(config_throughputs)
    bottom_throughput = avg_throughput - min(config_throughputs)
    top_throughput = max(config_throughputs) - avg_throughput

    avg_latency = sum(config_latencies) / len(config_latencies)
    bottom_latency = avg_latency - min(config_latencies)
    top_latency = max(config_latencies) - avg_latency

    # Since avg_latency doing float division, if all 3 avg_latencies are the same, it comes out to a slightly different number and might create tiny negative bottom/top latencies
    if np.isclose(bottom_latency, 0):
        bottom_latency = 0
    if np.isclose(top_latency, 0):
        top_latency = 0

    return int(avg_throughput), bottom_throughput, top_throughput, round(avg_latency, 2), bottom_latency, top_latency

for benchmark in benchmarks:
    throughputs = {config: [] for config in configs}
    bottom_throughputs = {config: [] for config in configs}
    top_throughputs = {config: [] for config in configs}
    latencies = {config: [] for config in configs}
    bottom_latencies = {config: [] for config in configs}
    top_latencies = {config: [] for config in configs}

    for config in configs:
        for file_system in file_systems:
            avg_throughput, bottom_throughput, top_throughput, avg_latency, bottom_latency, top_latency = extract_data(config, file_system, benchmark)
            throughputs[config].append(avg_throughput)
            bottom_throughputs[config].append(bottom_throughput)
            top_throughputs[config].append(top_throughput)
            latencies[config].append(avg_latency)
            bottom_latencies[config].append(bottom_latency)
            top_latencies[config].append(top_latency)

    throughput_df = pd.DataFrame(throughputs, index=file_systems)
    bottom_throughput_df = pd.DataFrame(bottom_throughputs, index=file_systems)
    top_throughput_df = pd.DataFrame(top_throughputs, index=file_systems)
    latency_df = pd.DataFrame(latencies, index=file_systems)
    bottom_latency_df = pd.DataFrame(bottom_latencies, index=file_systems)
    top_latency_df = pd.DataFrame(top_latencies, index=file_systems)

    # Plot throughput and latency comparisons
    for (df, bottom, top, axis, name) in [(throughput_df, bottom_throughput_df, top_throughput_df, "Throughput (ops/sec)", "throughput"), (latency_df, bottom_latency_df, top_latency_df, "Avg Latency (us)", "latency")]:
        plt.figure(figsize=(3, 2))
        bar_width = 1.0 / (len(configs) + 1)  # Width of each bar
        x = range(len(file_systems))
        plt.grid(axis='y', linestyle='-', alpha=0.3, zorder=0)

        # Generate bars for each configuration
        colors = ['red', 'cyan', 'lime', 'orange']  # Different colors for configurations
        patterns = ['/', '\\', 'x', '*']  # Different patterns for configurations
        for i, config in enumerate(configs):
            plt.bar_label(plt.bar(
                [pos + i * bar_width for pos in x],
                df[config],
                yerr=(bottom[config], top[config]),
                width=bar_width,
                label=config,
                color=colors[i % len(colors)],
                hatch=patterns[i % len(patterns)],
                zorder=5
            ), df[config], zorder=10, rotation=90, padding=5)

        # Add labels, title
        plt.ylabel(axis)
        plt.xticks([pos + bar_width * (len(configs)-1) / 2 for pos in x], file_systems)
        plt.tick_params(axis='y', left=False)
        plt.box(False)
        plt.tight_layout()
        plt.savefig(f"../../../../results/graphs/filebench_{benchmark}_{name}_bar_graph.pdf", bbox_inches='tight', pad_inches=0)
        plt.close()