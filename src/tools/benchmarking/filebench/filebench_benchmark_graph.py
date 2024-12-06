import matplotlib.pyplot as plt
import pandas as pd

configs = ["UNREPLICATED", "DM", "REPLICATED", "ROLLBACCINE"]
file_systems = ["ext4", "xfs"]
benchmarks = ["varmail", "webserver"]

# Returns throughput, latency
def extract_data(filename):
    with open(filename, 'r') as file:
        for line in file:
            if "IO Summary:" in line:
                words = line.split()
                return int(float(words[5])), float(words[-1].replace("ms/op", ""))

for benchmark in benchmarks:
    throughputs = {config: [] for config in configs}
    latencies = {config: [] for config in configs}

    for config in configs:
        for file_system in file_systems:
            filename = f"../../../../results/filebench/{config}_{file_system}_{benchmark}.txt"
            throughput, latency = extract_data(filename)
            throughputs[config].append(throughput)
            latencies[config].append(latency)

    throughput_df = pd.DataFrame(throughputs, index=file_systems)
    latency_df = pd.DataFrame(latencies, index=file_systems)

    # Plot throughput and latency comparisons
    for (df, axis, name) in [(throughput_df, "Throughput (ops/sec)", "throughput"), (latency_df, "Median Latency (us)", "latency")]:
        plt.figure(figsize=(5, 3))
        bar_width = 1.0 / (len(configs) + 1)  # Width of each bar
        x = range(len(file_systems))
        plt.grid(axis='y', linestyle='-', alpha=0.3, zorder=0)

        # Generate bars for each configuration
        colors = ['red', 'cyan', 'lime', 'orange', 'blue', 'purple']  # Different colors for configurations
        patterns = ['/', '\\', '|', '*', 'o', 'x']  # Different patterns for configurations
        for i, config in enumerate(configs):
            plt.bar_label(plt.bar(
                [pos + i * bar_width for pos in x],
                df[config],
                bar_width,
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
        plt.savefig(f"../../../../results/graphs/filebench_{benchmark}_{name}_bar_graph.pdf")
        plt.close()