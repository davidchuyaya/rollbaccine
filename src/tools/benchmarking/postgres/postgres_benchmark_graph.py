import json
import glob
import matplotlib.pyplot as plt

configs = ["UNREPLICATED_normal", "DM_normal", "REPLICATED_normal",
 "ROLLBACCINE_1_0_default_False", # Regular rollbaccine
 "ROLLBACCINE_1_0_sync_False", # All sync
 "ROLLBACCINE_0_0_default_False", "ROLLBACCINE_2_0_default_False", # Different f
 "ROLLBACCINE_1_614400_default_False", "ROLLBACCINE_1_616774_default_False", # Different merkle tree heights
]

# extract data from JSON files and return (throughputs, median_latencies)
def extract_data():
    throughputs = []
    bottom_throughputs = []
    top_throughputs = []
    latencies = []
    bottom_latencies = []
    top_latencies = []

    for config in configs:
        matched_files = glob.glob(f"../../../../results/{config}_tpcc_*.json")
        config_throughputs = []
        config_latencies = []
        for matched_file in matched_files:
            with open(matched_file, 'r') as file:
                data = json.load(file)

            throughput = data.get("Throughput (requests/second)", 0)
            median_latency = data.get("Latency Distribution", {}).get("Average Latency (microseconds)", 0)

            config_throughputs.append(int(throughput))
            config_latencies.append(int(median_latency))

        if not config_throughputs:
            continue
        
        avg_throughput = int(sum(config_throughputs) / len(config_throughputs))
        throughputs.append(avg_throughput)
        bottom_throughputs.append(avg_throughput - min(config_throughputs))
        top_throughputs.append(max(config_throughputs) - avg_throughput)

        avg_latency = int(sum(config_latencies) / len(config_latencies))
        latencies.append(avg_latency)
        bottom_latencies.append(avg_latency - min(config_latencies))
        top_latencies.append(max(config_latencies) - avg_latency)
        

    return throughputs, bottom_throughputs, top_throughputs, latencies, bottom_latencies, top_latencies


# plot bar graphs
def plot_bar_graph(avg, bottom, top, graph_title, performance_metric, filename):
    colors = ['red', 'cyan', 'lime', 'orange', 'peru', 'gold', 'yellow', 'khaki', 'navajowhite']  # Different colors for configurations
    patterns = ['/', '\\', 'x', '*', '*/', '\\*', 'x*', '*-', '*.']  # Different patterns for configurations
    plt.figure(figsize=(3, 2))
    plt.grid(axis='y', linestyle='-', alpha=0.3, zorder=0)
    plt.bar_label(plt.bar(configs, avg, yerr=(bottom, top), color=colors[:len(configs)], hatch=patterns[:len(configs)], width=1.0, zorder=5), avg, zorder=10, rotation=90)
    plt.ylabel(performance_metric)
    plt.tick_params(axis='both', left=False, bottom=False)
    plt.xticks(['' for _ in range(len(configs))])
    plt.box(False)
    plt.tight_layout()
    plt.savefig(f"../../../../results/graphs/{filename}", bbox_inches='tight', pad_inches=0)


if __name__ == "__main__":
    # Extract throughput and latency data
    throughputs, bottom_throughputs, top_throughputs, latencies, bottom_latencies, top_latencies = extract_data()

    # Plot throughput graph
    plot_bar_graph(
        throughputs,
        bottom_throughputs,
        top_throughputs,
        "Postgres Throughput per Configuration",
        "Throughput (ops/sec)",
        "postgres_throughput_bar_graph.pdf"
    )

    # Plot median latency graph
    plot_bar_graph(
        latencies,
        bottom_latencies,
        top_latencies,
        "Postgres Median Latency per Configuration",
        "Avg Latency (us)",
        "postgres_latency_bar_graph.pdf"
    )
