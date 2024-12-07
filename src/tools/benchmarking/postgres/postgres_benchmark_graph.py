import json
import matplotlib.pyplot as plt

configs = ["UNREPLICATED", "DM", "REPLICATED", "ROLLBACCINE"]

# extract data from JSON files and return (throughputs, median_latencies)
def extract_data():
    throughputs = []
    median_latencies = []

    for config in configs:
        with open(f"../../../../results/postgres/{config}_postgres_summary.json", 'r') as file:
            data = json.load(file)

        throughput = data.get("Throughput (requests/second)", 0)
        median_latency = data.get("Latency Distribution", {}).get("Average Latency (microseconds)", 0)

        throughputs.append(int(throughput))
        median_latencies.append(int(median_latency))

    return throughputs, median_latencies


# plot bar graphs
def plot_bar_graph(values, graph_title, performance_metric, filename):
    colors = ['red', 'cyan', 'lime', 'orange', 'blue', 'purple']  # Different colors for configurations
    patterns = ['/', '\\', '|', '*', 'o', 'x']  # Different patterns for configurations
    plt.figure(figsize=(3, 2.5))
    plt.grid(axis='y', linestyle='-', alpha=0.3, zorder=0)
    plt.bar_label(plt.bar(configs, values, color=colors[:len(configs)], hatch=patterns[:len(configs)], width=1.0, zorder=5), values, zorder=10)
    plt.ylabel(performance_metric)
    plt.tick_params(axis='both', left=False, bottom=False)
    plt.xticks(['' for _ in range(len(configs))])
    plt.box(False)
    plt.tight_layout()
    plt.savefig(f"../../../../results/graphs/{filename}")


if __name__ == "__main__":
    # Extract throughput and latency data
    throughput, median_latency = extract_data()

    # Plot throughput graph
    plot_bar_graph(
        throughput,
        "Postgres Throughput per Configuration",
        "Throughput (requests/sec)",
        "postgres_throughput_bar_graph.pdf"
    )

    # Plot median latency graph
    plot_bar_graph(
        median_latency,
        "Postgres Median Latency per Configuration",
        "Average Latency (us)",
        "postgres_latency_bar_graph.pdf"
    )
