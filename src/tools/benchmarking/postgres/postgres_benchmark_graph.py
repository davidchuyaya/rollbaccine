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
        median_latency = data.get("Latency Distribution", {}).get("Median Latency (microseconds)", 0)

        throughputs.append(throughput)
        median_latencies.append(median_latency)

    return throughputs, median_latencies


# plot bar graphs
def plot_bar_graph(values, graph_title, performance_metric, filename):
    colors = ['red', 'cyan', 'lime', 'orange']  # Different colors for configurations
    plt.figure(figsize=(5, 4))
    plt.bar(configs, values, color=colors[:len(configs)])
    plt.title(graph_title)
    plt.ylabel(performance_metric)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(f"../../../../results/graphs/{filename}")


if __name__ == "__main__":
    # Extract throughput and latency data
    throughput, median_latency = extract_data()

    # Plot throughput graph
    plot_bar_graph(
        throughput,
        "Postgres Throughput per Configuration",
        "Throughput (requests/second)",
        "postgres_throughput_bar_graph.pdf"
    )

    # Plot median latency graph
    plot_bar_graph(
        median_latency,
        "Postgres Median Latency per Configuration",
        "Median Latency (microseconds)",
        "postgres_latency_bar_graph.pdf"
    )
