import json
import matplotlib.pyplot as plt

# assume file path ordered as: [unreplicated, dm, replicated, rollbaccine]
file_paths = [
    "tpcc_2024-11-28_23-57-55.summary.json",
    "tpcc_1.json",
    "tpcc_2.json",
    "tpcc_3.json"
]
config_names = ["unreplicated", "dm", "replicated", "rollbaccine"]
figure_width = 5
figure_height = 4

# extract data from JSON files and return (throughputs, median_latencies)
def extract_data(json_file_paths: str) -> (list, list):
    throughputs = []
    median_latencies = []

    for file_path in json_file_paths:
        with open(file_path, 'r') as file:
            data = json.load(file)

        throughput = data.get("Throughput (requests/second)", 0)
        median_latency = data.get("Latency Distribution", {}).get("Median Latency (microseconds)", 0)

        throughputs.append(throughput)
        median_latencies.append(median_latency)

    return throughputs, median_latencies


# plot bar graphs
def plot_bar_graph(labels, values, graph_title, performance_metric, filename):
    colors = ['lightcoral', 'wheat', 'darkseagreen', 'powderblue']  # Different colors for configurations
    plt.figure(figsize=(figure_width, figure_height))
    plt.bar(labels, values, color=colors[:len(labels)])
    plt.title(graph_title)
    plt.ylabel(performance_metric)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(filename)
    plt.show()


if __name__ == "__main__":
    # Extract throughput and latency data
    throughput, median_latency = extract_data(file_paths)

    # Plot throughput graph
    plot_bar_graph(
        config_names,
        throughput,
        "Postgres Throughput per Configuration",
        "Throughput (requests/second)",
        "postgres_throughput_bar_graph.png"
    )

    # Plot median latency graph
    plot_bar_graph(
        config_names, median_latency,
        "Postgres Median Latency per Configuration",
        "Median Latency (microseconds)",
        "postgres_latency_bar_graph.png"
    )
