import matplotlib.pyplot as plt

# assume file path ordered as: [unreplicated, dm, replicated, rollbaccine]
file_paths = [
    "DM_ext1_varmail.txt",
    "DM_ext2_varmail.txt",
    "DM_ext3_varmail.txt",
    "DM_ext4_varmail.txt"
]
config_names = ["unreplicated", "dm", "replicated", "rollbaccine"]
figure_width = 5
figure_height = 4


def extract_data(datafile_paths: list[str]) -> (list, list):
    throughput = []
    latency = []

    for path in datafile_paths:
        with open(path, 'r') as file:
            for line in file:
                # Extract throughput (ops/s)
                if "IO Summary:" in line:
                    words = line.split()
                    ops_per_sec = float(words[5])
                    # print(ops_per_sec)
                    throughput.append(ops_per_sec)

                # Extract average latency (ms/op)
                if "IO Summary:" in line:
                    words = line.split()
                    avg_latency = float(words[-1].replace("ms/op", ""))
                    latency.append(avg_latency)

    return throughput, latency


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
        "Filebench Throughput per Configuration",
        "Throughput (operations/second)",
        "filebench_throughput_bar_graph.png"
    )

    # Plot median latency graph
    plot_bar_graph(
        config_names, median_latency,
        "Filebench Median Latency per Configuration",
        "Median Latency (microseconds)",
        "filebench_latency_bar_graph.png"
    )
