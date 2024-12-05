import matplotlib.pyplot as plt

configs = ["UNREPLICATED", "DM", "REPLICATED", "ROLLBACCINE"]
file_systems = ["ext4", "xfs"]
benchmarks = ["varmail", "webserver"]

def extract_data(file_system, benchmark):
    throughput = []
    latency = []

    for config in configs:
        with open(f"../../../../results/filebench/{config}_{file_system}_{benchmark}.txt", 'r') as file:
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
    for file_system in file_systems:
        for benchmark in benchmarks:
            # Extract throughput and latency data
            throughput, median_latency = extract_data(file_system, benchmark)

            # Plot throughput graph
            plot_bar_graph(
                throughput,
                f"{file_system} {benchmark} Throughput",
                "Throughput (operations/second)",
                f"filebench_{file_system}_{benchmark}_throughput_bar_graph.pdf"
            )

            # Plot median latency graph
            plot_bar_graph(
                median_latency,
                f"{file_system} {benchmark} Latency",
                "Median Latency (microseconds)",
                f"filebench_{file_system}_{benchmark}_latency_bar_graph.pdf"
            )
