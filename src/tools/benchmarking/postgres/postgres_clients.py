import os
import json
from matplotlib.patches import Patch
import matplotlib.pyplot as plt
import numpy as np
import glob

configs = ["UNREPLICATED_normal", "DM_normal", "REPLICATED_normal",
 "ROLLBACCINE_1_0_default_False", # Regular rollbaccine
 "ROLLBACCINE_1_0_sync_False", # All sync
 "ROLLBACCINE_0_0_default_False", "ROLLBACCINE_2_0_default_False", # Different f
 "ROLLBACCINE_1_614400_default_False", "ROLLBACCINE_1_616774_default_False", # Different merkle tree heights
]

def throughputs_latencies():
    avg_throughputs = dict()
    bottom_throughputs = dict()
    top_throughputs = dict()
    avg_latencies = dict()
    bottom_latencies = dict()
    top_latencies = dict()

    for config in configs:
        matched_files = glob.glob(f"../../../../results/{config}_tpcc_*.json")
        config_throughputs = dict()
        config_latencies = dict()
        for matched_file in matched_files:
            with open(matched_file, 'r') as file:
                data = json.load(file)

            throughput = data.get("Throughput (requests/second)", 0)
            latency = data.get("Latency Distribution", {}).get("Average Latency (microseconds)", 0)
            num_clients = int(data.get("terminals", "0"))

            if config_throughputs.get(num_clients) is None:
                config_throughputs[num_clients] = []
            if config_latencies.get(num_clients) is None:
                config_latencies[num_clients] = []
            config_throughputs[num_clients].append(throughput)
            config_latencies[num_clients].append(latency)

        avg_throughputs[config] = dict()
        bottom_throughputs[config] = dict()
        top_throughputs[config] = dict()
        avg_latencies[config] = dict()
        bottom_latencies[config] = dict()
        top_latencies[config] = dict()

        for num_clients in config_throughputs.keys():
            avg_throughput = int(sum(config_throughputs[num_clients]) / len(config_throughputs[num_clients]))
            avg_throughputs[config][num_clients] = avg_throughput
            bottom_throughputs[config][num_clients] = avg_throughput - min(config_throughputs[num_clients])
            top_throughputs[config][num_clients] = max(config_throughputs[num_clients]) - avg_throughput

            avg_latency = int(sum(config_latencies[num_clients]) / len(config_latencies[num_clients]))
            avg_latencies[config][num_clients] = avg_latency
            bottom_latencies[config][num_clients] = avg_latency - min(config_latencies[num_clients])
            top_latencies[config][num_clients] = max(config_latencies[num_clients]) - avg_latency

    return avg_throughputs, bottom_throughputs, top_throughputs, avg_latencies, bottom_latencies, top_latencies

def plot_latency_vs_throughput(throughputs, latencies):
    colors = ['red', 'cyan', 'lime', 'orange', 'peru', 'gold', 'yellow', 'khaki', 'navajowhite']  # Different colors for configurations

    plt.figure(figsize=(5, 5))
    ax = plt.gca()
    for i, config in enumerate(configs):
        cat_throughputs = []
        cat_latencies = []
        for num_clients in sorted(throughputs[config].keys()):
            cat_throughputs.append(throughputs[config][num_clients])
            cat_latencies.append(latencies[config][num_clients])
            # Annotate each data point with the number of clients
            ax.annotate(f"{num_clients}", (throughputs[config][num_clients], latencies[config][num_clients]), textcoords="offset points", xytext=(0,-5), ha='center')
        ax.plot(cat_throughputs, cat_latencies, marker=i, markersize=10, color=colors[i], linestyle='-', linewidth=3, label=config)
            
    ax.set_xlabel('Throughput (thousands of commands/sec)')
    ax.set_ylabel('Average Latency (us)')
    ax.legend(loc='upper center', bbox_to_anchor=(0.5, 1.2), ncol=4)
    ax.grid(True)
    plt.tight_layout()
    # Save the figure
    output_file = os.path.join(".", f'postgres_latency_vs_throughput.pdf')
    plt.savefig(output_file, bbox_inches='tight', pad_inches=0)
    # plt.close()
    print(f"Saved latency vs throughput graph to {output_file}")

def main():
    avg_throughputs, bottom_throughputs, top_throughputs, avg_latencies, bottom_latencies, top_latencies = throughputs_latencies()

    # Plot Latency vs Throughput per job
    plot_latency_vs_throughput(
        avg_throughputs,
        avg_latencies,
    )

if __name__ == "__main__":
    main()