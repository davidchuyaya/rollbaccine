import math
from matplotlib.patches import Patch
import matplotlib.pyplot as plt
import pandas as pd
import glob

# Configuration and operations
config_names = ["UNREPLICATED_normal", "DM_normal", "REPLICATED_normal", "ROLLBACCINE_1_0_default_False", "ROLLBACCINE_1_0_sync_False", "NIMBLE_HDFS_100_False", "NIMBLE_HDFS_100_True", "NIMBLE_HDFS_1_False", "NIMBLE_HDFS_1_True"]
operations = ["create", "mkdirs", "open", "delete", "fileStatus", "rename"]

# Initialize a dictionary to hold throughput data
throughput_data = {config: [] for config in config_names}
bottom_throughput_data = {config: [] for config in config_names}
top_throughput_data = {config: [] for config in config_names}

def extract_throughput(config, op):
    matched_files = glob.glob(f"../../../../results/{config}_{op}_*.txt")
    config_throughputs = []
    for matched_file in matched_files:
        with open(matched_file, 'r') as file:
            for line in file:
                if "Ops per sec:" in line:
                    config_throughputs.append(int(float(line.split("Ops per sec:")[1].strip())))

    avg_throughput = sum(config_throughputs) / len(config_throughputs)
    bottom_throughput = avg_throughput - min(config_throughputs)
    top_throughput = max(config_throughputs) - avg_throughput

    return int(avg_throughput), bottom_throughput, top_throughput

for config in config_names:
    for op in operations:
        avg_throughput, bottom_throughput, top_throughput = extract_throughput(config, op)
        throughput_data[config].append(avg_throughput)
        bottom_throughput_data[config].append(bottom_throughput)
        top_throughput_data[config].append(top_throughput)

# Convert throughput data to a DataFrame
throughput_df = pd.DataFrame(throughput_data, index=operations)
bottom_throughput_df = pd.DataFrame(bottom_throughput_data, index=operations)
top_throughput_df = pd.DataFrame(top_throughput_data, index=operations)

# Plot throughput comparison
plt.figure(figsize=(8.5, 2))
bar_width = 1.0 / (len(config_names) + 1)  # Width of each bar
x = range(len(operations))
plt.grid(axis='y', linestyle='-', alpha=0.3, zorder=0)

# Generate bars for each configuration
colors = ['red', 'cyan', 'lime', 'orange', 'saddlebrown', 'blue', 'lightsteelblue', 'purple', 'thistle']  # Different colors for configurations
patterns = ['/', '\\', 'x', '*', '**', 'o', '/o', '\\o', 'o-']  # Different patterns for configurations
for i, config in enumerate(config_names):
    plt.bar_label(plt.bar(
        [pos + i * bar_width for pos in x],
        throughput_df[config],
        width=bar_width,
        label=config,
        color=colors[i % len(colors)],
        hatch=patterns[i % len(patterns)],
        zorder=5,
        alpha=0.99 # Fix bug where hatches don't show up in pdf
    ), throughput_df[config], zorder=10, rotation=90, padding=5)

# Add labels, title
plt.ylabel("Throughput (ops/sec)")
plt.xticks([pos + bar_width * (len(config_names)-1) / 2 for pos in x], operations)
plt.tick_params(axis='y', left=False)
plt.box(False)
plt.tight_layout()
plt.xlim(-0.1, len(operations) - 0.15)
plt.savefig("../../../../graphs/hdfs_throughput_comparison.pdf", bbox_inches='tight', pad_inches=0)
plt.close()

# Save the legend, including configs from postgres that are not used in this benchmark
config_names = ["Unreplicated", "NimbleHDFS-100-Mem", "DM", "NimbleHDFS-100", "Replicated", "NimbleHDFS-1-Mem", "Rollbaccine", "NimbleHDFS-1", "Rollbaccine-sync"]
colors = ['red', 'blue', 'cyan', 'lightsteelblue', 'lime', 'purple', 'orange', 'thistle', 'saddlebrown']
patterns = ['/', 'o', '\\', '/o', 'x', '\\o', '*', 'o-', '**']

fig_leg = plt.figure(figsize=(len(config_names)*0.75, 0.4))
ax_leg = fig_leg.add_subplot(111)
patches = [Patch(facecolor=color, label=label, hatch=pattern, alpha=0.99) for label, color, pattern in zip(config_names, colors, patterns)]
# add the legend from the previous axes
ax_leg.legend(patches, config_names, loc='center', ncol=math.ceil(len(config_names)/2))
# hide the axes frame and the x/y labels
ax_leg.axis('off')
fig_leg.savefig('../../../../graphs/bar_graphs_legend.pdf', bbox_inches='tight', pad_inches=0)