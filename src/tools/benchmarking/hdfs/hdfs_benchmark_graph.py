from matplotlib.patches import Patch
import matplotlib.pyplot as plt
import pandas as pd

# Configuration and operations
config_names = ["UNREPLICATED", "DM", "REPLICATED", "ROLLBACCINE", "NIMBLE_HDFS_100", "NIMBLE_HDFS_1"]

operations = ["create", "mkdirs", "open", "delete", "fileStatus", "rename"]

# Initialize a dictionary to hold throughput data
throughput_data = {config: [] for config in config_names}


def extract_throughput(filename):
    try:
        with open(filename, 'r') as file:
            for line in file:
                if "Ops per sec:" in line:
                    return int(float(line.split("Ops per sec:")[1].strip()))
    except FileNotFoundError:
        return 0  # If the file is missing, return 0


for config in config_names:
    for op in operations:
        filename = f"../../../../results/hdfs/{config}_{op}.txt"
        throughput = extract_throughput(filename)
        throughput_data[config].append(throughput)

# Convert throughput data to a DataFrame
throughput_df = pd.DataFrame(throughput_data, index=operations)

# Plot throughput comparison
plt.figure(figsize=(10, 3))
bar_width = 1.0 / (len(config_names) + 1)  # Width of each bar
x = range(len(operations))
plt.grid(axis='y', linestyle='-', alpha=0.3, zorder=0)

# Generate bars for each configuration
colors = ['red', 'cyan', 'lime', 'orange', 'blue', 'purple']  # Different colors for configurations
patterns = ['/', '\\', '|', '*', 'o', 'x']  # Different patterns for configurations
for i, config in enumerate(config_names):
    plt.bar_label(plt.bar(
        [pos + i * bar_width for pos in x],
        throughput_df[config],
        bar_width,
        label=config,
        color=colors[i % len(colors)],
        hatch=patterns[i % len(patterns)],
        zorder=5
    ), throughput_df[config], zorder=10, rotation=90, padding=5)

# Add labels, title
plt.ylabel("Throughput (ops/sec)")
plt.xticks([pos + bar_width * (len(config_names)-1) / 2 for pos in x], operations)
plt.tick_params(axis='y', left=False)
plt.box(False)
plt.tight_layout()
plt.savefig("../../../../results/graphs/hdfs_throughput_comparison.pdf")
plt.close()

# Save the legend
fig_leg = plt.figure(figsize=(len(config_names)*2, 0.5))
ax_leg = fig_leg.add_subplot(111)
patches = [Patch(facecolor=color, label=label, hatch=pattern) for label, color, pattern in zip(config_names, colors, patterns)]
# add the legend from the previous axes
ax_leg.legend(patches, config_names, loc='center', ncol=len(config_names))
# hide the axes frame and the x/y labels
ax_leg.axis('off')
fig_leg.savefig('../../../../results/graphs/bar_graphs_legend.pdf')