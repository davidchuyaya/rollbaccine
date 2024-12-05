import matplotlib.pyplot as plt
import pandas as pd

# Configuration and operations
config_names = ["UNREPLICATED", "DM", "REPLICATED", "ROLLBACCINE"]

operations = ["create", "mkdirs", "open", "delete", "fileStatus", "rename"]

# Initialize a dictionary to hold throughput data
throughput_data = {config: [] for config in config_names}


def extract_throughput(filename):
    try:
        with open(filename, 'r') as file:
            for line in file:
                if "Ops per sec:" in line:
                    return float(line.split("Ops per sec:")[1].strip())
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
plt.figure(figsize=(10, 6))
bar_width = 1.0 / (len(config_names) + 1)  # Width of each bar
x = range(len(operations))

# Generate bars for each configuration
colors = ['red', 'cyan', 'lime', 'orange']  # Different colors for configurations
for i, config in enumerate(config_names):
    plt.bar(
        [pos + i * bar_width for pos in x],
        throughput_df[config],
        bar_width,
        label=config.capitalize(),
        color=colors[i % len(colors)]  # Cycle through colors if needed
    )

# Add labels, title, and legend
plt.xlabel("Operations")
plt.ylabel("Throughput (ops/sec)")
plt.title("HDFS Throughput Comparison")
plt.xticks([pos + bar_width for pos in x], operations, rotation=45)
plt.legend()
plt.tight_layout()
plt.savefig("../../../../results/graphs/hdfs_throughput_comparison.pdf")
