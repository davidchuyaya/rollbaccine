import os
import json
import glob
import pandas as pd
import matplotlib.pyplot as plt

def parse_fio_results(result_dir):
    # Initialize a list to hold all the data
    data = []

    # Glob all JSON files in the result directory
    json_files = glob.glob(os.path.join(result_dir, '*_fio_results.json'))
    print(f"Found {len(json_files)} JSON files in {result_dir}")

    for json_file in json_files:
        with open(json_file, 'r') as f:
            fio_result = json.load(f)

        # Extract job name from the filename
        filename = os.path.basename(json_file)
        job_name = filename.replace('_fio_results.json', '')

        # Extract configuration and thread count from the job name
        parts = job_name.split('_threads_')
        if len(parts) < 2:
            print(f"Skipping file {json_file} because it doesn't match the expected pattern")
            continue  # Skip files that don't match the expected pattern
        config_name = parts[0]
        threads_part = parts[1]
        num_threads = int(threads_part.split('_')[0])

        # Assuming single job per file
        job = fio_result['jobs'][0]

        # Check both 'read' and 'write' sections for non-zero io_bytes
        read_io_bytes = job.get('read', {}).get('io_bytes', 0)
        write_io_bytes = job.get('write', {}).get('io_bytes', 0)

        if read_io_bytes > 0:
            io_type = 'read'
            io_data = job['read']
        elif write_io_bytes > 0:
            io_type = 'write'
            io_data = job['write']
        else:
            print(f"Skipping file {json_file} because it doesn't contain read or write data")
            continue  # Skip if neither read nor write data is present

        # Check if bandwidth is present and greater than zero
        bw_kb_s = io_data.get('bw', 0)  # Bandwidth in KB/s, default to 0 if missing
        if bw_kb_s == 0:
            print(f"Skipping file {json_file} because bandwidth is zero")
            continue  # Skip if bandwidth is zero

        bw_mb_s = bw_kb_s / 1024  # Convert KB/s to MB/s

        # Extract median latency from percentiles
        clat_ns = io_data.get('clat_ns', {})
        if 'percentile' in clat_ns and '50.000000' in clat_ns['percentile']:
            median_lat_ns = clat_ns['percentile']['50.000000']
        else:
            median_lat_ns = clat_ns.get('mean', 0)

        lat_ms = median_lat_ns / 1e6  # Convert nanoseconds to milliseconds

        # Append to data list
        data.append({
            'config': config_name,
            'num_threads': num_threads,
            'throughput_mb_s': bw_mb_s,
            'latency_ms': lat_ms,
            'io_type': io_type
        })

    # Convert data to a DataFrame
    df = pd.DataFrame(data)
    return df

def organize_data(df):
    # Sort the DataFrame for consistent plotting
    df_sorted = df.sort_values(by=['config', 'num_threads'])
    return df_sorted

def plot_throughput_latency_per_config(df, output_dir='plots'):
    # Create the output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Get unique configurations
    configs = df['config'].unique()

    for config in configs:
        df_config = df[df['config'] == config]

        plt.figure(figsize=(10, 6))

        # Plot throughput vs. latency for different thread counts
        plt.plot(
            df_config['throughput_mb_s'],
            df_config['latency_ms'],
            marker='o',
            linestyle='-',
            label=f'Threads: {sorted(df_config["num_threads"].unique())}'
        )

        plt.xlabel('Throughput (MB/s)')
        plt.ylabel('Median Latency (ms)')
        plt.title(f'Throughput vs. Median Latency for {config}')
        plt.grid(True)

        # Save the plot to a file
        safe_config_name = config.replace('/', '_')  # Replace any slashes to make a safe filename
        plot_filename = os.path.join(output_dir, f'{safe_config_name}_throughput_latency.png')
        plt.savefig(plot_filename)

        plt.close()  # Close the figure to free memory

        print(f"Plot saved to {plot_filename}")

if __name__ == "__main__":
    # Directory where FIO result JSON files are stored
    result_directory = 'results'

    # Parse FIO results
    df_results = parse_fio_results(result_directory)

    if df_results.empty:
        print("No data found to plot.")
    else:
        # Organize data (sorting)
        df_results_sorted = df_results.sort_values(by=['config', 'num_threads'])

        # Generate and save plots for each configuration
        plot_throughput_latency_per_config(df_results_sorted)