import os
import json
import matplotlib.pyplot as plt
import numpy as np

def read_fio_json_results(results_dir):
    """
    Reads all FIO JSON result files in the specified directory.
    Returns a list of tuples containing the job name, category, thread count, and the FIO result data.
    """
    results = []
    for filename in os.listdir(results_dir):
        if filename.endswith('.json'):
            filepath = os.path.join(results_dir, filename)
            # Example filename: DM_rand_read_direct0_fsync0_threads_16_8ef3_fio_results.json
            filename_without_extension = filename[:-len('_fio_results.json')]
            filename_parts = filename_without_extension.split('_')
            # Extract the category (e.g., 'DM', 'UNREPLICATED', 'REPLICATED', 'ROLLBACCINE')
            category = filename_parts[0]
            try:
                threads_index = filename_parts.index('threads')
                base_job_name_parts = filename_parts[1:threads_index]
                base_job_name = '_'.join(base_job_name_parts)
                thread_count = int(filename_parts[threads_index + 1])
            except ValueError:
                # Handle error if 'threads' is not in filename_parts
                print(f"Error parsing filename {filename}")
                continue

            with open(filepath, 'r') as f:
                data = json.load(f)
                for job in data['jobs']:
                    job_name = job['jobname']
                    results.append((base_job_name, category, thread_count, job))
    return results

def extract_performance_data(results):
    performance_data = {}
    for base_job_name, category, thread_count, job_data in results:
        rw_option = job_data['job options'].get('rw', '')
        is_read = 'read' in rw_option
        is_write = 'write' in rw_option

        if is_read:
            # Throughput: use 'iops' from 'read'
            read_iops = job_data['read']['iops']
            # Latency: extract from 'read' -> 'clat_ns'
            latency_percentiles = job_data['read'].get('clat_ns', {}).get('percentile', {})
            median_latency_ns = latency_percentiles.get('50.000000')
            if median_latency_ns is None:
                median_latency_ns = job_data['read'].get('clat_ns', {}).get('mean', 0)
            # Convert latency from nanoseconds to milliseconds
            median_latency_ms = median_latency_ns / 1e6  # ns to ms
            throughput_k = read_iops / 1000  # Convert to thousands

        elif is_write:
            # Throughput: use 'iops' from 'write'
            write_iops = job_data['write']['iops']
            # Check if 'fsync' is enabled in job options
            fsync_enabled = job_data['job options'].get('fsync', '0') == '1'

            # Latency: extract from 'sync' if 'fsync' is enabled, else from 'write'
            if fsync_enabled and 'sync' in job_data and 'lat_ns' in job_data['sync']:
                latency_percentiles = job_data['sync']['lat_ns'].get('percentile', {})
                median_latency_ns = latency_percentiles.get('50.000000')
                if median_latency_ns is None:
                    median_latency_ns = job_data['sync']['lat_ns'].get('mean', 0)
            else:
                latency_percentiles = job_data['write'].get('clat_ns', {}).get('percentile', {})
                median_latency_ns = latency_percentiles.get('50.000000')
                if median_latency_ns is None:
                    median_latency_ns = job_data['write'].get('clat_ns', {}).get('mean', 0)
            # Convert latency from nanoseconds to milliseconds
            median_latency_ms = median_latency_ns / 1e6  # ns to ms
            throughput_k = write_iops / 1000  # Convert to thousands
        else:
            print(f"Unknown rw option '{rw_option}' in job '{job_data['jobname']}'. Skipping.")
            continue

        if base_job_name not in performance_data:
            performance_data[base_job_name] = {}
        if category not in performance_data[base_job_name]:
            performance_data[base_job_name][category] = {}
        performance_data[base_job_name][category][thread_count] = {
            'throughput_k': throughput_k,
            'median_lat_ms': median_latency_ms
        }
    return performance_data

def plot_latency_vs_throughput_per_job(performance_data, output_dir, markers, colors):
    for base_job_name in performance_data:
        plt.figure(figsize=(10, 6))
        ax = plt.gca()
        for category in performance_data[base_job_name]:
            throughputs = []
            latencies = []
            thread_counts = []
            for thread_count in sorted(performance_data[base_job_name][category].keys()):
                metrics = performance_data[base_job_name][category][thread_count]
                throughput = metrics['throughput_k']
                latency = metrics['median_lat_ms']
                throughputs.append(throughput)
                latencies.append(latency)
                thread_counts.append(thread_count)
            label = f"{category}"
            ax.plot(throughputs, latencies, marker=markers.get(category, 'o'), color=colors.get(category, 'black'), linestyle='-', label=label)
            # Annotate each data point with the number of threads
            for i in range(len(throughputs)):
                ax.annotate(f"{thread_counts[i]}", (throughputs[i], latencies[i]), textcoords="offset points", xytext=(0,10), ha='center')
        ax.set_xlabel('Throughput (thousands of commands per second)')
        ax.set_ylabel('Median Latency (ms)')
        ax.set_title(f'{base_job_name} - Median Latency vs Throughput')
        ax.legend()
        ax.grid(True)
        plt.tight_layout()
        # Save the figure
        output_file = os.path.join(output_dir, f'{base_job_name}_latency_vs_throughput.png')
        plt.savefig(output_file)
        plt.close()
        print(f"Saved latency vs throughput graph to {output_file}")

def main():
    # Directory where the FIO JSON results are stored
    results_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'results', 'fio')

    # Read the FIO JSON results
    results = read_fio_json_results(results_dir)

    if not results:
        print("No FIO JSON result files found in the directory.")
        return

    # Extract performance data
    performance_data = extract_performance_data(results)
    print("Performance Data:")
    for job_name, data in performance_data.items():
        print(f"{job_name}: {data}")

    # Collect categories
    categories = set()
    for base_job_name in performance_data:
        categories.update(performance_data[base_job_name].keys())

    categories = sorted(categories)
    markers_list = ['o', '^', 's', 'd', '*', '+', 'x', 'v', '<', '>', 'p', 'h']
    colors_list = ['blue', 'red', 'green', 'orange', 'purple', 'brown', 'pink', 'gray', 'olive', 'cyan', 'magenta', 'yellow']

    # Ensure we have enough markers and colors
    if len(categories) > len(markers_list):
        print("Not enough markers to assign to categories.")
        return

    if len(categories) > len(colors_list):
        print("Not enough colors to assign to categories.")
        return

    markers = {}
    colors = {}
    for idx, category in enumerate(categories):
        markers[category] = markers_list[idx % len(markers_list)]
        colors[category] = colors_list[idx % len(colors_list)]

    # Create an output directory for graphs
    output_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'results', 'graphs')
    os.makedirs(output_dir, exist_ok=True)

    # Plot Latency vs Throughput per job
    plot_latency_vs_throughput_per_job(
        performance_data,
        output_dir=output_dir,
        markers=markers,
        colors=colors
    )

if __name__ == "__main__":
    main()