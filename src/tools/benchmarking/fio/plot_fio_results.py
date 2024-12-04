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
            if category not in ['DM', 'UNREPLICATED', 'REPLICATED', 'ROLLBACCINE']:
                print(f"Unknown category '{category}' in filename '{filename}'. Skipping.")
                continue
            try:
                threads_index = filename_parts.index('threads')
                base_job_name_parts = filename_parts[1:threads_index]
                base_job_name = '_'.join(base_job_name_parts)
                thread_count = int(filename_parts[threads_index + 1])
            except ValueError:
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
        rw_name = 'read' if 'read' in rw_option else 'write'

        # Throughput: use 'iops'
        read_iops = job_data[rw_name]['iops']
        # Latency: extract from 'clat_ns'
        latency_percentiles = job_data[rw_name].get('clat_ns', {}).get('percentile', {})
        median_latency_ns = latency_percentiles.get('50.000000')
        if median_latency_ns is None:
            median_latency_ns = job_data[rw_name].get('clat_ns', {}).get('mean', 0)
        # Convert latency from nanoseconds to milliseconds
        median_latency_ms = median_latency_ns / 1e6  # ns to ms
        throughput_k = read_iops / 1000  # Convert to thousands

        if base_job_name not in performance_data:
            performance_data[base_job_name] = {}
        if category not in performance_data[base_job_name]:
            performance_data[base_job_name][category] = {}
        performance_data[base_job_name][category][thread_count] = {
            'throughput_k': throughput_k,
            'median_lat_ms': median_latency_ms
        }
    return performance_data

def plot_latency_vs_throughput_per_job(performance_data, output_dir):
    markers = {
        'DM': 'o',
        'UNREPLICATED': '^',
        'REPLICATED': 's',
        'ROLLBACCINE': 'd'
    }
    colors = {
        'DM': 'cyan',
        'UNREPLICATED': 'red',
        'REPLICATED': 'lime',
        'ROLLBACCINE': 'orange'
    }

    for base_job_name in performance_data:
        plt.figure(figsize=(5, 3))
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
            ax.plot(throughputs, latencies, marker=markers.get(category, 'o'), markersize=10, color=colors.get(category, 'black'), linestyle='-', linewidth=3, label=label)
            # Annotate each data point with the number of threads
            for i in range(len(throughputs)):
                ax.annotate(f"{thread_counts[i]}", (throughputs[i], latencies[i]), textcoords="offset points", xytext=(0,-5), ha='center')
        ax.set_xlabel('Throughput (thousands of commands per second)')
        ax.set_ylabel('Median Latency (ms)')
        ax.set_title(f'{base_job_name} - Median Latency vs Throughput')
        ax.legend()
        ax.grid(True)
        # log for y axis
        ax.set_yscale('log')
        plt.tight_layout()
        # Save the figure
        output_file = os.path.join(output_dir, f'{base_job_name}_latency_vs_throughput.pdf')
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

    # Create an output directory for graphs
    output_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'results', 'graphs')
    os.makedirs(output_dir, exist_ok=True)

    # Plot Latency vs Throughput per job
    plot_latency_vs_throughput_per_job(
        performance_data,
        output_dir=output_dir
    )

if __name__ == "__main__":
    main()