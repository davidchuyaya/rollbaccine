import os
import json
from matplotlib.patches import Patch
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

def get_mean(data):
    return data.get('mean', 0)

def extract_performance_data(results):
    performance_data = {}
    for base_job_name, category, thread_count, job_data in results:
        rw_option = job_data['job options'].get('rw', '')
        fsync_option = job_data['job options'].get('fsync', '0')
        if 'read' in rw_option:
            iops = job_data['read']['iops']
            latency = get_mean(job_data['read'].get('clat_ns', {}))
        else:
            iops = job_data['write']['iops']
            latency = get_mean(job_data['write'].get('clat_ns', {}))
            if fsync_option == '1':
                latency += get_mean(job_data['sync'].get('lat_ns', {}))

        # Convert latency from nanoseconds to milliseconds
        latency_ms = latency / 1e6  # ns to ms
        throughput_k = iops / 1000  # Convert to thousands

        if base_job_name not in performance_data:
            performance_data[base_job_name] = {}
        if category not in performance_data[base_job_name]:
            performance_data[base_job_name][category] = {}
        performance_data[base_job_name][category][thread_count] = {
            'throughput_k': throughput_k,
            'lat_ms': latency_ms
        }
    return performance_data

def plot_latency_vs_throughput_per_job(performance_data, output_dir):
    config_names = ["UNREPLICATED", "DM", "REPLICATED", "ROLLBACCINE"]
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
                throughputs.append(metrics['throughput_k'])
                latencies.append(metrics['lat_ms'])
                thread_counts.append(thread_count)
            label = f"{category}"
            ax.plot(throughputs, latencies, marker=markers.get(category, 'o'), markersize=10, color=colors.get(category, 'black'), linestyle='-', linewidth=3, label=label)
            # Annotate each data point with the number of threads
            for i in range(len(throughputs)):
                ax.annotate(f"{thread_counts[i]}", (throughputs[i], latencies[i]), textcoords="offset points", xytext=(0,-5), ha='center')
        ax.set_xlabel('Throughput (thousands of commands/sec)')
        ax.set_ylabel('Average Latency (ms)')
        # ax.legend()
        ax.grid(True)
        # log for y axis
        ax.set_yscale('log')
        plt.tight_layout()
        # Save the figure
        output_file = os.path.join(output_dir, f'{base_job_name}_latency_vs_throughput.pdf')
        plt.savefig(output_file)
        # plt.close()
        print(f"Saved latency vs throughput graph to {output_file}")
    
    # Save the legend
    fig_leg = plt.figure(figsize=(len(markers)*2, 0.5))
    ax_leg = fig_leg.add_subplot(111)
    # add the legend from the previous axes
    ax_leg.legend(*ax.get_legend_handles_labels(), loc='center', ncol=len(config_names))
    # hide the axes frame and the x/y labels
    ax_leg.axis('off')
    fig_leg.savefig('../../../../results/graphs/fio_legend.pdf')

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