import os
import json
from matplotlib.patches import Patch
import matplotlib.pyplot as plt
import numpy as np
import glob

def read_fio_json_results():
    """
    Reads all FIO JSON result files in the specified directory.
    Returns a list of tuples containing the job name, category, thread count, and the FIO result data.
    """
    results = []
    matched_files = glob.glob(f"../../../../results/*_fio_results_*.json")
    for filename in matched_files:
        # Example filename: REPLICATED_write_direct0_fsync1__threads_16_normal_fio_results_0.json
        # Example filename for Rollbaccine: ROLLBACCINE_randread_direct0__fsync0_threads_4_1_0_default_False_fio_results_2.json
        # Example filename with contention: DM_write_direct1_fsync0_contention_threads_1_normal_fio_results_0.json
        filename_parts = os.path.basename(filename).split('_')
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

        print(f"Reading FIO JSON result file: {filename}")
        lines = []
        with open(filename, 'r+') as f:
            for line in f:
                if not line.startswith("fio: "):
                    lines.append(line)

        data = json.loads(''.join(lines))
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
        if thread_count not in performance_data[base_job_name][category]:
            performance_data[base_job_name][category][thread_count] = {
                'throughput_k': [],
                'lat_ms': []
            }
        performance_data[base_job_name][category][thread_count]['throughput_k'].append(throughput_k)
        performance_data[base_job_name][category][thread_count]['lat_ms'].append(latency_ms)
    return performance_data

def plot_latency_vs_throughput_per_job(performance_data, output_dir):
    config_names = ["UNREPLICATED", "DM", "REPLICATED", "ROLLBACCINE"]
    config_pretty = {
        "UNREPLICATED": "Unreplicated",
        "DM": "DM",
        "REPLICATED": "Replicated",
        "ROLLBACCINE": "Rollbaccine"
    }
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
        plt.figure(figsize=(5, 2))
        ax = plt.gca()
        for category in performance_data[base_job_name]:
            throughputs = []
            bottom_throughputs = []
            top_throughputs = []
            latencies = []
            bottom_latencies = []
            top_latencies = []
            thread_counts = []
            for thread_count in sorted(performance_data[base_job_name][category].keys()):
                metrics = performance_data[base_job_name][category][thread_count]
                repeated_throughputs = metrics['throughput_k']
                repeated_latencies = metrics['lat_ms']
                
                avg_throughput = sum(repeated_throughputs) / len(repeated_throughputs)
                throughputs.append(avg_throughput)
                bottom_throughputs.append(min(repeated_throughputs))
                top_throughputs.append(max(repeated_throughputs))

                avg_latency = sum(repeated_latencies) / len(repeated_latencies)
                latencies.append(avg_latency)
                bottom_latencies.append(min(repeated_latencies))
                top_latencies.append(max(repeated_latencies))

                thread_counts.append(thread_count)
            ax.plot(throughputs, latencies, marker=markers.get(category, 'o'), markersize=10, color=colors.get(category, 'black'), linestyle='-', linewidth=3, label=config_pretty[category])
            # ax.fill_betweenx(latencies, bottom_throughputs, top_throughputs, color = colors.get(category, 'black'), alpha=0.25)
            # ax.fill_between(throughputs, bottom_latencies, top_latencies, color = colors.get(category, 'black'), alpha=0.25)
            
            # Annotate each data point with the number of threads
            for i in range(len(throughputs)):
                ax.annotate(f"{thread_counts[i]}", (throughputs[i], latencies[i]), textcoords="offset points", xytext=(0,-5), ha='center')
        ax.set_xlabel('Throughput (thousands of ops/sec)')
        ax.set_ylabel('Avg Latency (ms)')
        # ax.legend()
        ax.grid(linestyle='-', alpha=0.3, zorder=0)
        # log for x axis if high contention graph
        if 'contention' in base_job_name:
            ax.set_xscale('log')
        # log for y axis
        ax.set_yscale('log')
        plt.tight_layout()
        # Save the figure
        output_file = os.path.join(output_dir, f'{base_job_name}_latency_vs_throughput.pdf')
        plt.savefig(output_file, bbox_inches='tight', pad_inches=0)
        # plt.close()
        print(f"Saved latency vs throughput graph to {output_file}")
    
    # Save the legend
    fig_leg = plt.figure(figsize=(len(markers)*1.5, 0.3))
    ax_leg = fig_leg.add_subplot(111)
    # add the legend from the previous axes
    ax_leg.legend(*ax.get_legend_handles_labels(), loc='center', ncol=len(config_names))
    # hide the axes frame and the x/y labels
    ax_leg.axis('off')
    fig_leg.savefig('../../../../graphs/fio_legend.pdf')

def main():
    # Read the FIO JSON results
    results = read_fio_json_results()
    if not results:
        print("No FIO JSON result files found in the directory.")
        return

    # Extract performance data
    performance_data = extract_performance_data(results)
    print("Performance Data:")
    for job_name, data in performance_data.items():
        print(f"{job_name}: {data}")

    # Create an output directory for graphs
    output_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'graphs')
    os.makedirs(output_dir, exist_ok=True)

    # Plot Latency vs Throughput per job
    plot_latency_vs_throughput_per_job(
        performance_data,
        output_dir=output_dir
    )

if __name__ == "__main__":
    main()