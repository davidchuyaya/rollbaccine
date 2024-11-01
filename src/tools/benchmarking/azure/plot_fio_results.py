import os
import json
import matplotlib.pyplot as plt
import numpy as np

def read_fio_json_results(results_dir):
    """
    Reads all FIO JSON result files in the specified directory.
    Returns a list of tuples containing the job name and the FIO result data.
    """
    results = []
    for filename in os.listdir(results_dir):
        if filename.endswith('.json'):
            filepath = os.path.join(results_dir, filename)
            with open(filepath, 'r') as f:
                data = json.load(f)
                for job in data['jobs']:
                    job_name = job['jobname']
                    results.append((job_name, job))
    return results

def extract_performance_data(results):
    """
    Extracts performance metrics from FIO results.
    Returns a dictionary with job names as keys and performance metrics as values.
    """
    performance_data = {}
    for job_name, job_data in results:
        read_iops = job_data['read']['iops']
        read_bw = job_data['read']['bw']  # Bandwidth in KB/s
        read_lat = job_data['read']['lat_ns']['mean'] / 1000  # Convert to microseconds
        write_iops = job_data['write']['iops']
        write_bw = job_data['write']['bw']  # Bandwidth in KB/s
        write_lat = job_data['write']['lat_ns']['mean'] / 1000  # Convert to microseconds

        performance_data[job_name] = {
            'read_iops': read_iops,
            'read_bw': read_bw,
            'read_lat_us': read_lat,
            'write_iops': write_iops,
            'write_bw': write_bw,
            'write_lat_us': write_lat
        }
    return performance_data

def plot_bar_graph(performance_data, metric, title, ylabel, output_file):
    """
    Plots a bar graph for the specified performance metric.
    """
    job_names = list(performance_data.keys())
    values = [performance_data[job][metric] for job in job_names]

    x_pos = np.arange(len(job_names))

    plt.figure(figsize=(10, 6))
    bars = plt.bar(x_pos, values, align='center', alpha=0.7)
    plt.xticks(x_pos, job_names, rotation=45, ha='right')
    plt.xlabel('FIO Jobs')
    plt.ylabel(ylabel)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()
    print(f"Saved bar graph to {output_file}")

def main():
    # Directory where the FIO JSON results are stored
    results_dir = './results'  # Adjust this path if needed

    # Read the FIO JSON results
    results = read_fio_json_results(results_dir)

    if not results:
        print("No FIO JSON result files found in the directory.")
        return

    # Extract performance data
    performance_data = extract_performance_data(results)
    print(performance_data)

    # Create an output directory for graphs
    output_dir = './graphs'
    os.makedirs(output_dir, exist_ok=True)

    # Plot Read IOPS
    plot_bar_graph(
        performance_data,
        metric='read_iops',
        title='Read IOPS per FIO Job',
        ylabel='IOPS',
        output_file=os.path.join(output_dir, 'read_iops_bar_graph.png')
    )

    # Plot Write IOPS
    plot_bar_graph(
        performance_data,
        metric='write_iops',
        title='Write IOPS per FIO Job',
        ylabel='IOPS',
        output_file=os.path.join(output_dir, 'write_iops_bar_graph.png')
    )

    # Plot Read Bandwidth
    plot_bar_graph(
        performance_data,
        metric='read_bw',
        title='Read Bandwidth per FIO Job',
        ylabel='Bandwidth (KB/s)',
        output_file=os.path.join(output_dir, 'read_bandwidth_bar_graph.png')
    )

    # Plot Write Bandwidth
    plot_bar_graph(
        performance_data,
        metric='write_bw',
        title='Write Bandwidth per FIO Job',
        ylabel='Bandwidth (KB/s)',
        output_file=os.path.join(output_dir, 'write_bandwidth_bar_graph.png')
    )

    # Plot Read Latency
    plot_bar_graph(
        performance_data,
        metric='read_lat_us',
        title='Read Latency per FIO Job',
        ylabel='Latency (μs)',
        output_file=os.path.join(output_dir, 'read_latency_bar_graph.png')
    )

    # Plot Write Latency
    plot_bar_graph(
        performance_data,
        metric='write_lat_us',
        title='Write Latency per FIO Job',
        ylabel='Latency (μs)',
        output_file=os.path.join(output_dir, 'write_latency_bar_graph.png')
    )

if __name__ == "__main__":
    main()