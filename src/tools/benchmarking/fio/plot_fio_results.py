import os
import json
import matplotlib.pyplot as plt
import numpy as np

def read_fio_json_results(results_dir):
    """
    Reads all FIO JSON result files in the specified directory.
    Returns a list of tuples containing the job name, category (normal_disk or rollbaccine), and the FIO result data.
    """
    results = []
    for filename in os.listdir(results_dir):
        if filename.endswith('.json'):
            filepath = os.path.join(results_dir, filename)
            # Determine the category based on filename
            if filename.startswith('normal_disk_'):
                category = 'normal_disk'
                base_job_name = filename[len('normal_disk_'):-len('_fio_results.json')]
            else:
                category = 'rollbaccine'
                base_job_name = filename[:-len('_fio_results.json')]
            with open(filepath, 'r') as f:
                data = json.load(f)
                for job in data['jobs']:
                    job_name = job['jobname']
                    results.append((base_job_name, category, job))
    return results

def extract_performance_data(results):
    """
    Extracts performance metrics from FIO results.
    Returns a nested dictionary with base job names as keys and performance metrics as values for both categories.
    """
    performance_data = {}
    for base_job_name, category, job_data in results:
        read_iops = job_data['read']['iops']
        read_bw = job_data['read']['bw']  # Bandwidth in KB/s
        read_lat = job_data['read']['lat_ns']['mean'] / 1000  # Convert to microseconds
        read_throughput = job_data['read']['bw_bytes'] / (1024 * 1024)  # Convert to MB/s
        write_iops = job_data['write']['iops']
        write_bw = job_data['write']['bw']  # Bandwidth in KB/s
        write_lat = job_data['write']['lat_ns']['mean'] / 1000  # Convert to microseconds
        write_throughput = job_data['write']['bw_bytes'] / (1024 * 1024)  # Convert to MB/s

        if base_job_name not in performance_data:
            performance_data[base_job_name] = {}

        performance_data[base_job_name][category] = {
            'read_iops': read_iops,
            'read_bw': read_bw,
            'read_lat_us': read_lat,
            'read_throughput_mbs': read_throughput,
            'write_iops': write_iops,
            'write_bw': write_bw,
            'write_lat_us': write_lat,
            'write_throughput_mbs': write_throughput
        }
    return performance_data

def plot_grouped_bar_graph(performance_data, metric, title, ylabel, output_file):
    """
    Plots a grouped bar chart for the specified performance metric.
    """
    categories = ['normal_disk', 'rollbaccine']
    job_names = list(performance_data.keys())
    num_jobs = len(job_names)
    num_categories = len(categories)

    # Prepare data
    data = {category: [] for category in categories}
    for job_name in job_names:
        for category in categories:
            if category in performance_data[job_name]:
                data[category].append(performance_data[job_name][category].get(metric, 0))
            else:
                data[category].append(0)

    x = np.arange(num_jobs)  # the label locations
    width = 0.35  # the width of the bars

    plt.figure(figsize=(12, 6))
    fig, ax = plt.subplots()
    rects_list = []

    # Plot bars for each category
    for idx, category in enumerate(categories):
        offset = (idx - (num_categories - 1) / 2) * width
        rects = ax.bar(x + offset, data[category], width, label=category)
        rects_list.append(rects)

    # Add labels, title, and custom x-axis tick labels, etc.
    ax.set_xlabel('FIO Jobs')
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_xticklabels(job_names, rotation=45, ha='right')
    ax.legend()

    # Attach a text label above each bar in rects, displaying its height
    def autolabel(rects):
        for rect in rects:
            height = rect.get_height()
            if height != 0:
                ax.annotate('{}'.format(int(height)),
                            xy=(rect.get_x() + rect.get_width() / 2, height),
                            xytext=(0, 3),  # 3 points vertical offset
                            textcoords="offset points",
                            ha='center', va='bottom')

    for rects in rects_list:
        autolabel(rects)

    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()
    print(f"Saved grouped bar graph to {output_file}")

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
    print("Performance Data:")
    for job_name, data in performance_data.items():
        print(f"{job_name}: {data}")

    # Create an output directory for graphs
    output_dir = './graphs'
    os.makedirs(output_dir, exist_ok=True)

    # Plot Read IOPS
    plot_grouped_bar_graph(
        performance_data,
        metric='read_iops',
        title='Read IOPS per FIO Job',
        ylabel='IOPS',
        output_file=os.path.join(output_dir, 'read_iops_grouped_bar_graph.png')
    )

    # Plot Write IOPS
    plot_grouped_bar_graph(
        performance_data,
        metric='write_iops',
        title='Write IOPS per FIO Job',
        ylabel='IOPS',
        output_file=os.path.join(output_dir, 'write_iops_grouped_bar_graph.png')
    )

    # Plot Read Bandwidth
    plot_grouped_bar_graph(
        performance_data,
        metric='read_bw',
        title='Read Bandwidth per FIO Job',
        ylabel='Bandwidth (KB/s)',
        output_file=os.path.join(output_dir, 'read_bandwidth_grouped_bar_graph.png')
    )

    # Plot Write Bandwidth
    plot_grouped_bar_graph(
        performance_data,
        metric='write_bw',
        title='Write Bandwidth per FIO Job',
        ylabel='Bandwidth (KB/s)',
        output_file=os.path.join(output_dir, 'write_bandwidth_grouped_bar_graph.png')
    )

    # Plot Read Latency
    plot_grouped_bar_graph(
        performance_data,
        metric='read_lat_us',
        title='Read Latency per FIO Job',
        ylabel='Latency (μs)',
        output_file=os.path.join(output_dir, 'read_latency_grouped_bar_graph.png')
    )

    # Plot Write Latency
    plot_grouped_bar_graph(
        performance_data,
        metric='write_lat_us',
        title='Write Latency per FIO Job',
        ylabel='Latency (μs)',
        output_file=os.path.join(output_dir, 'write_latency_grouped_bar_graph.png')
    )

    # Plot Read Throughput
    plot_grouped_bar_graph(
        performance_data,
        metric='read_throughput_mbs',
        title='Read Throughput per FIO Job',
        ylabel='Throughput (MB/s)',
        output_file=os.path.join(output_dir, 'read_throughput_grouped_bar_graph.png')
    )

    # Plot Write Throughput
    plot_grouped_bar_graph(
        performance_data,
        metric='write_throughput_mbs',
        title='Write Throughput per FIO Job',
        ylabel='Throughput (MB/s)',
        output_file=os.path.join(output_dir, 'write_throughput_grouped_bar_graph.png')
    )

if __name__ == "__main__":
    main()