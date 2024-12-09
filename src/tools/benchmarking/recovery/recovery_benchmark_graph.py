import json
import matplotlib.pyplot as plt
from enum import Enum

class Mode(Enum):
    NORMAL = 1
    RECEIVING_HASHES = 2
    SCANNING_DISK = 3
    
    def __str__(self):
        return f'{self.name}'

def extract_data(filename: str):
    times = [] 
    throughputs = []
    crash_start = 0
    hash_receive_start = 0
    hash_receive_end = 0
    disk_scan_end = 0
    mode = Mode.NORMAL

    start_time = 0
    curr_time = 0
    prev_write_index = -1
    with open(f"../../../../results/recovery/{filename}", 'r') as file:
        for line in file:
            line = line.strip()

            if "Time" in line:
                curr_time = float(line.split("Time: ")[1]) - start_time
                if start_time == 0:
                    start_time = curr_time
                if mode == Mode.RECEIVING_HASHES and hash_receive_start == 0:
                    hash_receive_start = curr_time
            elif "Latest write index" in line:
                new_write_index = int(line.split("Latest write index: ")[1])
                if prev_write_index != -1 and mode == Mode.NORMAL:
                    diff = new_write_index - prev_write_index
                    times.append(curr_time)
                    throughputs.append(diff)
                prev_write_index = new_write_index
            elif "Recovery time" in line:
                times.append(curr_time)
                throughputs.append(0)
                crash_start = curr_time
                mode = Mode.RECEIVING_HASHES
            elif "Hashes received during recovery: 1258287104, total sectors: 1258287104" in line and hash_receive_end == 0:
                hash_receive_end = curr_time
                mode = Mode.SCANNING_DISK
            elif "ballot 3, seen_ballot: 3" in line and disk_scan_end == 0:
                disk_scan_end = curr_time
                mode = Mode.NORMAL

    return times, throughputs, crash_start, hash_receive_start, hash_receive_end, disk_scan_end


# plot bar graphs
def plot_time_series(filename, times, throughputs, crash_start, hash_receive_start, hash_receive_end, disk_scan_end):
    fig, ax = plt.subplots(figsize=(5, 2))
    plt.plot(times, throughputs)
    plt.ylabel("Writes per sec")
    plt.xlabel("Time (sec)")
    plt.axvline(x=crash_start, color='black', ls=":")
    plt.text(crash_start + 10, 0.99, 'Crash', rotation=90, ha='left', va='top', transform=ax.get_xaxis_transform())
    plt.axvline(x=hash_receive_start, color='black', ls=":")
    plt.text(hash_receive_start + 10, 0.99, 'Restarted', rotation=90, ha='left', va='top', transform=ax.get_xaxis_transform())
    plt.axvline(x=hash_receive_end, color='black', ls=":")
    plt.text(hash_receive_end + 10, 0.99, 'Hashes received', rotation=90, ha='left', va='top', transform=ax.get_xaxis_transform())
    plt.axvline(x=disk_scan_end, color='black', ls=":")
    plt.text(disk_scan_end + 10, 0.99, 'Disk scanned', rotation=90, ha='left', va='top', transform=ax.get_xaxis_transform())
    plt.box(False)
    plt.tight_layout()
    plt.savefig(f"../../../../results/graphs/{filename}")


if __name__ == "__main__":
    for name in ["primary", "backup"]:
        times, throughputs, crash_start, hash_receive_start, hash_receive_end, disk_scan_end = extract_data(f"crash_{name}_out.txt")
        plot_time_series(f"{name}_recovery.pdf", times, throughputs, crash_start, hash_receive_start, hash_receive_end, disk_scan_end)
