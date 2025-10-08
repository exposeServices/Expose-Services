import psutil
import time

def monitor_performance(duration=10800):
    """Monitors CPU, memory, disk, and network usage over a given duration (seconds)."""
    cpu_usages = []
    mem_usages = []
    disk_usages = []
    net_usages = []

    for _ in range(duration):
        cpu_usages.append(psutil.cpu_percent(interval=1))
        mem_usages.append(psutil.virtual_memory().used / (1024 * 1024))  # Convert to MB
        disk_usages.append(psutil.disk_io_counters().read_bytes / (1024 * 1024))  # Read in MB
        net_usages.append(psutil.net_io_counters().bytes_sent / (1024 * 1024))  # Sent in MB
        time.sleep(1)

    # Compute averages
    avg_cpu = sum(cpu_usages) / len(cpu_usages)
    avg_mem = sum(mem_usages) / len(mem_usages)
    avg_disk = sum(disk_usages) / len(disk_usages)
    avg_net = sum(net_usages) / len(net_usages)

    print(f"Avg CPU Usage: {avg_cpu:.2f}%")
    print(f"Avg RAM Usage: {avg_mem:.2f} MB")
    print(f"Avg Disk Read: {avg_disk:.2f} MB")
    print(f"Avg Network Sent: {avg_net:.2f} MB")

monitor_performance(10800)  # Run for 5 minutes

