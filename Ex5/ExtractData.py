import pyshark
import pandas as pd
import matplotlib.pyplot as plt

# Function to extract packet data from a PCAPNG file
def extract_packet_data(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="ip or tcp or tls")

    data = []

    for packet in cap:
        try:
            length = int(packet.length) if hasattr(packet, 'length') else None
            ip_length = int(packet.ip.len) if hasattr(packet, 'ip') and hasattr(packet.ip, 'len') else None
            tcp_length = int(packet.tcp.len) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'len') else None
            tls_length = int(packet.tls.record_length) if hasattr(packet, 'tls') and hasattr(packet.tls, 'record_length') else None

            data.append({
                'Packet Length': length,
                'IP Length': ip_length,
                'TCP Length': tcp_length,
                'TLS Length': tls_length
            })
        except AttributeError:
            continue

    cap.close()

    return pd.DataFrame(data)


# Function to plot comparisons
def plot_comparison(dfs, apps, ip_categories, title, colors):
    # Ensure data is numeric and handle errors (convert non-numeric to NaN)
    for i, df in enumerate(dfs):
        for category in ip_categories:
            # Try to convert the column to numeric, coercing errors to NaN
            df[category] = pd.to_numeric(df[category], errors='coerce')

    avg_values = [df[category].dropna().mean() for df in dfs for category in ip_categories]

    # Plotting logic
    plt.figure(figsize=(10, 6))
    bar_width = 0.15  # Bar width for each category
    indices = range(len(apps))  # X-axis positions for bars
    for idx, category in enumerate(ip_categories):
        plt.bar([i + bar_width * idx for i in indices], [df[category].dropna().mean() for df in dfs],
                color=colors[idx], width=bar_width, label=category)

    plt.xlabel('Application')
    plt.ylabel(f'Average Value')
    plt.title(title)
    plt.xticks([i + bar_width * (len(ip_categories) - 1) / 2 for i in indices], apps)
    plt.legend(title="Category")
    plt.tight_layout()
    plt.show()


# Function to compare traffic from multiple applications
def compare_traffic():
    apps = ['Firefox', 'Google Chrome', 'Spotify', 'YouTube', 'Zoom']
    pcap_files = ['firefox3.pcapng', 'googlechrome.pcapng', 'spotify.pcapng', 'youtube.pcapng', 'zoom.pcapng']

    dfs = [extract_packet_data(pcap) for pcap in pcap_files]

    ip_categories = ['IP Length', 'TCP Length', 'TLS Length', 'Packet Length']
    colors = ['b', 'g', 'r', 'purple']

    # Plot comparison for each category
    plot_comparison(dfs, apps, ip_categories, 'Traffic Field Comparison', colors)


# Run the comparison function
compare_traffic()
