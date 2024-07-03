import subprocess
import os
import time
import pandas as pd
from datetime import datetime, timezone

def get_user_input():
    tshark_interface = input("Enter the capture interface (e.g., eth0 or Wi-Fi): ")
    tshark_filter = input("Enter the capture filter (e.g., tcp port 80): ")
    pcap_file = input("Enter the name of the pcap file to save (e.g., capture.pcap): ")
    capture_duration = int(input("Enter the capture duration in seconds (e.g., 60): "))
    
    networkminer_path = 'C:\\Users\\Jill\\Desktop\\PacketInspector\\networkminer-cli\\NetworkMinerCLI.exe' # Replace with your actual path to NetworkMinerCLI.exe
    
    return tshark_interface, tshark_filter, pcap_file, networkminer_path, capture_duration

def capture_packets(interface, capture_filter, pcap_output):
    tshark_path = r'C:\\Users\\Jill\\Desktop\\PacketInspector\\Wireshark\\tshark.exe'  # Replace with your actual path to tshark.exe
    tshark_command = [
        tshark_path,
        '-i', interface,
        '-f', capture_filter,
        '-w', pcap_output,
        '-F', 'pcap'
    ]
    print(f"Running tshark command: {' '.join(tshark_command)}")
    tshark_process = subprocess.Popen(tshark_command)

    return tshark_process

def analyze_pcap(networkminer_cli_path, pcap_input):
    networkminer_command = [
        networkminer_cli_path,
        pcap_input
    ]
    print(f"Running NetworkMinerCLI command: {' '.join(networkminer_command)}")
    subprocess.run(networkminer_command)

def extract_files_with_timestamps(networkminer_output_dir):
    artifacts = []
    for root, dirs, files in os.walk(networkminer_output_dir):
        for file in files:
            file_path = os.path.join(root, file)
            file_stat = os.stat(file_path)
            file_timestamp = datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc)  # Normalize to UTC
            artifacts.append((root, file, os.path.splitext(file)[1][1:], file_timestamp))
    return artifacts

def create_timeline_df(artifacts):
    df = pd.DataFrame(artifacts, columns=['Location', 'Artifact', 'Artifact Type', 'Timestamp'])
    return df

def save_timeline_to_csv(df, output_file):
    df.to_csv(output_file, index=False)
    print(f"Timeline saved to {output_file}")

if __name__ == "__main__":
    # Get user input
    tshark_interface, tshark_filter, pcap_file, networkminer_path, capture_duration = get_user_input()
    
    # Start capturing packets
    tshark_process = capture_packets(tshark_interface, tshark_filter, pcap_file)
    
    # Capture packets for the specified duration
    print(f"Capturing packets for {capture_duration} seconds...")
    time.sleep(capture_duration)
    
    # Stop tshark
    tshark_process.terminate()
    tshark_process.wait()
    print("Packet capture completed.")
    
    # Analyze the captured pcap file with NetworkMinerCLI
    analyze_pcap(networkminer_path, pcap_file)
    print(f"Analysis completed. Output stored in networkminer-cli\\AssembledFiles")
    
    # Extract files with timestamps from NetworkMiner output
    networkminer_output_dir = 'C:\\Users\\Jill\\Desktop\\PacketInspector\\networkminer-cli\\AssembledFiles'  # Replace with your actual path
    artifacts = extract_files_with_timestamps(networkminer_output_dir)
    
    # Create a timeline DataFrame
    timeline_df = create_timeline_df(artifacts)
    
    # Save the timeline to a CSV file
    timeline_output_file = 'timeline.csv'
    save_timeline_to_csv(timeline_df, timeline_output_file)
