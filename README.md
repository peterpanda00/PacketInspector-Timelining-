# Timelining Tool

## Overview

This tool captures network traffic using `tshark`, analyzes the captured data with `NetworkMinerCLI`, extracts artifacts, and generates a timeline of extracted artifacts with timestamps. The timeline is saved as a CSV file with columns for `Location`, `Artifact`, `Artifact Type`, `Timestamp`, and  `Host IP`.

## Prerequisites

1. **Wireshark/tshark**: Ensure you have `tshark` installed. You can download it from [Wireshark's official website](https://www.wireshark.org/download.html).
2. **NetworkMinerCLI**: Ensure you have `NetworkMinerCLI` installed. You can download it from [NetworkMiner's official website](https://www.netresec.com/?page=NetworkMiner).
3. **Python**: Ensure you have Python installed. You can download it from [Python's official website](https://www.python.org/downloads/).

## Installation

1. Install the required Python packages:
    ```sh
    pip install pandas
    ```

2. Place the `NetworkMinerCLI.exe` and `tshark.exe` in appropriate directories. Update the paths in the script if necessary.

## Usage

1. **Run the script**:
    ```sh
    python script.py
    ```

2. **Provide the required inputs** when prompted:
    - **Capture interface**: The network interface to capture traffic from (e.g., `eth0`, `Wi-Fi`).
    - **Capture filter**: The capture filter for `tshark` (e.g., `tcp port 80`).
    - **Pcap file name**: The name of the pcap file to save (e.g., `capture.pcap`).
    - **Capture duration**: The duration for which to capture packets (e.g., `60` seconds).
    - **NetworkMinerCLI path**: The path to `NetworkMinerCLI.exe`.

3. **Wait for the script to complete**:
    - The script captures packets for the specified duration.
    - It then analyzes the captured pcap file with `NetworkMinerCLI`.
    - Extracts files with timestamps and generates a timeline.

4. **Check the output**:
    - The timeline is saved as `timeline.csv` in the current directory.

## Script Explanation

### Function Definitions

- **get_user_input()**:
    - Prompts the user for input parameters such as interface, filter, pcap file name, and capture duration.
    - Returns the input parameters.

- **capture_packets(interface, capture_filter, pcap_output)**:
    - Runs the `tshark` command to capture packets based on the provided interface, filter, and output file.
    - Returns the `tshark` process.

- **analyze_pcap(networkminer_cli_path, pcap_input)**:
    - Runs the `NetworkMinerCLI` command to analyze the captured pcap file.

- **extract_files_with_timestamps(networkminer_output_dir)**:
    - Extracts files and their timestamps from the `NetworkMiner` output directory.
    - Normalizes timestamps to UTC.
    - Returns a list of artifacts with their details.

- **create_timeline_df(artifacts)**:
    - Creates a DataFrame with columns `Location`, `Artifact`, `Artifact Type`, and `Timestamp`.

- **save_timeline_to_csv(df, output_file)**:
    - Saves the timeline DataFrame to a CSV file.

### Main Script

1. Gets user input for capturing parameters.
2. Captures network packets using `tshark`.
3. Analyzes the captured pcap file with `NetworkMinerCLI`.
4. Extracts files and their timestamps from the `NetworkMiner` output.
5. Creates a timeline DataFrame and saves it to a CSV file.
