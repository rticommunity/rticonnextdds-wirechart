<img src="img/wirechart_icon.jpg">

# Wirechart

Wirechart analyzes DDS traffic based on an input PCAP file.  It provides statics about the total number of DDS topics in a capture and insight into the traffic for each topic.  Wirechart presents some basic data in the terminal and the full analysis is presented visually and can optionally be saved to an `*.xlsx` file in a format that can be easily converted to a pivot table.

⚠️ **Note:** Wirechart depends on information exchanged during the discovery process to perform analytics. For the most accurate results, you must start the packet capture prior to starting your DDS application.

## Requirements

### Python Dependencies
The application requires the following Python libraries:

- `pandas`: For data manipulation and analysis.
- `matplotlib`: For generating visualizations.
- `openpyxl`: For exporting data to Excel files.

Install the dependencies using:

```bash
pip install pandas matplotlib openpyxl
```

### External Tools

- `tshark`: Required for extracting data from PCAP files.
    - Install Wireshark, which typically includes `tshark`.
    - Ensure `tshark` is accessible from your system's `PATH`.

## Usage

```bash
python3 wirechart.py [-h] --pcap /path/to/PCAP_FILE.pcap [--output /path/to/OUTPUT_FILE.xlsx] [--no-gui]
```

### Argument Description

<pre>
--pcap      /path/to/PCAP_FILE.pcap     Required argument to specify the PCAP file.
--output    /path/to/OUTPUT_FILE.xlsx   Optional argument to specify an output file for PCAP statistics.
--no-gui                                Optional argument to limit output to the console.
</pre>