<img src="./img/wirechart_icon.png">

# Wirechart

Wirechart analyzes DDS traffic based on an input PCAP file.  It provides statics about the total number of DDS topics in a capture and insight into the traffic for each topic.  Wirechart presents some basic data in the terminal and the full analysis is presented visually and can optionally be saved to an `*.xlsx` file in a format that can be easily converted to a pivot table.

⚠️ **Note:** Wirechart depends on information exchanged during the discovery process to perform analytics. For the most accurate results, you must start the packet capture prior to starting your DDS application.

## Requirements

### Tkinter

Install `Tkinter` first.  It should install by default in Windows.

```bash
# Linux
sudo apt-get install python3-tk
pip install --upgrade pillow
```

### Python Dependencies
The application requires the following Python libraries:

- `pandas`: For data manipulation and analysis.
- `matplotlib`: For generating visualizations.
- `networkx`: For creating node/edge graphs.
- `openpyxl`: For exporting data to Excel files.
- `tqdm`: For status display bar.

Install the dependencies using:

```bash
pip install pandas matplotlib networkx openpyxl tqdm
```
#### Python Virtual Environment
[requirements.txt](./config/requirements.txt) will install the exact version of the tools above:

```bash
cd <repo_root>

# Create Python Virtual Environment
python -m venv wirechart

# Activate Virtual Environment
wirechart\Scripts\activate      # Windows
source wirechart/bin/activate   # Mac/Linux

# Install Dependencies in Virtual Environment (on creation only)
pip install -r config/requirements.txt

# Exit Virtual Environment
deactivate
```

### External Tools

- `tshark`: Required for extracting data from PCAP files.
    - Install [Wireshark](https://www.wireshark.org/download.html), which installs `tshark` by default.  See more details [here](https://tshark.dev/setup/install/) on installing `tshark` standalone from Wireshark.
    - Ensure `tshark` is accessible from your system's `PATH`.

## Usage

```bash
usage: python3 wirechart.py
```

### Configuration Description

<pre>
PCAP File               Required to specify the PCAP file.
Output                  Specify an output path for statistics and logs.  Default is 'output'.
Frame Range             Specify the range of frames (inclusive) to analyze.  Default is all frames.
Console Log Level       Specify the console log level (DEBUG, INFO, WARNING, *ERROR*, CRITICAL).
File Log Level          Specify the file log level (DEBUG, *INFO*, WARNING, ERROR, CRITICAL).
</pre>

## Details

- **Length Calculation:** The size in bytes is calculated based on the entire frame size, including IP, UDP, and RTPS headers.  These lengths are attributed to the first RTPS submessage (often a `DATA` submessage).  Any subsequence submessages (e.g. a `PIGGYBACK_HEARTBEAT`) will be the actual submessage length.
- **Node Graphs:**
    - Node graphs will only be accurate for RELIABLE DW/DR pairs.  It's possible that a BEST_EFFORT DW/DR will display, but not guaranteed.  If the DW starts before the DR, a `GAP` submessage will be sent when the DR matches, which has the data required to show up on the node graph. See issues [4](https://github.com/rticommunity/rti-wirechart/issues/4) and [25](https://github.com/rticommunity/rti-wirechart/issues/25).
    - Node graphs do not differentiate between domains.  For example, if the topic `Squares` is in both domains 0 and 1, they will display in the same graph. See issue [26](https://github.com/rticommunity/rti-wirechart/issues/26).

### Known Issues

- [Current List of Issues](https://github.com/rticommunity/rti-wirechart/issues)

### Test Versions

- Windows 11
    - tshark: 4.4.6
    - Python: 3.12.0, 3.13.3
- Ubuntu 22.04
    - tshark: 4.4.6
    - Python: 3.10.12