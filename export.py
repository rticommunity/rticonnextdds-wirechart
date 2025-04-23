import subprocess

def run_tshark_with_filter(pcap_file, display_filter):
    command = [
        'tshark',
        '-r', pcap_file,
        '-Y', display_filter,
        '-T', 'fields',
        '-e', 'frame.number',
        '-e', '_ws.col.Info'  # the real "Info" column!
    ]

    result = subprocess.run(command, capture_output=True, text=True)
    # Split lines and return as list of (frame_number, info) tuples
    output = []
    for line in result.stdout.splitlines():
        parts = line.split('\t')
        if len(parts) == 2:
            output.append((parts[0], parts[1]))
        elif len(parts) == 1:
            output.append((parts[0], ''))  # Handle missing Info
    return output