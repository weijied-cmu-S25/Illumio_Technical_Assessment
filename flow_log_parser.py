#!/usr/bin/env python3

import csv
import sys
import os
from collections import defaultdict
from typing import Dict, Tuple, Set

class FlowLogParser:
    def __init__(self, lookup_file: str):
        self.lookup_table: Dict[Tuple[int, str], str] = {}
        self.tag_counts: Dict[str, int] = defaultdict(int)
        self.port_protocol_counts: Dict[Tuple[int, str], int] = defaultdict(int)
        self.load_lookup_table(lookup_file)

    def load_lookup_table(self, lookup_file: str) -> None:
        """Load the lookup table from CSV file."""
        with open(lookup_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    dstport = int(row['dstport'])
                    protocol = row['protocol'].lower().strip()
                    tag = row['tag'].strip()
                    # Store tag in lowercase for case-insensitive matching
                    self.lookup_table[(dstport, protocol)] = tag.lower()
                except (ValueError, KeyError):
                    continue  # Skip invalid rows

    def parse_flow_log(self, flow_log_file: str) -> None:
        """Parse the flow log file and count matches."""
        with open(flow_log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Parse flow log fields
                fields = line.split()
                if len(fields) < 14:  # VPC Flow logs should have at least 14 fields
                    continue
                
                try:
                    # Extract relevant fields
                    dst_port = int(fields[5])
                    protocol = self._get_protocol_name(int(fields[7]))
                    
                    # Count port/protocol combination
                    self.port_protocol_counts[(dst_port, protocol)] += 1
                    
                    # Look up tag (case-insensitive)
                    tag = self.lookup_table.get((dst_port, protocol), 'Untagged')
                    self.tag_counts[tag] += 1
                except (ValueError, IndexError):
                    continue  # Skip invalid entries

    def _get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to name."""
        protocol_map = {
            1: 'icmp',
            6: 'tcp',
            17: 'udp'
        }
        return protocol_map.get(protocol_num, 'unknown').lower()

    def write_results(self, output_file: str) -> None:
        """Write results to output file."""
        with open(output_file, 'w') as f:
            # Write tag counts
            f.write("Tag Counts:\n")
            f.write("Tag,Count\n")
            for tag, count in sorted(self.tag_counts.items()):
                f.write(f"{tag},{count}\n")
            
            f.write("\nPort/Protocol Combination Counts:\n")
            f.write("Port,Protocol,Count\n")
            for (port, protocol), count in sorted(self.port_protocol_counts.items()):
                f.write(f"{port},{protocol},{count}\n")

def main():
    # Default file names
    default_files = {
        'flow_log': 'flow_logs.txt',
        'lookup': 'lookup_table.csv',
        'output': 'results.csv'
    }

    # Check if files exist in current directory
    for file_type, filename in default_files.items():
        if not os.path.exists(filename):
            print(f"Warning: Default {file_type} file '{filename}' not found in current directory.")

    # Parse command line arguments
    if len(sys.argv) == 1:
        # No arguments provided, use default files
        flow_log_file = default_files['flow_log']
        lookup_file = default_files['lookup']
        output_file = default_files['output']
    elif len(sys.argv) == 4:
        # All arguments provided
        flow_log_file = sys.argv[1]
        lookup_file = sys.argv[2]
        output_file = sys.argv[3]
    else:
        print("Usage:")
        print("  python flow_log_parser.py")
        print("  python flow_log_parser.py <flow_log_file> <lookup_file> <output_file>")
        print("\nIf no arguments are provided, the program will look for:")
        print(f"  - Flow log file: {default_files['flow_log']}")
        print(f"  - Lookup table: {default_files['lookup']}")
        print(f"  - Output file: {default_files['output']}")
        sys.exit(1)

    # Check if input files exist
    if not os.path.exists(flow_log_file):
        print(f"Error: Flow log file '{flow_log_file}' not found.")
        sys.exit(1)
    if not os.path.exists(lookup_file):
        print(f"Error: Lookup table file '{lookup_file}' not found.")
        sys.exit(1)

    # Process the files
    parser = FlowLogParser(lookup_file)
    parser.parse_flow_log(flow_log_file)
    parser.write_results(output_file)
    print(f"Results written to '{output_file}'")

if __name__ == "__main__":
    main() 