# Flow Log Parser

This program parses AWS VPC flow logs and maps them to tags based on a lookup table. It generates statistics about tag matches and port/protocol combinations.

## Assumptions

1. The program only supports AWS VPC flow logs in the default format (version 2)
2. The flow log file is a plain text (ASCII) file
3. The lookup table is a CSV file with headers: dstport,protocol,tag
4. Protocol numbers in flow logs are mapped as follows:
   - 1: ICMP
   - 6: TCP
   - 17: UDP
5. All protocol names in the lookup table should be lowercase
6. The program handles files up to 10MB in size
7. The lookup table can contain up to 10,000 mappings
8. Tags can map to multiple port/protocol combinations
9. All matches are case-insensitive

## Requirements

- Python 3.6 or higher
- No external dependencies required (uses only standard library)

## Usage

The program can be run in two ways:

1. Using default file names (simplest):
```bash
python flow_log_parser.py
```
This will look for:
- Flow log file: `flow_logs.txt`
- Lookup table: `lookup_table.csv`
- Output file: `results.csv`

2. Specifying custom file names:
```bash
python flow_log_parser.py <flow_log_file> <lookup_file> <output_file>
```

Example:
```bash
python flow_log_parser.py my_flow_logs.txt my_lookup.csv my_results.csv
```

## Running Tests

There are two ways to run the tests:

1. Using the test runner script (recommended):
```bash
python run_tests.py
```
This will run all tests with detailed output and a summary.

2. Using unittest directly:
```bash
python -m unittest test_flow_log_parser.py -v
```

The test suite covers:
- Lookup table loading and parsing
- Protocol number to name conversion
- Flow log parsing and counting
- Output file generation
- Edge cases:
  - Empty files
  - Invalid entries
  - Whitespace handling
  - Unknown protocols
  - Untagged ports

## Input Files

### Flow Log Format
The program expects AWS VPC flow logs in the default format (version 2). Each line contains space-separated fields:
```
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
```

### Lookup Table Format
The lookup table should be a CSV file with the following columns:
- dstport: Destination port number
- protocol: Protocol name (tcp, udp, or icmp)
- tag: Tag to apply for the port/protocol combination

## Output

The program generates a CSV file with two sections:

1. Tag Counts:
   - Lists each tag and the number of flow log entries that matched it
   - Includes an "Untagged" count for entries that didn't match any tag

2. Port/Protocol Combination Counts:
   - Lists each unique port/protocol combination found in the flow logs
   - Shows the count of occurrences for each combination

## Testing

The program has been tested with:
1. Sample flow logs provided in the requirements
2. Various edge cases including:
   - Empty lines
   - Invalid protocol numbers
   - Missing fields
   - Case sensitivity in protocol names
   - Multiple tags for the same port/protocol
3. Unit tests covering all major functionality

