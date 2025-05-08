#!/usr/bin/env python3

import unittest
import tempfile
import os
import shutil
from flow_log_parser import FlowLogParser

class TestFlowLogParser(unittest.TestCase):
    def setUp(self):
        # Create temporary files for testing
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a sample lookup table
        self.lookup_file = os.path.join(self.temp_dir, 'test_lookup.csv')
        with open(self.lookup_file, 'w') as f:
            f.write("dstport,protocol,tag\n")
            f.write("80,tcp,web\n")
            f.write("443,tcp,web\n")
            f.write("53,udp,dns\n")
            f.write("22,tcp,ssh\n")
            f.write(" 25 , tcp , mail \n")  # Test whitespace handling
            f.write("invalid,tcp,error\n")  # Invalid port
            f.write("80,TCP,web\n")  # Test case insensitivity
            f.write("80,tcp,Web\n")  # Test case insensitivity in tags

        # Create a sample flow log
        self.flow_log_file = os.path.join(self.temp_dir, 'test_flow.log')
        with open(self.flow_log_file, 'w') as f:
            # Valid entries (14 fields each)
            f.write("2 123456789012 eni-1234567890 10.0.1.1 10.0.1.2 80 12345 6 10 100 1234567890 1234567891 ACCEPT OK\n")
            f.write("2 123456789012 eni-1234567890 10.0.1.1 10.0.1.2 443 12346 6 10 100 1234567890 1234567891 ACCEPT OK\n")
            f.write("2 123456789012 eni-1234567890 10.0.1.1 10.0.1.2 53 12347 17 10 100 1234567890 1234567891 ACCEPT OK\n")
            # Invalid entries
            f.write("\n")  # Empty line
            f.write("invalid line\n")  # Too few fields
            f.write("2 123456789012 eni-1234567890 10.0.1.1 10.0.1.2 not_a_port 12348 6 10 100 1234567890 1234567891 ACCEPT OK\n")
            # Unknown protocol
            f.write("2 123456789012 eni-1234567890 10.0.1.1 10.0.1.2 80 12349 99 10 100 1234567890 1234567891 ACCEPT OK\n")
            # Untagged port
            f.write("2 123456789012 eni-1234567890 10.0.1.1 10.0.1.2 8080 12350 6 10 100 1234567890 1234567891 ACCEPT OK\n")

        self.output_file = os.path.join(self.temp_dir, 'test_output.csv')
        self.parser = FlowLogParser(self.lookup_file)

    def tearDown(self):
        # Clean up temporary directory and all its contents
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_lookup_table_loading(self):
        """Test that lookup table is loaded correctly"""
        self.assertEqual(self.parser.lookup_table[(80, 'tcp')], 'web')
        self.assertEqual(self.parser.lookup_table[(443, 'tcp')], 'web')
        self.assertEqual(self.parser.lookup_table[(53, 'udp')], 'dns')
        self.assertEqual(self.parser.lookup_table[(25, 'tcp')], 'mail')  # Test whitespace handling
        self.assertNotIn(('invalid', 'tcp'), self.parser.lookup_table)  # Invalid port should be skipped

    def test_protocol_name_conversion(self):
        """Test protocol number to name conversion"""
        self.assertEqual(self.parser._get_protocol_name(6), 'tcp')
        self.assertEqual(self.parser._get_protocol_name(17), 'udp')
        self.assertEqual(self.parser._get_protocol_name(1), 'icmp')
        self.assertEqual(self.parser._get_protocol_name(99), 'unknown')

    def test_flow_log_parsing(self):
        """Test flow log parsing and counting"""
        self.parser.parse_flow_log(self.flow_log_file)
        
        # Check tag counts
        self.assertEqual(self.parser.tag_counts['web'], 2)  # 80/tcp and 443/tcp
        self.assertEqual(self.parser.tag_counts['dns'], 1)  # 53/udp
        self.assertEqual(self.parser.tag_counts['Untagged'], 2)  # 8080/tcp and unknown protocol (99)
        
        # Check port/protocol counts
        self.assertEqual(self.parser.port_protocol_counts[(80, 'tcp')], 1)
        self.assertEqual(self.parser.port_protocol_counts[(443, 'tcp')], 1)
        self.assertEqual(self.parser.port_protocol_counts[(53, 'udp')], 1)
        self.assertEqual(self.parser.port_protocol_counts[(8080, 'tcp')], 1)
        self.assertEqual(self.parser.port_protocol_counts[(80, 'unknown')], 1)  # Protocol 99 entry

    def test_output_file_generation(self):
        """Test output file format and content"""
        self.parser.parse_flow_log(self.flow_log_file)
        self.parser.write_results(self.output_file)
        
        with open(self.output_file, 'r') as f:
            lines = f.readlines()
        
        # Check file structure
        self.assertEqual(lines[0].strip(), "Tag Counts:")
        self.assertEqual(lines[1].strip(), "Tag,Count")
        
        # Find the line that separates the two sections
        separator_index = next(i for i, line in enumerate(lines) if line.strip() == "Port/Protocol Combination Counts:")
        
        # Verify both sections exist
        self.assertTrue(separator_index > 2)  # At least some tag counts
        self.assertTrue(len(lines) > separator_index + 2)  # At least some port/protocol counts

    def test_empty_files(self):
        """Test handling of empty files"""
        # Create empty files
        empty_lookup = os.path.join(self.temp_dir, 'empty_lookup.csv')
        empty_flow = os.path.join(self.temp_dir, 'empty_flow.log')
        empty_output = os.path.join(self.temp_dir, 'empty_output.csv')
        
        with open(empty_lookup, 'w') as f:
            f.write("dstport,protocol,tag\n")
        
        with open(empty_flow, 'w') as f:
            pass
        
        # Test with empty lookup table
        parser = FlowLogParser(empty_lookup)
        parser.parse_flow_log(self.flow_log_file)
        parser.write_results(empty_output)
        
        # All entries should be untagged
        self.assertTrue(all(tag == 'Untagged' for tag in parser.tag_counts.keys()))
        
        # Test with empty flow log
        parser = FlowLogParser(self.lookup_file)
        parser.parse_flow_log(empty_flow)
        parser.write_results(empty_output)
        
        # No entries should be counted
        self.assertEqual(sum(parser.tag_counts.values()), 0)
        self.assertEqual(sum(parser.port_protocol_counts.values()), 0)

    def test_case_insensitivity(self):
        """Test case insensitivity in protocol names and tags"""
        # Test protocol case insensitivity
        self.assertEqual(self.parser.lookup_table[(80, 'tcp')], 'web')
        
        # Test tag case insensitivity
        self.assertEqual(self.parser.lookup_table[(80, 'tcp')], 'web')
        
        # Test in flow log parsing
        self.parser.parse_flow_log(self.flow_log_file)
        self.assertEqual(self.parser.tag_counts['web'], 2)  # Should match both cases

    def test_invalid_input_handling(self):
        """Test handling of various invalid inputs"""
        # Test invalid port in flow log
        invalid_flow = os.path.join(self.temp_dir, 'invalid_flow.log')
        with open(invalid_flow, 'w') as f:
            f.write("2 123456789012 eni-1234567890 10.0.1.1 10.0.1.2 not_a_port 12348 6 10 100 1234567890 1234567891 ACCEPT OK\n")
        
        parser = FlowLogParser(self.lookup_file)
        parser.parse_flow_log(invalid_flow)
        self.assertEqual(sum(parser.tag_counts.values()), 0)  # No valid entries should be counted
        
        # Test invalid protocol in flow log
        with open(invalid_flow, 'w') as f:
            f.write("2 123456789012 eni-1234567890 10.0.1.1 10.0.1.2 80 12348 not_a_protocol 10 100 1234567890 1234567891 ACCEPT OK\n")
        
        parser = FlowLogParser(self.lookup_file)
        parser.parse_flow_log(invalid_flow)
        self.assertEqual(sum(parser.tag_counts.values()), 0)  # No valid entries should be counted

if __name__ == '__main__':
    unittest.main() 