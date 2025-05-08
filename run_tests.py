#!/usr/bin/env python3

import unittest
import sys
from test_flow_log_parser import TestFlowLogParser

def run_tests():
    # Create a test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestFlowLogParser)
    
    # Create a test runner with verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    
    # Run the tests
    print("\nRunning Flow Log Parser Tests")
    print("=" * 50)
    result = runner.run(suite)
    
    # Print summary
    print("\nTest Summary")
    print("=" * 50)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    # Return appropriate exit code
    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    sys.exit(run_tests()) 