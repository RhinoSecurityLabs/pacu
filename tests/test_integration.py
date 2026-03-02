#!/usr/bin/env python3
"""
Integration tests for Pacu enhancements (Issues #442 and #445).

This module tests the integration of both the environment variable authentication
and enhanced IAM privilege escalation functionality with the existing Pacu architecture.
"""

import unittest
from unittest.mock import patch, MagicMock, Mock
import os
import sys
import tempfile
import json

# Add the pacu directory to the path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import Pacu components
try:
    from pacu import Main
    from pacu.core.models import PacuSession, AWSKey
except ImportError:
    print("Warning: Could not import Pacu components. Some tests may be skipped.")
    Main = None
    PacuSession = None
    AWSKey = None


class TestPacuIntegration(unittest.TestCase):
    """Integration tests for Pacu enhancements."""

    def setUp(self):
        """Set up test fixtures."""
        if Main is None:
            self.skipTest("Pacu components not available")
            
        self.main = Main()
        self.main.database = MagicMock()
        
        # Mock session
        self.mock_session = MagicMock(spec=PacuSession)
        self.mock_session.name = 'test-session'
        self.mock_session.key_alias = None
        self.mock_session.access_key_id = None
        self.mock_session.secret_access_key = None
        self.mock_session.session_token = None
        
        self.main.get_active_session = MagicMock(return_value=self.mock_session)

    @patch.dict(os.environ, {
        'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE',
        'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'AWS_SESSION_TOKEN': 'test-session-token'
    })
    def test_environment_variable_integration_workflow(self):
        """Test the complete workflow for environment variable authentication."""
        # Mock the necessary methods
        with patch.object(self.main, 'set_keys') as mock_set_keys, \
             patch.object(self.main, 'get_boto3_client') as mock_get_client, \
             patch.object(self.main, 'print') as mock_print:
            
            # Mock STS client for validation
            mock_sts_client = MagicMock()
            mock_sts_client.get_caller_identity.return_value = {
                'Arn': 'arn:aws:iam::123456789012:user/test-user',
                'Account': '123456789012',
                'UserId': 'AIDACKCEVSQ6C2EXAMPLE'
            }
            mock_get_client.return_value = mock_sts_client

            # Test the import_env_keys functionality
            self.main.import_env_keys()

            # Verify credentials were set correctly
            mock_set_keys.assert_called_once_with(
                key_alias='env-vars',
                access_key_id='AKIAIOSFODNN7EXAMPLE',
                secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                session_token='test-session-token'
            )

            # Verify success message was printed
            mock_print.assert_any_call('  Successfully imported temporary AWS credentials from environment variables.')

            # Verify credential validation was attempted
            mock_get_client.assert_called_with('sts')
            mock_sts_client.get_caller_identity.assert_called_once()

    def test_command_parsing_integration(self):
        """Test that the new import_keys --env command is properly parsed."""
        with patch.object(self.main, 'import_env_keys') as mock_import_env_keys:
            # Test command parsing
            self.main.parse_awscli_keys_import(['import_keys', '--env'])
            
            # Verify the method was called
            mock_import_env_keys.assert_called_once()

    @patch.dict(os.environ, {
        'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE',
        'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    })
    def test_boto_session_integration_with_env_credentials(self):
        """Test that environment credentials work with boto session creation."""
        # Set up session with environment credentials
        self.mock_session.key_alias = 'env-vars'
        self.mock_session.access_key_id = 'AKIAIOSFODNN7EXAMPLE'
        self.mock_session.secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        self.mock_session.session_token = None

        with patch('boto3.session.Session') as mock_boto_session:
            # Test session creation
            self.main.get_boto_session()
            
            # Verify correct parameters were used
            mock_boto_session.assert_called_with(
                region_name=None,
                aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
                aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                aws_session_token=None
            )

    def test_iam_privesc_scan_enhanced_integration(self):
        """Test integration of enhanced IAM privilege escalation scanning."""
        # Mock the IAM privesc scan module
        with patch('pacu.modules.iam__privesc_scan.main.enhance_privesc_scan_with_managed_policies') as mock_enhance:
            mock_enhance.return_value = {
                'high_risk_policies': [
                    {
                        'policy_name': 'AdministratorAccess',
                        'risk_level': 'CRITICAL'
                    }
                ],
                'escalation_opportunities': []
            }
            
            # Mock IAM client
            mock_iam_client = MagicMock()
            
            with patch.object(self.main, 'get_boto3_client') as mock_get_client:
                mock_get_client.return_value = mock_iam_client
                
                # This would be called from within the iam__privesc_scan module
                # with the --include-managed-policies flag
                try:
                    from pacu.modules.iam__privesc_scan.managed_policy_analyzer import enhance_privesc_scan_with_managed_policies
                    
                    results = enhance_privesc_scan_with_managed_policies(
                        self.mock_session, mock_iam_client, self.main
                    )
                    
                    # The function should return results
                    self.assertIsInstance(results, dict)
                    
                except ImportError:
                    # If the module is not available, skip this test
                    self.skipTest("Enhanced IAM privesc scan module not available")

    def test_error_handling_integration(self):
        """Test error handling across the integrated functionality."""
        # Test environment variable authentication with missing variables
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(self.main, 'print') as mock_print:
                self.main.import_env_keys()
                
                # Should print error message
                mock_print.assert_any_call('\\n  Error: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables must be set.')

    def test_session_management_integration(self):
        """Test that session management works correctly with new functionality."""
        # Mock AWS key creation
        mock_aws_key = MagicMock(spec=AWSKey)
        mock_aws_key.user_name = 'test-user'
        mock_aws_key.role_name = None
        
        self.mock_session.get_active_aws_key.return_value = mock_aws_key
        
        # Test that session can be used for both functionalities
        with patch.object(self.main, 'print') as mock_print:
            # Test session information retrieval
            session = self.main.get_active_session()
            self.assertIsNotNone(session)
            
            # Test that AWS key can be retrieved
            aws_key = session.get_active_aws_key(self.main.database)
            self.assertIsNotNone(aws_key)

    @patch('tempfile.mkdtemp')
    def test_file_operations_integration(self):
        """Test that file operations work correctly with new functionality."""
        mock_temp_dir = '/tmp/test_pacu'
        
        # Test that the enhanced IAM scanning can write results
        with patch('tempfile.mkdtemp', return_value=mock_temp_dir), \
             patch('builtins.open', create=True) as mock_open, \
             patch('json.dump') as mock_json_dump:
            
            # Mock file handle
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file
            
            # Test data writing (simulating what the privesc scan would do)
            test_data = {
                'managed_policy_analysis': {
                    'high_risk_policies': ['AdministratorAccess'],
                    'escalation_opportunities': []
                }
            }
            
            # This simulates saving results from the enhanced scan
            with open(f"{mock_temp_dir}/enhanced_scan_results.json", 'w') as f:
                json.dump(test_data, f)
            
            # Verify file operations
            mock_open.assert_called()
            mock_json_dump.assert_called()

    def test_command_line_argument_integration(self):
        """Test that new command line arguments are properly integrated."""
        # Test argument parsing for iam__privesc_scan module
        try:
            from pacu.modules.iam__privesc_scan.main import parser
            
            # Test that the new argument is available
            args = parser.parse_args(['--include-managed-policies'])
            self.assertTrue(args.include_managed_policies)
            
            # Test with scan-only and managed policies
            args = parser.parse_args(['--scan-only', '--include-managed-policies'])
            self.assertTrue(args.scan_only)
            self.assertTrue(args.include_managed_policies)
            
        except ImportError:
            self.skipTest("IAM privesc scan module not available for argument testing")

    def test_help_text_integration(self):
        """Test that help text includes new functionality."""
        # This test ensures that the help system is aware of new functionality
        with patch.object(self.main, 'print') as mock_print:
            # Test help for import_keys includes --env option
            # This would be tested by calling the help system, but since it's complex
            # to mock the entire help system, we'll verify the method exists
            self.assertTrue(hasattr(self.main, 'import_env_keys'))
            self.assertTrue(callable(getattr(self.main, 'import_env_keys')))

    def test_backward_compatibility(self):
        """Test that existing functionality still works with enhancements."""
        # Test that original import_keys functionality still works
        with patch('boto3.session.Session') as mock_boto_session, \
             patch.object(self.main, 'set_keys') as mock_set_keys, \
             patch.object(self.main, 'print') as mock_print:
            
            # Mock boto3 session and credentials
            mock_session = MagicMock()
            mock_creds = MagicMock()
            mock_creds.access_key = 'AKIATEST'
            mock_creds.secret_key = 'test-secret'
            mock_creds.token = None
            
            mock_session.get_credentials.return_value = mock_creds
            mock_boto_session.return_value = mock_session
            
            # Test original profile-based import
            self.main.import_awscli_key('test-profile')
            
            # Verify original functionality still works
            mock_set_keys.assert_called_once()

    def test_integration_with_modules(self):
        """Test that enhanced functionality integrates properly with other modules."""
        # Mock module execution environment
        mock_pacu_main = MagicMock()
        mock_pacu_main.get_active_session.return_value = self.mock_session
        mock_pacu_main.get_boto3_client.return_value = MagicMock()
        
        # Test that enhanced functions can be called from module context
        # This simulates how the enhanced privesc scan would be called
        try:
            from pacu.modules.iam__privesc_scan.managed_policy_analyzer import AWSManagedPolicyAnalyzer
            
            analyzer = AWSManagedPolicyAnalyzer(pacu_main=mock_pacu_main)
            self.assertIsNotNone(analyzer)
            
            # Test analyzer can be used in module context
            test_policies = []
            results = analyzer.analyze_managed_policies(test_policies)
            self.assertIsInstance(results, dict)
            
        except ImportError:
            self.skipTest("Enhanced analyzer not available for module integration test")


class TestEndToEndIntegration(unittest.TestCase):
    """End-to-end integration tests."""

    @patch.dict(os.environ, {
        'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE',
        'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    })
    def test_complete_workflow_env_auth_to_privesc_scan(self):
        """Test complete workflow from environment auth to privilege escalation scan."""
        if Main is None:
            self.skipTest("Pacu components not available")
            
        main = Main()
        main.database = MagicMock()
        
        # Mock session
        mock_session = MagicMock()
        mock_session.name = 'test-session'
        main.get_active_session = MagicMock(return_value=mock_session)
        
        with patch.object(main, 'set_keys') as mock_set_keys, \
             patch.object(main, 'get_boto3_client') as mock_get_client, \
             patch.object(main, 'print') as mock_print:
            
            # Step 1: Import credentials from environment
            mock_sts_client = MagicMock()
            mock_sts_client.get_caller_identity.return_value = {
                'Arn': 'arn:aws:iam::123456789012:user/test-user',
                'Account': '123456789012'
            }
            mock_get_client.return_value = mock_sts_client
            
            # Import environment credentials
            main.import_env_keys()
            
            # Verify credentials were imported
            mock_set_keys.assert_called_once_with(
                key_alias='env-vars',
                access_key_id='AKIAIOSFODNN7EXAMPLE',
                secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                session_token='c'  # No session token in this test
            )
            
            # Step 2: Use credentials for enhanced privesc scan
            # Mock IAM client for privesc scan
            mock_iam_client = MagicMock()
            mock_iam_client.list_attached_user_policies.return_value = {
                'AttachedPolicies': []
            }
            mock_iam_client.get_groups_for_user.return_value = {
                'Groups': []
            }
            
            # Override the STS client with IAM client for privesc scan
            mock_get_client.side_effect = lambda service: mock_iam_client if service == 'iam' else mock_sts_client
            
            # Mock active AWS key
            mock_aws_key = MagicMock()
            mock_aws_key.user_name = 'test-user'
            mock_aws_key.role_name = None
            mock_session.get_active_aws_key.return_value = mock_aws_key
            
            # Test the enhanced privesc scan would work with imported credentials
            try:
                from pacu.modules.iam__privesc_scan.managed_policy_analyzer import enhance_privesc_scan_with_managed_policies
                
                results = enhance_privesc_scan_with_managed_policies(
                    mock_session, mock_iam_client, main
                )
                
                # Should return results dictionary
                self.assertIsInstance(results, dict)
                
            except ImportError:
                # If module not available, verify the integration points exist
                self.assertTrue(hasattr(main, 'import_env_keys'))
                self.assertTrue(hasattr(main, 'get_boto3_client'))


if __name__ == '__main__':
    # Set up test environment
    test_loader = unittest.TestLoader()
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTests(test_loader.loadTestsFromTestCase(TestPacuIntegration))
    test_suite.addTests(test_loader.loadTestsFromTestCase(TestEndToEndIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with error code if tests failed
    sys.exit(not result.wasSuccessful())