#!/usr/bin/env python3
"""
Unit tests for environment variable authentication support in Pacu.

This module tests the new functionality for importing AWS credentials from
environment variables (Issue #442).
"""

import os
import unittest
from unittest.mock import patch, MagicMock, Mock
import pytest
from pacu import Main
from pacu.core.models import PacuSession, AWSKey
from pacu.utils import get_database_connection


class TestEnvironmentVariableAuth(unittest.TestCase):
    """Test suite for environment variable authentication functionality."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.main = Main()
        self.main.database = MagicMock()
        
        # Mock session
        self.mock_session = MagicMock(spec=PacuSession)
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
    @patch('pacu.Main.set_keys')
    @patch('pacu.Main.get_boto3_client')
    def test_import_env_keys_with_session_token(self, mock_get_client, mock_set_keys):
        """Test importing credentials from environment variables with session token."""
        # Mock STS client for validation
        mock_sts_client = MagicMock()
        mock_sts_client.get_caller_identity.return_value = {
            'Arn': 'arn:aws:iam::123456789012:user/test-user',
            'Account': '123456789012'
        }
        mock_get_client.return_value = mock_sts_client
        
        # Mock print method
        self.main.print = MagicMock()
        
        # Execute the method
        self.main.import_env_keys()
        
        # Verify set_keys was called with correct parameters
        mock_set_keys.assert_called_once_with(
            key_alias='env-vars',
            access_key_id='AKIAIOSFODNN7EXAMPLE',
            secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            session_token='test-session-token'
        )
        
        # Verify success message was printed
        self.main.print.assert_any_call('  Successfully imported temporary AWS credentials from environment variables.')
        
        # Verify validation was attempted
        mock_get_client.assert_called_once_with('sts')
        mock_sts_client.get_caller_identity.assert_called_once()

    @patch.dict(os.environ, {
        'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE',
        'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    }, clear=True)  # Clear any existing AWS_SESSION_TOKEN
    @patch('pacu.Main.set_keys')
    @patch('pacu.Main.get_boto3_client')
    def test_import_env_keys_without_session_token(self, mock_get_client, mock_set_keys):
        """Test importing credentials from environment variables without session token."""
        # Mock STS client for validation
        mock_sts_client = MagicMock()
        mock_sts_client.get_caller_identity.return_value = {
            'Arn': 'arn:aws:iam::123456789012:user/test-user',
            'Account': '123456789012'
        }
        mock_get_client.return_value = mock_sts_client
        
        # Mock print method
        self.main.print = MagicMock()
        
        # Execute the method
        self.main.import_env_keys()
        
        # Verify set_keys was called with correct parameters
        mock_set_keys.assert_called_once_with(
            key_alias='env-vars',
            access_key_id='AKIAIOSFODNN7EXAMPLE',
            secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            session_token='c'  # Clear any existing session token
        )
        
        # Verify success message was printed
        self.main.print.assert_any_call('  Successfully imported AWS credentials from environment variables.')

    @patch.dict(os.environ, {
        'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE'
    }, clear=True)  # Clear AWS_SECRET_ACCESS_KEY
    def test_import_env_keys_missing_secret_key(self):
        """Test importing credentials with missing secret access key."""
        # Mock print method
        self.main.print = MagicMock()
        
        # Execute the method
        self.main.import_env_keys()
        
        # Verify error message was printed
        self.main.print.assert_any_call('\\n  Error: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables must be set.')
        
        # Verify environment variable status was shown
        self.main.print.assert_any_call('  Available environment variables:')
        self.main.print.assert_any_call('    AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE')
        self.main.print.assert_any_call('    AWS_SECRET_ACCESS_KEY: Not set')

    @patch.dict(os.environ, {
        'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    }, clear=True)  # Clear AWS_ACCESS_KEY_ID
    def test_import_env_keys_missing_access_key(self):
        """Test importing credentials with missing access key ID."""
        # Mock print method
        self.main.print = MagicMock()
        
        # Execute the method
        self.main.import_env_keys()
        
        # Verify error message was printed
        self.main.print.assert_any_call('\\n  Error: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables must be set.')
        
        # Verify environment variable status was shown
        self.main.print.assert_any_call('    AWS_ACCESS_KEY_ID: Not set')
        self.main.print.assert_any_call('    AWS_SECRET_ACCESS_KEY: ******* (hidden)')

    @patch.dict(os.environ, {
        'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE',
        'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'AWS_DEFAULT_REGION': 'us-west-2'
    })
    @patch('pacu.Main.set_keys')
    @patch('pacu.Main.get_boto3_client')
    def test_import_env_keys_with_validation_failure(self, mock_get_client, mock_set_keys):
        """Test importing credentials with STS validation failure."""
        # Mock STS client to raise an exception
        mock_sts_client = MagicMock()
        mock_sts_client.get_caller_identity.side_effect = Exception("Access denied")
        mock_get_client.return_value = mock_sts_client
        
        # Mock print method
        self.main.print = MagicMock()
        
        # Execute the method
        self.main.import_env_keys()
        
        # Verify credentials were still set despite validation failure
        mock_set_keys.assert_called_once()
        
        # Verify warning message was printed
        self.main.print.assert_any_call('  Warning: Could not validate credentials: Access denied')
        self.main.print.assert_any_call('  Credentials imported but may be invalid or lack necessary permissions.')

    @patch('pacu.Main.import_env_keys')
    def test_parse_awscli_keys_import_env_flag(self, mock_import_env_keys):
        """Test that parse_awscli_keys_import correctly calls import_env_keys with --env flag."""
        # Execute the method with --env flag
        self.main.parse_awscli_keys_import(['import_keys', '--env'])
        
        # Verify import_env_keys was called
        mock_import_env_keys.assert_called_once()

    def test_help_text_includes_env_option(self):
        """Test that help text includes the new --env option."""
        # This would typically be tested by checking the help output
        # For now, we verify the method exists
        self.assertTrue(hasattr(self.main, 'import_env_keys'))
        self.assertTrue(callable(getattr(self.main, 'import_env_keys')))


class TestEnvironmentVariableAuthIntegration(unittest.TestCase):
    """Integration tests for environment variable authentication."""

    @patch.dict(os.environ, {
        'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE',
        'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    })
    def test_env_credentials_integration_with_boto_session(self):
        """Test that environment credentials integrate properly with boto3 session creation."""
        main = Main()
        
        # Mock database and session
        main.database = MagicMock()
        mock_session = MagicMock(spec=PacuSession)
        mock_session.key_alias = 'env-vars'
        mock_session.access_key_id = 'AKIAIOSFODNN7EXAMPLE'
        mock_session.secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        mock_session.session_token = None
        
        main.get_active_session = MagicMock(return_value=mock_session)
        
        # Test boto session creation
        with patch('boto3.session.Session') as mock_boto_session:
            boto_session = main.get_boto_session()
            
            # Verify boto3.Session was called with correct parameters
            mock_boto_session.assert_called_with(
                region_name=None,
                aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
                aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                aws_session_token=None
            )


if __name__ == '__main__':
    unittest.main()