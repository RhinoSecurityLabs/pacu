#!/usr/bin/env python3
"""
Unit tests for the enhanced IAM privilege escalation scanner with managed policy analysis.

This module tests the new functionality for analyzing AWS managed policies
for privilege escalation opportunities (Issue #445).
"""

import unittest
from unittest.mock import patch, MagicMock, Mock
import json
from botocore.exceptions import ClientError

# Import the managed policy analyzer
try:
    from pacu.modules.iam__privesc_scan.managed_policy_analyzer import (
        AWSManagedPolicyAnalyzer,
        enhance_privesc_scan_with_managed_policies
    )
except ImportError:
    # If running tests independently
    import sys
    import os
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    from pacu.modules.iam__privesc_scan.managed_policy_analyzer import (
        AWSManagedPolicyAnalyzer,
        enhance_privesc_scan_with_managed_policies
    )


class TestAWSManagedPolicyAnalyzer(unittest.TestCase):
    """Test suite for AWS managed policy analyzer functionality."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.mock_iam_client = MagicMock()
        self.mock_pacu_main = MagicMock()
        self.analyzer = AWSManagedPolicyAnalyzer(
            iam_client=self.mock_iam_client,
            pacu_main=self.mock_pacu_main
        )

    def test_analyzer_initialization(self):
        """Test that analyzer initializes correctly."""
        self.assertEqual(self.analyzer.iam_client, self.mock_iam_client)
        self.assertEqual(self.analyzer.pacu_main, self.mock_pacu_main)
        self.assertEqual(self.analyzer.escalation_paths, [])

    def test_high_risk_policy_detection(self):
        """Test detection of high-risk managed policies."""
        attached_policies = [
            {
                'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess',
                'PolicyName': 'AdministratorAccess'
            },
            {
                'PolicyArn': 'arn:aws:iam::aws:policy/PowerUserAccess',
                'PolicyName': 'PowerUserAccess'
            }
        ]

        # Mock policy document retrieval
        self.mock_iam_client.get_policy.side_effect = [
            {'Policy': {'DefaultVersionId': 'v1'}},
            {'Policy': {'DefaultVersionId': 'v1'}}
        ]
        
        self.mock_iam_client.get_policy_version.side_effect = [
            {
                'PolicyVersion': {
                    'Document': {
                        'Statement': [{
                            'Effect': 'Allow',
                            'Action': '*',
                            'Resource': '*'
                        }]
                    }
                }
            },
            {
                'PolicyVersion': {
                    'Document': {
                        'Statement': [{
                            'Effect': 'Allow',
                            'Action': '*',
                            'Resource': '*',
                            'Condition': {'StringNotEquals': {'aws:RequestedRegion': 'us-east-1'}}
                        }]
                    }
                }
            }
        ]

        results = self.analyzer.analyze_managed_policies(attached_policies)

        # Verify high-risk policies are detected
        self.assertEqual(len(results['high_risk_policies']), 2)
        self.assertEqual(results['high_risk_policies'][0]['risk_level'], 'CRITICAL')
        self.assertEqual(results['high_risk_policies'][1]['risk_level'], 'CRITICAL')

    def test_policy_document_analysis(self):
        """Test analysis of policy documents for escalation opportunities."""
        policy_doc = {
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Action': [
                        'iam:AttachUserPolicy',
                        'iam:ListUsers'
                    ],
                    'Resource': '*'
                },
                {
                    'Effect': 'Allow', 
                    'Action': [
                        'lambda:UpdateFunctionCode',
                        'lambda:InvokeFunction'
                    ],
                    'Resource': 'arn:aws:lambda:*:*:function:*'
                }
            ]
        }

        escalation_paths = self.analyzer._analyze_policy_document(policy_doc, 'test-policy-arn')

        # Should detect IAM user policy attachment escalation
        iam_escalation = next((path for path in escalation_paths 
                               if path['escalation_type'] == 'IAM_USER_POLICY_ATTACHMENT'), None)
        self.assertIsNotNone(iam_escalation)
        self.assertEqual(iam_escalation['risk_level'], 'HIGH')

        # Should detect Lambda code execution escalation
        lambda_escalation = next((path for path in escalation_paths 
                                  if path['escalation_type'] == 'LAMBDA_CODE_EXECUTION'), None)
        self.assertIsNotNone(lambda_escalation)
        self.assertEqual(lambda_escalation['risk_level'], 'MEDIUM')

    def test_dangerous_permission_combinations(self):
        """Test identification of dangerous permission combinations."""
        test_cases = [
            {
                'actions': ['iam:AttachUserPolicy', 'iam:ListUsers'],
                'resources': ['*'],
                'expected_type': 'IAM_USER_POLICY_ATTACHMENT'
            },
            {
                'actions': ['iam:AttachRolePolicy', 'sts:AssumeRole'],
                'resources': ['*'],
                'expected_type': 'IAM_ROLE_POLICY_ATTACHMENT'
            },
            {
                'actions': ['iam:CreatePolicyVersion'],
                'resources': ['*'],
                'expected_type': 'IAM_POLICY_VERSION_MANIPULATION'
            },
            {
                'actions': ['ec2:RunInstances', 'iam:PassRole'],
                'resources': ['*'],
                'expected_type': 'EC2_INSTANCE_PROFILE_ESCALATION'
            }
        ]

        for test_case in test_cases:
            with self.subTest(test_case=test_case):
                dangerous_combos = self.analyzer._identify_dangerous_combinations(
                    test_case['actions'], test_case['resources']
                )
                
                # Should find the expected dangerous combination
                expected_combo = next((combo for combo in dangerous_combos 
                                       if combo['type'] == test_case['expected_type']), None)
                self.assertIsNotNone(expected_combo, 
                    f"Expected to find {test_case['expected_type']} escalation")

    def test_policy_document_retrieval_aws_managed(self):
        """Test retrieval of AWS managed policy documents."""
        policy_arn = 'arn:aws:iam::aws:policy/ReadOnlyAccess'
        policy_name = 'ReadOnlyAccess'

        # Mock AWS managed policy response
        self.mock_iam_client.get_policy.return_value = {
            'Policy': {'DefaultVersionId': 'v1'}
        }
        self.mock_iam_client.get_policy_version.return_value = {
            'PolicyVersion': {
                'Document': {
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': ['*:List*', '*:Get*', '*:Describe*'],
                        'Resource': '*'
                    }]
                }
            }
        }

        policy_doc = self.analyzer._get_policy_document(policy_arn, policy_name)

        self.assertIsNotNone(policy_doc)
        self.assertIn('Statement', policy_doc)
        self.mock_iam_client.get_policy.assert_called_once_with(PolicyArn=policy_arn)

    def test_policy_document_retrieval_error_handling(self):
        """Test error handling during policy document retrieval."""
        policy_arn = 'arn:aws:iam::123456789012:policy/NonExistentPolicy'
        policy_name = 'NonExistentPolicy'

        # Mock ClientError
        self.mock_iam_client.get_policy.side_effect = ClientError(
            {'Error': {'Code': 'NoSuchEntity', 'Message': 'Policy not found'}},
            'GetPolicy'
        )

        policy_doc = self.analyzer._get_policy_document(policy_arn, policy_name)

        self.assertIsNone(policy_doc)
        self.mock_pacu_main.print.assert_called()

    def test_service_linked_escalation_analysis(self):
        """Test analysis of service-linked role escalation opportunities."""
        attached_policies = [
            {'PolicyArn': 'arn:aws:iam::aws:policy/service-role/AWSLambdaRole'},
            {'PolicyArn': 'arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforAWSCodeDeploy'}
        ]

        service_risks = self.analyzer._analyze_service_linked_escalation(attached_policies)

        # Should identify service-linked escalation risks
        self.assertGreater(len(service_risks), 0)
        
        # Check that we have identified some key services
        service_names = [risk['service'] for risk in service_risks]
        self.assertIn('lambda', service_names)
        self.assertIn('ec2', service_names)

    def test_cross_service_vector_identification(self):
        """Test identification of cross-service escalation vectors."""
        attached_policies = [
            {'PolicyArn': 'arn:aws:iam::aws:policy/AWSLambdaExecute'},
            {'PolicyArn': 'arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess'}
        ]

        cross_service_vectors = self.analyzer._identify_cross_service_vectors(attached_policies)

        # Should identify common cross-service escalation patterns
        self.assertGreater(len(cross_service_vectors), 0)
        
        # Check for expected vector types
        vector_types = [vector['vector_type'] for vector in cross_service_vectors]
        self.assertIn('LAMBDA_TO_IAM', vector_types)

    def test_report_generation(self):
        """Test generation of escalation analysis reports."""
        analysis_results = {
            'high_risk_policies': [
                {
                    'policy_name': 'AdministratorAccess',
                    'policy_arn': 'arn:aws:iam::aws:policy/AdministratorAccess',
                    'risk_level': 'CRITICAL',
                    'description': 'Full administrative access'
                }
            ],
            'escalation_opportunities': [
                {
                    'policy_arn': 'arn:aws:iam::123456789012:policy/TestPolicy',
                    'escalation_type': 'IAM_USER_POLICY_ATTACHMENT',
                    'actions': ['iam:AttachUserPolicy'],
                    'risk_level': 'HIGH',
                    'description': 'Can attach managed policies to users'
                }
            ],
            'service_linked_risks': [
                {
                    'service': 'lambda',
                    'required_permissions': ['lambda:InvokeFunction'],
                    'risk_level': 'MEDIUM',
                    'description': 'Potential lambda service escalation'
                }
            ],
            'cross_service_vectors': []
        }

        report = self.analyzer.generate_escalation_report(analysis_results)

        # Verify report contains expected sections
        self.assertIn('HIGH-RISK MANAGED POLICIES:', report)
        self.assertIn('PRIVILEGE ESCALATION OPPORTUNITIES:', report)
        self.assertIn('SERVICE-LINKED ROLE RISKS:', report)
        self.assertIn('AdministratorAccess', report)
        self.assertIn('IAM_USER_POLICY_ATTACHMENT', report)

    def test_empty_analysis_results_report(self):
        """Test report generation with empty analysis results."""
        empty_results = {
            'high_risk_policies': [],
            'escalation_opportunities': [],
            'service_linked_risks': [],
            'cross_service_vectors': []
        }

        report = self.analyzer.generate_escalation_report(empty_results)

        self.assertIn('No significant managed policy escalation risks identified', report)


class TestEnhancedPrivescScan(unittest.TestCase):
    """Test suite for the enhanced privilege escalation scan integration."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.mock_session = MagicMock()
        self.mock_iam_client = MagicMock()
        self.mock_pacu_main = MagicMock()
        
        # Mock active AWS key
        self.mock_aws_key = MagicMock()
        self.mock_aws_key.user_name = 'test-user'
        self.mock_aws_key.role_name = None
        
        self.mock_session.get_active_aws_key.return_value = self.mock_aws_key
        self.mock_pacu_main.database = MagicMock()

    def test_enhance_privesc_scan_user_based(self):
        """Test enhanced privilege escalation scan for user-based credentials."""
        # Mock user policy attachments
        self.mock_iam_client.list_attached_user_policies.return_value = {
            'AttachedPolicies': [
                {
                    'PolicyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess',
                    'PolicyName': 'ReadOnlyAccess'
                }
            ]
        }

        # Mock group membership
        self.mock_iam_client.get_groups_for_user.return_value = {
            'Groups': [
                {'GroupName': 'test-group'}
            ]
        }

        self.mock_iam_client.list_attached_group_policies.return_value = {
            'AttachedPolicies': [
                {
                    'PolicyArn': 'arn:aws:iam::aws:policy/PowerUserAccess',
                    'PolicyName': 'PowerUserAccess'
                }
            ]
        }

        # Mock policy document retrieval
        self.mock_iam_client.get_policy.return_value = {
            'Policy': {'DefaultVersionId': 'v1'}
        }
        self.mock_iam_client.get_policy_version.return_value = {
            'PolicyVersion': {
                'Document': {
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*'
                    }]
                }
            }
        }

        results = enhance_privesc_scan_with_managed_policies(
            self.mock_session, self.mock_iam_client, self.mock_pacu_main
        )

        # Verify the scan was performed
        self.mock_iam_client.list_attached_user_policies.assert_called_once()
        self.mock_iam_client.get_groups_for_user.assert_called_once()
        self.mock_pacu_main.print.assert_called()

    def test_enhance_privesc_scan_role_based(self):
        """Test enhanced privilege escalation scan for role-based credentials."""
        # Set up role-based credential
        self.mock_aws_key.user_name = None
        self.mock_aws_key.role_name = 'test-role'

        # Mock role policy attachments
        self.mock_iam_client.list_attached_role_policies.return_value = {
            'AttachedPolicies': [
                {
                    'PolicyArn': 'arn:aws:iam::aws:policy/IAMFullAccess',
                    'PolicyName': 'IAMFullAccess'
                }
            ]
        }

        results = enhance_privesc_scan_with_managed_policies(
            self.mock_session, self.mock_iam_client, self.mock_pacu_main
        )

        # Verify role-specific calls were made
        self.mock_iam_client.list_attached_role_policies.assert_called_once_with(
            RoleName='test-role'
        )

    def test_enhance_privesc_scan_no_active_key(self):
        """Test enhanced scan behavior when no active AWS key is found."""
        self.mock_session.get_active_aws_key.return_value = None

        results = enhance_privesc_scan_with_managed_policies(
            self.mock_session, self.mock_iam_client, self.mock_pacu_main
        )

        # Should return empty results and log error
        self.assertEqual(results, {})
        self.mock_pacu_main.print.assert_called_with("  No active AWS key found. Cannot perform analysis.")

    def test_enhance_privesc_scan_api_error_handling(self):
        """Test error handling during API calls."""
        # Mock ClientError during policy retrieval
        self.mock_iam_client.list_attached_user_policies.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
            'ListAttachedUserPolicies'
        )

        results = enhance_privesc_scan_with_managed_policies(
            self.mock_session, self.mock_iam_client, self.mock_pacu_main
        )

        # Should handle error gracefully
        self.mock_pacu_main.print.assert_any_call(
            "  Warning: Could not retrieve user policies: Access denied"
        )


if __name__ == '__main__':
    unittest.main()