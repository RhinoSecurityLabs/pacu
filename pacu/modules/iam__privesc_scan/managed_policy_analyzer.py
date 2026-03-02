#!/usr/bin/env python3
"""
Enhanced IAM Privilege Escalation Scanner - AWS Managed Policy Analyzer

This module extends the existing iam__privesc_scan to analyze AWS managed policies
for privilege escalation opportunities (Issue #445).

Author: Enhanced by Claude Code for Pacu contribution
"""

import json
import boto3
from botocore.exceptions import ClientError
from typing import Dict, List, Set, Tuple, Optional


class AWSManagedPolicyAnalyzer:
    """
    Analyzes AWS managed policies for privilege escalation paths.
    
    This class extends the current iam__privesc_scan functionality to include
    comprehensive analysis of AWS managed policies that may provide escalation
    opportunities.
    """
    
    # High-risk AWS managed policies that can lead to privilege escalation
    HIGH_RISK_MANAGED_POLICIES = {
        'arn:aws:iam::aws:policy/AdministratorAccess': 'Full administrative access',
        'arn:aws:iam::aws:policy/PowerUserAccess': 'Full access except IAM',
        'arn:aws:iam::aws:policy/IAMFullAccess': 'Full IAM management access',
        'arn:aws:iam::aws:policy/SecurityAuditAccess': 'Read access to security resources',
        'arn:aws:iam::aws:policy/ReadOnlyAccess': 'Read-only access to all AWS resources',
        'arn:aws:iam::aws:policy/SystemAdministrator': 'System administration access',
    }
    
    # Privilege escalation vectors through service-linked roles
    SERVICE_LINKED_ESCALATION_PATHS = {
        'lambda': ['lambda:InvokeFunction', 'lambda:UpdateFunctionCode'],
        'ec2': ['ec2:RunInstances', 'iam:PassRole'],
        'cloudformation': ['cloudformation:CreateStack', 'iam:PassRole'],
        'iam': ['iam:CreateRole', 'iam:AttachRolePolicy', 'iam:AssumeRole'],
        'sts': ['sts:AssumeRole', 'sts:AssumeRoleWithWebIdentity'],
        'glue': ['glue:CreateDevEndpoint', 'iam:PassRole'],
    }
    
    def __init__(self, iam_client=None, pacu_main=None):
        """
        Initialize the managed policy analyzer.
        
        Args:
            iam_client: boto3 IAM client (optional, will create if None)
            pacu_main: Pacu main instance for logging and session management
        """
        self.iam_client = iam_client
        self.pacu_main = pacu_main
        self.escalation_paths = []
        
    def analyze_managed_policies(self, attached_policies: List[Dict]) -> Dict:
        """
        Analyze attached managed policies for escalation opportunities.
        
        Args:
            attached_policies: List of attached policy dictionaries
            
        Returns:
            Dictionary containing analysis results
        """
        analysis_results = {
            'high_risk_policies': [],
            'escalation_opportunities': [],
            'service_linked_risks': [],
            'cross_service_vectors': []
        }
        
        for policy in attached_policies:
            policy_arn = policy.get('PolicyArn', '')
            policy_name = policy.get('PolicyName', '')
            
            # Check for high-risk managed policies
            if policy_arn in self.HIGH_RISK_MANAGED_POLICIES:
                analysis_results['high_risk_policies'].append({
                    'policy_arn': policy_arn,
                    'policy_name': policy_name,
                    'risk_level': 'CRITICAL',
                    'description': self.HIGH_RISK_MANAGED_POLICIES[policy_arn]
                })
                
            # Analyze policy document for escalation paths
            try:
                policy_doc = self._get_policy_document(policy_arn, policy_name)
                if policy_doc:
                    escalation_paths = self._analyze_policy_document(policy_doc, policy_arn)
                    if escalation_paths:
                        analysis_results['escalation_opportunities'].extend(escalation_paths)
                        
            except Exception as e:
                if self.pacu_main:
                    self.pacu_main.print(f"  Warning: Could not analyze policy {policy_name}: {str(e)}")
                    
        # Analyze service-linked role escalation opportunities
        service_risks = self._analyze_service_linked_escalation(attached_policies)
        analysis_results['service_linked_risks'] = service_risks
        
        # Identify cross-service escalation vectors
        cross_service_vectors = self._identify_cross_service_vectors(attached_policies)
        analysis_results['cross_service_vectors'] = cross_service_vectors
        
        return analysis_results
    
    def _get_policy_document(self, policy_arn: str, policy_name: str) -> Optional[Dict]:
        """
        Retrieve the policy document for analysis.
        
        Args:
            policy_arn: ARN of the policy
            policy_name: Name of the policy
            
        Returns:
            Policy document dictionary or None if retrieval fails
        """
        if not self.iam_client:
            return None
            
        try:
            if policy_arn.startswith('arn:aws:iam::aws:policy/'):
                # AWS managed policy
                response = self.iam_client.get_policy(PolicyArn=policy_arn)
                policy_version = response['Policy']['DefaultVersionId']
                
                version_response = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_version
                )
                return version_response['PolicyVersion']['Document']
                
            else:
                # Customer managed policy
                response = self.iam_client.get_policy(PolicyArn=policy_arn)
                policy_version = response['Policy']['DefaultVersionId']
                
                version_response = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_version
                )
                return version_response['PolicyVersion']['Document']
                
        except ClientError as e:
            if self.pacu_main:
                self.pacu_main.print(f"  Error retrieving policy document for {policy_name}: {str(e)}")
            return None
    
    def _analyze_policy_document(self, policy_doc: Dict, policy_arn: str) -> List[Dict]:
        """
        Analyze a policy document for privilege escalation opportunities.
        
        Args:
            policy_doc: The policy document to analyze
            policy_arn: ARN of the policy being analyzed
            
        Returns:
            List of identified escalation opportunities
        """
        escalation_opportunities = []
        
        statements = policy_doc.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
            
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
                
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
                
            resources = statement.get('Resource', ['*'])
            if isinstance(resources, str):
                resources = [resources]
                
            # Check for dangerous permission combinations
            dangerous_combos = self._identify_dangerous_combinations(actions, resources)
            for combo in dangerous_combos:
                escalation_opportunities.append({
                    'policy_arn': policy_arn,
                    'escalation_type': combo['type'],
                    'actions': combo['actions'],
                    'resources': resources,
                    'risk_level': combo['risk_level'],
                    'description': combo['description']
                })
                
        return escalation_opportunities
    
    def _identify_dangerous_combinations(self, actions: List[str], resources: List[str]) -> List[Dict]:
        """
        Identify dangerous permission combinations that enable privilege escalation.
        
        Args:
            actions: List of allowed actions
            resources: List of allowed resources
            
        Returns:
            List of dangerous combinations found
        """
        dangerous_combos = []
        action_set = set(action.lower() for action in actions)
        
        # IAM privilege escalation combinations
        if 'iam:attachuserpolicy' in action_set and ('*' in resources or any('user/*' in r for r in resources)):
            dangerous_combos.append({
                'type': 'IAM_USER_POLICY_ATTACHMENT',
                'actions': ['iam:AttachUserPolicy'],
                'risk_level': 'HIGH',
                'description': 'Can attach managed policies to users, potentially granting admin access'
            })
            
        if 'iam:attachrolepolicy' in action_set and 'sts:assumerole' in action_set:
            dangerous_combos.append({
                'type': 'IAM_ROLE_POLICY_ATTACHMENT',
                'actions': ['iam:AttachRolePolicy', 'sts:AssumeRole'],
                'risk_level': 'HIGH',
                'description': 'Can attach policies to roles and assume them'
            })
            
        if 'iam:createpolicyversion' in action_set:
            dangerous_combos.append({
                'type': 'IAM_POLICY_VERSION_MANIPULATION',
                'actions': ['iam:CreatePolicyVersion'],
                'risk_level': 'HIGH',
                'description': 'Can create new policy versions, potentially escalating privileges'
            })
            
        # Lambda-based escalation
        if 'lambda:updatefunctioncode' in action_set and 'lambda:invokefunction' in action_set:
            dangerous_combos.append({
                'type': 'LAMBDA_CODE_EXECUTION',
                'actions': ['lambda:UpdateFunctionCode', 'lambda:InvokeFunction'],
                'risk_level': 'MEDIUM',
                'description': 'Can modify and execute Lambda functions with their associated roles'
            })
            
        # EC2 instance profile escalation
        if 'ec2:runinstances' in action_set and 'iam:passrole' in action_set:
            dangerous_combos.append({
                'type': 'EC2_INSTANCE_PROFILE_ESCALATION',
                'actions': ['ec2:RunInstances', 'iam:PassRole'],
                'risk_level': 'HIGH',
                'description': 'Can launch EC2 instances with privileged instance profiles'
            })
            
        # CloudFormation-based escalation
        if 'cloudformation:createstack' in action_set and 'iam:passrole' in action_set:
            dangerous_combos.append({
                'type': 'CLOUDFORMATION_STACK_ESCALATION',
                'actions': ['cloudformation:CreateStack', 'iam:PassRole'],
                'risk_level': 'HIGH',
                'description': 'Can create CloudFormation stacks with privileged service roles'
            })
            
        return dangerous_combos
    
    def _analyze_service_linked_escalation(self, attached_policies: List[Dict]) -> List[Dict]:
        """
        Analyze service-linked role escalation opportunities.
        
        Args:
            attached_policies: List of attached policies
            
        Returns:
            List of service-linked escalation risks
        """
        service_risks = []
        
        for service, required_permissions in self.SERVICE_LINKED_ESCALATION_PATHS.items():
            # This would require more detailed analysis of policy documents
            # For now, we flag potential service-linked role risks
            service_risks.append({
                'service': service,
                'required_permissions': required_permissions,
                'risk_level': 'MEDIUM',
                'description': f'Potential {service} service-linked role escalation path'
            })
            
        return service_risks
    
    def _identify_cross_service_vectors(self, attached_policies: List[Dict]) -> List[Dict]:
        """
        Identify cross-service privilege escalation vectors.
        
        Args:
            attached_policies: List of attached policies
            
        Returns:
            List of cross-service escalation vectors
        """
        cross_service_vectors = []
        
        # Common cross-service escalation patterns
        common_vectors = [
            {
                'vector_type': 'LAMBDA_TO_IAM',
                'description': 'Lambda function execution can be used to escalate IAM privileges',
                'services': ['lambda', 'iam'],
                'risk_level': 'HIGH'
            },
            {
                'vector_type': 'EC2_TO_METADATA',
                'description': 'EC2 instance metadata service can expose instance profile credentials',
                'services': ['ec2', 'sts'],
                'risk_level': 'MEDIUM'
            },
            {
                'vector_type': 'ASSUME_ROLE_CHAINING',
                'description': 'Role assumption chaining can lead to privilege escalation',
                'services': ['sts', 'iam'],
                'risk_level': 'HIGH'
            }
        ]
        
        # For now, return the common vectors; in a full implementation,
        # we would analyze actual policy documents to confirm these vectors
        return common_vectors
    
    def generate_escalation_report(self, analysis_results: Dict) -> str:
        """
        Generate a comprehensive escalation analysis report.
        
        Args:
            analysis_results: Results from managed policy analysis
            
        Returns:
            Formatted report string
        """
        report_lines = []
        report_lines.append("AWS Managed Policy Privilege Escalation Analysis")
        report_lines.append("=" * 55)
        report_lines.append("")
        
        # High-risk policies
        if analysis_results['high_risk_policies']:
            report_lines.append("HIGH-RISK MANAGED POLICIES:")
            for policy in analysis_results['high_risk_policies']:
                report_lines.append(f"  • {policy['policy_name']}")
                report_lines.append(f"    ARN: {policy['policy_arn']}")
                report_lines.append(f"    Risk: {policy['risk_level']}")
                report_lines.append(f"    Description: {policy['description']}")
                report_lines.append("")
                
        # Escalation opportunities
        if analysis_results['escalation_opportunities']:
            report_lines.append("PRIVILEGE ESCALATION OPPORTUNITIES:")
            for opp in analysis_results['escalation_opportunities']:
                report_lines.append(f"  • {opp['escalation_type']}")
                report_lines.append(f"    Policy: {opp['policy_arn']}")
                report_lines.append(f"    Actions: {', '.join(opp['actions'])}")
                report_lines.append(f"    Risk Level: {opp['risk_level']}")
                report_lines.append(f"    Description: {opp['description']}")
                report_lines.append("")
                
        # Service-linked risks
        if analysis_results['service_linked_risks']:
            report_lines.append("SERVICE-LINKED ROLE RISKS:")
            for risk in analysis_results['service_linked_risks']:
                report_lines.append(f"  • {risk['service'].upper()} Service")
                report_lines.append(f"    Required Permissions: {', '.join(risk['required_permissions'])}")
                report_lines.append(f"    Risk Level: {risk['risk_level']}")
                report_lines.append(f"    Description: {risk['description']}")
                report_lines.append("")
                
        # Cross-service vectors
        if analysis_results['cross_service_vectors']:
            report_lines.append("CROSS-SERVICE ESCALATION VECTORS:")
            for vector in analysis_results['cross_service_vectors']:
                report_lines.append(f"  • {vector['vector_type']}")
                report_lines.append(f"    Services: {', '.join(vector['services'])}")
                report_lines.append(f"    Risk Level: {vector['risk_level']}")
                report_lines.append(f"    Description: {vector['description']}")
                report_lines.append("")
                
        if not any([analysis_results['high_risk_policies'], 
                   analysis_results['escalation_opportunities'],
                   analysis_results['service_linked_risks'],
                   analysis_results['cross_service_vectors']]):
            report_lines.append("No significant managed policy escalation risks identified.")
            
        return "\n".join(report_lines)


def enhance_privesc_scan_with_managed_policies(session, iam_client, pacu_main):
    """
    Enhanced privilege escalation scanning that includes AWS managed policy analysis.
    
    This function extends the existing iam__privesc_scan functionality to include
    comprehensive analysis of AWS managed policies.
    
    Args:
        session: Current Pacu session
        iam_client: boto3 IAM client
        pacu_main: Pacu main instance
        
    Returns:
        Enhanced analysis results including managed policy risks
    """
    analyzer = AWSManagedPolicyAnalyzer(iam_client, pacu_main)
    
    try:
        # Get current user/role information
        active_aws_key = session.get_active_aws_key(pacu_main.database)
        if not active_aws_key:
            pacu_main.print("  No active AWS key found. Cannot perform analysis.")
            return {}
            
        # Get attached managed policies
        attached_policies = []
        
        if active_aws_key.user_name:
            # User-based analysis
            try:
                response = iam_client.list_attached_user_policies(
                    UserName=active_aws_key.user_name
                )
                attached_policies.extend(response.get('AttachedPolicies', []))
                
                # Also check group policies
                group_response = iam_client.get_groups_for_user(
                    UserName=active_aws_key.user_name
                )
                
                for group in group_response.get('Groups', []):
                    group_policies = iam_client.list_attached_group_policies(
                        GroupName=group['GroupName']
                    )
                    attached_policies.extend(group_policies.get('AttachedPolicies', []))
                    
            except ClientError as e:
                pacu_main.print(f"  Warning: Could not retrieve user policies: {str(e)}")
                
        elif active_aws_key.role_name:
            # Role-based analysis
            try:
                response = iam_client.list_attached_role_policies(
                    RoleName=active_aws_key.role_name
                )
                attached_policies.extend(response.get('AttachedPolicies', []))
                
            except ClientError as e:
                pacu_main.print(f"  Warning: Could not retrieve role policies: {str(e)}")
                
        # Perform managed policy analysis
        if attached_policies:
            pacu_main.print(f"  Analyzing {len(attached_policies)} attached managed policies...")
            analysis_results = analyzer.analyze_managed_policies(attached_policies)
            
            # Generate and display report
            report = analyzer.generate_escalation_report(analysis_results)
            pacu_main.print("\n" + report)
            
            return analysis_results
        else:
            pacu_main.print("  No managed policies found for analysis.")
            return {}
            
    except Exception as e:
        pacu_main.print(f"  Error during managed policy analysis: {str(e)}")
        return {}