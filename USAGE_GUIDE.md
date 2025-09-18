# Pacu Enhancements Usage Guide

## Quick Start

### Environment Variable Authentication

#### Basic Usage
```bash
# Set your AWS credentials as environment variables
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Start Pacu and import credentials
pacu
pacu (session_name) > import_keys --env
```

#### With Temporary Credentials
```bash
# Include session token for temporary credentials
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" 
export AWS_SESSION_TOKEN="AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/..."

# Import temporary credentials
pacu (session_name) > import_keys --env
Successfully imported temporary AWS credentials from environment variables.
Validated credentials for: arn:aws:iam::123456789012:user/test-user
Account ID: 123456789012
```

### Enhanced IAM Privilege Escalation Analysis

#### Run Enhanced Scan
```bash
# Standard privilege escalation scan with managed policy analysis
pacu (session_name) > run iam__privesc_scan --include-managed-policies
```

#### Scan-Only Mode (No Exploitation)
```bash
# Identify potential escalation paths without attempting them
pacu (session_name) > run iam__privesc_scan --scan-only --include-managed-policies
```

## Detailed Examples

### Example 1: CI/CD Pipeline Integration

```bash
#!/bin/bash
# CI/CD script for automated AWS security testing

# Credentials provided by CI/CD system
export AWS_ACCESS_KEY_ID="$CI_AWS_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$CI_AWS_SECRET_ACCESS_KEY"
export AWS_SESSION_TOKEN="$CI_AWS_SESSION_TOKEN"

# Start Pacu session and import credentials
pacu --session ci-security-test
pacu --session ci-security-test --import_keys --env

# Run comprehensive security analysis
pacu --session ci-security-test --run iam__enum_permissions
pacu --session ci-security-test --run iam__privesc_scan --scan-only --include-managed-policies
pacu --session ci-security-test --run iam__enum_users_roles_policies_groups
```

### Example 2: Cross-Account Assessment

```bash
# Account 1 - Production
export AWS_ACCESS_KEY_ID="AKIA_PROD_KEY"
export AWS_SECRET_ACCESS_KEY="prod_secret_key"
pacu --session prod-assessment
pacu (prod-assessment) > import_keys --env
pacu (prod-assessment) > run iam__privesc_scan --include-managed-policies

# Account 2 - Development  
export AWS_ACCESS_KEY_ID="AKIA_DEV_KEY"
export AWS_SECRET_ACCESS_KEY="dev_secret_key"
pacu --session dev-assessment
pacu (dev-assessment) > import_keys --env
pacu (dev-assessment) > run iam__privesc_scan --include-managed-policies

# Compare results between accounts
pacu (prod-assessment) > data iam
pacu (dev-assessment) > data iam
```

### Example 3: Comprehensive Security Assessment

```bash
# Import credentials
export AWS_ACCESS_KEY_ID="your_access_key"
export AWS_SECRET_ACCESS_KEY="your_secret_key"
pacu (security-assessment) > import_keys --env

# Enumerate IAM permissions and configurations
pacu (security-assessment) > run iam__enum_permissions --all-users --all-roles
pacu (security-assessment) > run iam__enum_users_roles_policies_groups

# Run enhanced privilege escalation analysis
pacu (security-assessment) > run iam__privesc_scan --include-managed-policies

# Additional security modules
pacu (security-assessment) > run iam__get_credential_report
pacu (security-assessment) > run iam__backdoor_users_keys --scan-only
```

## Understanding Output

### Environment Variable Authentication Output

#### Success Case
```
pacu (session) > import_keys --env
  Successfully imported AWS credentials from environment variables.
  Validated credentials for: arn:aws:iam::123456789012:user/security-tester
  Account ID: 123456789012
```

#### Error Cases
```
pacu (session) > import_keys --env
  Error: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables must be set.
  Available environment variables:
    AWS_ACCESS_KEY_ID: Not set
    AWS_SECRET_ACCESS_KEY: Not set  
    AWS_SESSION_TOKEN: Not set
    AWS_DEFAULT_REGION: us-east-1
```

```
pacu (session) > import_keys --env
  Successfully imported AWS credentials from environment variables.
  Warning: Could not validate credentials: Access denied
  Credentials imported but may be invalid or lack necessary permissions.
```

### Enhanced IAM Privilege Escalation Output

```
pacu (session) > run iam__privesc_scan --include-managed-policies

============================================================
ENHANCED AWS MANAGED POLICY ANALYSIS
============================================================

Analyzing 5 attached managed policies...

HIGH-RISK MANAGED POLICIES:
  • AdministratorAccess
    ARN: arn:aws:iam::aws:policy/AdministratorAccess
    Risk: CRITICAL
    Description: Full administrative access

  • PowerUserAccess
    ARN: arn:aws:iam::aws:policy/PowerUserAccess  
    Risk: CRITICAL
    Description: Full access except IAM

PRIVILEGE ESCALATION OPPORTUNITIES:
  • IAM_USER_POLICY_ATTACHMENT
    Policy: arn:aws:iam::123456789012:policy/DeveloperPolicy
    Actions: iam:AttachUserPolicy
    Risk Level: HIGH
    Description: Can attach managed policies to users, potentially granting admin access

  • LAMBDA_CODE_EXECUTION
    Policy: arn:aws:iam::123456789012:policy/LambdaDevPolicy
    Actions: lambda:UpdateFunctionCode, lambda:InvokeFunction
    Risk Level: MEDIUM
    Description: Can modify and execute Lambda functions with their associated roles

SERVICE-LINKED ROLE RISKS:
  • LAMBDA Service
    Required Permissions: lambda:InvokeFunction, lambda:UpdateFunctionCode
    Risk Level: MEDIUM
    Description: Potential lambda service-linked role escalation path

  • EC2 Service
    Required Permissions: ec2:RunInstances, iam:PassRole
    Risk Level: MEDIUM
    Description: Potential ec2 service-linked role escalation path

CROSS-SERVICE ESCALATION VECTORS:
  • LAMBDA_TO_IAM
    Services: lambda, iam
    Risk Level: HIGH
    Description: Lambda function execution can be used to escalate IAM privileges

  • ASSUME_ROLE_CHAINING
    Services: sts, iam
    Risk Level: HIGH
    Description: Role assumption chaining can lead to privilege escalation
```

## Best Practices

### Security Considerations

#### 1. Environment Variable Security
```bash
# Good: Set variables temporarily for single session
AWS_ACCESS_KEY_ID="key" AWS_SECRET_ACCESS_KEY="secret" pacu

# Bad: Export globally where other processes can access
export AWS_ACCESS_KEY_ID="key"  # Other processes can see this
```

#### 2. Credential Rotation
```bash
# Regularly rotate credentials used in assessments
# Use temporary credentials when possible
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/SecurityAuditRole \
  --role-session-name pacu-assessment \
  --duration-seconds 3600

# Export temporary credentials
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."  
export AWS_SESSION_TOKEN="..."
```

#### 3. Session Management
```bash
# Use descriptive session names
pacu --session "prod-security-audit-$(date +%Y%m%d)"

# Clean up sessions after use
pacu (session) > delete_session
```

### Assessment Methodology

#### 1. Reconnaissance Phase
```bash
# Start with basic enumeration
pacu (session) > run iam__enum_permissions
pacu (session) > whoami

# Check current user/role capabilities
pacu (session) > data iam
```

#### 2. Privilege Analysis Phase
```bash
# Comprehensive privilege escalation scan
pacu (session) > run iam__privesc_scan --include-managed-policies

# Focus on specific methods if needed
pacu (session) > run iam__privesc_scan --method-info AttachUserPolicy
```

#### 3. Validation Phase
```bash
# Scan-only mode to identify opportunities without exploitation
pacu (session) > run iam__privesc_scan --scan-only --include-managed-policies

# Review findings before attempting exploitation
pacu (session) > data iam
```

## Troubleshooting

### Common Issues

#### 1. Import Fails with Missing Variables
```bash
# Check current environment
env | grep AWS

# Verify variables are set correctly
echo $AWS_ACCESS_KEY_ID
echo ${AWS_SECRET_ACCESS_KEY:0:8}...  # Show partial secret for verification
```

#### 2. Credentials Not Validated
```bash
# Test credentials manually
aws sts get-caller-identity

# Check permissions
aws iam get-user
aws sts get-session-token
```

#### 3. Enhanced Analysis Not Available
```bash
# Verify module availability
pacu (session) > run iam__privesc_scan --method-list
pacu (session) > run iam__privesc_scan --help

# Check for managed policy analyzer
python -c "from pacu.modules.iam__privesc_scan.managed_policy_analyzer import AWSManagedPolicyAnalyzer; print('Available')"
```

### Debug Mode
```bash
# Enable debug output for troubleshooting
pacu (session) > debug

# Check session data
pacu (session) > data
```

## Advanced Usage

### Scripting Integration

#### Python Script Example
```python
import os
import subprocess

# Set credentials programmatically
os.environ['AWS_ACCESS_KEY_ID'] = 'your_key'
os.environ['AWS_SECRET_ACCESS_KEY'] = 'your_secret'

# Run Pacu commands
commands = [
    'pacu --session automated-scan',
    'pacu --session automated-scan --import_keys --env',
    'pacu --session automated-scan --run iam__privesc_scan --scan-only --include-managed-policies'
]

for cmd in commands:
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    print(f"Command: {cmd}")
    print(f"Output: {result.stdout}")
    if result.stderr:
        print(f"Errors: {result.stderr}")
```

#### Bash Script Example
```bash
#!/bin/bash
# Automated security assessment script

SESSION_NAME="security-audit-$(date +%Y%m%d-%H%M%S)"

# Function to run Pacu commands
run_pacu_cmd() {
    echo "Running: $1"
    pacu --session "$SESSION_NAME" --exec "$1"
}

# Set up session and import credentials
pacu --session "$SESSION_NAME"
run_pacu_cmd "import_keys --env"

# Run security analysis modules
MODULES=(
    "iam__enum_permissions"
    "iam__enum_users_roles_policies_groups"
    "iam__privesc_scan --scan-only --include-managed-policies"
    "iam__get_credential_report"
)

for module in "${MODULES[@]}"; do
    run_pacu_cmd "run $module"
done

# Export results
run_pacu_cmd "data all > security-report-$SESSION_NAME.json"
```

## Integration with Other Tools

### AWS CLI Integration
```bash
# Use AWS CLI profiles with environment variables
aws configure set aws_access_key_id "$AWS_ACCESS_KEY_ID" --profile pacu-assessment
aws configure set aws_secret_access_key "$AWS_SECRET_ACCESS_KEY" --profile pacu-assessment

# Verify setup
aws sts get-caller-identity --profile pacu-assessment

# Use in Pacu
pacu (session) > aws sts get-caller-identity --profile pacu-assessment
```

### ScoutSuite Integration
```bash
# Run ScoutSuite analysis
scout aws --access-key-id "$AWS_ACCESS_KEY_ID" --secret-access-key "$AWS_SECRET_ACCESS_KEY"

# Run Pacu analysis with same credentials  
pacu (session) > import_keys --env
pacu (session) > run iam__privesc_scan --include-managed-policies

# Compare findings between tools
```

This guide provides comprehensive examples and best practices for using the new Pacu enhancements effectively and securely.