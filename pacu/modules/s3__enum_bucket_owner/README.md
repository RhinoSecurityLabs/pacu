# S3 Account Enumerator

## Description

This module discovers AWS account IDs that own specified S3 buckets using IAM policy conditions (s3:ResourceAccount). It works by leveraging STS assume-role with policy intersection to determine the account ID one digit at a time.

## Role Requirements

You must have ONE of the following:

1. An existing role that:

   - You have permission to assume
   - Has the necessary S3 permissions
   - Example: `arn:aws:iam::123456789012:role/my-role`

2. OR permissions to create IAM roles:
   - Requires IAM write access
   - The module will create and manage a temporary role
   - The temporary role will be automatically cleaned up

## Required Permissions

For using an existing role:

- `sts:AssumeRole` on the specified role

For creating a temporary role:

- `iam:CreateRole`
- `iam:PutRolePolicy`
- `iam:DeleteRole`
- `iam:DeleteRolePolicy`

## Usage

1. Using an existing role (recommended):

```bash
run s3__enum_account --buckets my-bucket1,my-bucket2 --role-arn arn:aws:iam::123456789012:role/my-role
```

2. Using automatic role creation (requires IAM permissions):

```bash
run s3__enum_account --buckets my-bucket1,my-bucket2
```

## Arguments

- `--buckets`: Comma-separated list of bucket names to enumerate
- `--role-arn`: (Optional) Role ARN to use for enumeration. If not provided, the module will attempt to create a temporary role (requires IAM permissions)

## Examples

1. Enumerate single bucket with existing role:

```bash
run s3__enum_account --buckets company-assets --role-arn arn:aws:iam::123456789012:role/s3-readonly
```

2. Enumerate multiple buckets with automatic role creation:

```bash
run s3__enum_account --buckets bucket1,bucket2,bucket3
```

## Error Messages

1. No role provided and no IAM permissions:

```
ERROR: No role ARN provided and no permissions to create a temporary role.
You must either:
1. Provide an existing role ARN with --role-arn
2. Or have IAM permissions to create a temporary role
```

2. Failed to create temporary role:

```
Failed to create temporary role.
```

## References

- [Finding the Account ID of any public S3 bucket](https://cloudar.be/awsblog/finding-the-account-id-of-any-public-s3-bucket/)
