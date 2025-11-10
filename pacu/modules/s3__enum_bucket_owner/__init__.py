"""Module for enumerating S3 bucket owner account IDs."""
module_info = {
    'name': 's3__enum_bucket_owner',
    'author': 'Made Pradipta',
    'category': 'ENUM',
    'one_liner': 'Enumerates AWS account IDs of S3 bucket owners',
    'description': 'This module attempts to enumerate the AWS account IDs of S3 bucket owners by leveraging the s3:ResourceAccount condition in IAM policies.',
    'services': ['S3', 'IAM', 'STS'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--buckets', '--role-arn']
}
