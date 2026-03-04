"""CDK stack for envault — provisions DynamoDB, S3, KMS, and IAM resources."""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
)
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_s3 as s3
from cdk_nag import NagSuppressions
from constructs import Construct


class EnvaultStack(Stack):
    """Provisions all AWS resources required by envault.

    Resources:
      - KMS Customer Managed Key with annual rotation
      - S3 bucket with versioning, SSE-KMS, and block public access
      - DynamoDB table with single-table design, GSIs, PITR, and KMS encryption
      - IAM managed policy for least-privilege access
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs: object) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ------------------------------------------------------------------ #
        # KMS Customer Managed Key                                             #
        # ------------------------------------------------------------------ #
        encryption_key = kms.Key(
            self,
            "EnvaultKey",
            description="envault — envelope encryption key for file data keys",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN,  # never auto-delete a KMS key
        )
        kms.Alias(
            self,
            "EnvaultKeyAlias",
            alias_name="alias/envault",
            target_key=encryption_key,
        )

        # ------------------------------------------------------------------ #
        # S3 Access Logging Bucket                                              #
        # ------------------------------------------------------------------ #
        access_logs_bucket = s3.Bucket(
            self,
            "EnvaultAccessLogsBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    expiration=Duration.days(365),
                )
            ],
        )

        # ------------------------------------------------------------------ #
        # S3 Bucket                                                            #
        # ------------------------------------------------------------------ #
        bucket = s3.Bucket(
            self,
            "EnvaultBucket",
            versioned=True,
            encryption=s3.BucketEncryption.KMS,
            encryption_key=encryption_key,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            server_access_logs_bucket=access_logs_bucket,
            server_access_logs_prefix="envault-access-logs/",
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                # Move old non-current versions to GLACIER after 90 days
                s3.LifecycleRule(
                    noncurrent_version_transitions=[
                        s3.NoncurrentVersionTransition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(90),
                        )
                    ]
                )
            ],
        )

        # ------------------------------------------------------------------ #
        # DynamoDB Table (single-table design)                                 #
        # ------------------------------------------------------------------ #
        table = dynamodb.Table(
            self,
            "EnvaultStateTable",
            table_name="envault-state",
            partition_key=dynamodb.Attribute(name="PK", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="SK", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=encryption_key,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            deletion_protection=True,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.RETAIN,
        )

        # GSI: query all files in a given state
        table.add_global_secondary_index(
            index_name="state-index",
            partition_key=dynamodb.Attribute(name="current_state", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="encrypted_at", type=dynamodb.AttributeType.STRING),
            projection_type=dynamodb.ProjectionType.ALL,
        )

        # GSI: query all events on a given calendar date
        table.add_global_secondary_index(
            index_name="date-index",
            partition_key=dynamodb.Attribute(name="date", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="last_updated", type=dynamodb.AttributeType.STRING),
            projection_type=dynamodb.ProjectionType.ALL,
        )

        # ------------------------------------------------------------------ #
        # IAM Managed Policy (least-privilege)                                 #
        # ------------------------------------------------------------------ #
        policy = iam.ManagedPolicy(
            self,
            "EnvaultUserPolicy",
            managed_policy_name="EnvaultUserPolicy",
            description="Least-privilege access for envault CLI users",
            statements=[
                iam.PolicyStatement(
                    sid="KmsEnvelopeEncryption",
                    actions=["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"],
                    resources=[encryption_key.key_arn],
                ),
                iam.PolicyStatement(
                    sid="S3EncryptedObjects",
                    actions=[
                        "s3:PutObject",
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                        "s3:ListBucket",
                    ],
                    resources=[bucket.bucket_arn, f"{bucket.bucket_arn}/*"],
                ),
                iam.PolicyStatement(
                    sid="DynamoDBStateAccess",
                    actions=[
                        "dynamodb:PutItem",
                        "dynamodb:GetItem",
                        "dynamodb:Query",
                        "dynamodb:UpdateItem",
                    ],
                    resources=[table.table_arn, f"{table.table_arn}/index/*"],
                ),
            ],
        )

        # ------------------------------------------------------------------ #
        # cdk-nag suppressions for scoped wildcards                            #
        # ------------------------------------------------------------------ #
        NagSuppressions.add_resource_suppressions(
            policy,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": (
                        "S3 object-level actions (PutObject, GetObject) require"
                        " bucket/* wildcard. Access is scoped to the single"
                        " envault bucket."
                    ),
                    "applies_to": [
                        f"Resource::<{bucket.node.id}.Arn>/*",
                    ],
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": (
                        "DynamoDB GSI queries require table/index/* wildcard."
                        " Access is scoped to the single envault table and"
                        " only allows read/write operations."
                    ),
                    "applies_to": [
                        f"Resource::<{table.node.id}.Arn>/index/*",
                    ],
                },
            ],
        )

        # ------------------------------------------------------------------ #
        # CloudFormation Outputs                                               #
        # ------------------------------------------------------------------ #
        cdk.CfnOutput(self, "KmsKeyAlias", value="alias/envault")
        cdk.CfnOutput(self, "BucketName", value=bucket.bucket_name)
        cdk.CfnOutput(self, "TableName", value=table.table_name)
        cdk.CfnOutput(self, "ManagedPolicyArn", value=policy.managed_policy_arn)

        cdk.CfnOutput(
            self,
            "EnvaultEnvVars",
            value=(
                f"export ENVAULT_KEY_ID=alias/envault\n"
                f"export ENVAULT_BUCKET={bucket.bucket_name}\n"
                f"export ENVAULT_TABLE={table.table_name}"
            ),
            description="Copy-paste these env vars to configure the envault CLI",
        )
