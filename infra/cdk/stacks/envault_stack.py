"""CDK stack for envault — provisions DynamoDB, S3, KMS, and IAM resources."""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
)
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cw_actions
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_sns as sns
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
        # Parameters                                                            #
        # ------------------------------------------------------------------ #
        table_name_param = cdk.CfnParameter(
            self,
            "TableNameParam",
            type="String",
            default="envault-state",
            description="Name for the DynamoDB state table.",
            allowed_pattern=r"[a-zA-Z0-9_.\-]+",
            min_length=3,
            max_length=255,
        )
        policy_name_param = cdk.CfnParameter(
            self,
            "PolicyNameParam",
            type="String",
            default="EnvaultUserPolicy",
            description="Name for the IAM managed policy.",
            allowed_pattern=r"[\w+=,.@\-]+",
            min_length=1,
            max_length=128,
        )

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

        # Deny key deletion for all principals — requires removing this
        # policy statement first (break-glass procedure).
        encryption_key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="DenyScheduleKeyDeletion",
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["kms:ScheduleKeyDeletion", "kms:DisableKey"],
                resources=["*"],
            )
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
            bucket_key_enabled=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            server_access_logs_bucket=access_logs_bucket,
            server_access_logs_prefix="envault-access-logs/",
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                # Move old non-current versions to GLACIER after 90 days,
                # then expire after 365 days to prevent unbounded growth
                # from key rotation creating new versions per file.
                s3.LifecycleRule(
                    noncurrent_version_transitions=[
                        s3.NoncurrentVersionTransition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(90),
                        )
                    ],
                    noncurrent_version_expiration=Duration.days(365),
                )
            ],
        )

        # ------------------------------------------------------------------ #
        # DynamoDB Table (single-table design)                                 #
        # ------------------------------------------------------------------ #
        table = dynamodb.Table(
            self,
            "EnvaultStateTable",
            table_name=table_name_param.value_as_string,
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

        # GSI: query all files in a given state.
        # Projection ALL is required: rotate-key reads all attributes from this index.
        # Changing projection type would cause CloudFormation table replacement.
        table.add_global_secondary_index(
            index_name="state-index",
            partition_key=dynamodb.Attribute(name="current_state", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="encrypted_at", type=dynamodb.AttributeType.STRING),
            projection_type=dynamodb.ProjectionType.ALL,
        )

        # GSI: query all events on a given calendar date.
        # Projection ALL kept to avoid CloudFormation table replacement on existing stacks.
        # For new deployments, INCLUDE with [SK, file_name, sha256_hash, correlation_id,
        # operation] would reduce storage and exposure surface.
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
            managed_policy_name=policy_name_param.value_as_string,
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
        # Monitoring — SNS + CloudWatch Alarms                                #
        # ------------------------------------------------------------------ #
        ops_topic = sns.Topic(
            self,
            "EnvaultOpsTopic",
            display_name="envault operational alerts",
            enforce_ssl=True,
        )

        # DynamoDB throttle alarm
        table.metric_throttled_requests_for_operation("PutItem").create_alarm(
            self,
            "DynamoThrottleAlarm",
            alarm_name="envault-dynamodb-throttle",
            evaluation_periods=1,
            threshold=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        ).add_alarm_action(cw_actions.SnsAction(ops_topic))

        # DynamoDB system errors — use a math expression over the four
        # operations envault actually calls to stay within the 10-metric
        # alarm limit imposed by CloudWatch.
        sys_err_metrics: dict[str, cloudwatch.IMetric] = {}
        for op in ("PutItem", "GetItem", "Query", "UpdateItem"):
            sys_err_metrics[op.lower()] = cloudwatch.Metric(
                namespace="AWS/DynamoDB",
                metric_name="SystemErrors",
                dimensions_map={
                    "TableName": table.table_name,
                    "Operation": op,
                },
                statistic="Sum",
                period=Duration.minutes(5),
            )
        sys_err_expression = cloudwatch.MathExpression(
            expression=" + ".join(sys_err_metrics.keys()),
            using_metrics=sys_err_metrics,
            label="DynamoDB SystemErrors (envault operations)",
            period=Duration.minutes(5),
        )
        sys_err_expression.create_alarm(
            self,
            "DynamoSystemErrorAlarm",
            alarm_name="envault-dynamodb-system-errors",
            evaluation_periods=1,
            threshold=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        ).add_alarm_action(cw_actions.SnsAction(ops_topic))

        cdk.CfnOutput(self, "OpsTopicArn", value=ops_topic.topic_arn)

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
