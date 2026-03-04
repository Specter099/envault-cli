#!/usr/bin/env python3
"""CDK app entry point for envault infrastructure."""

import aws_cdk as cdk
from cdk_nag import AwsSolutionsChecks
from stacks.envault_stack import EnvaultStack

app = cdk.App()
cdk.Aspects.of(app).add(AwsSolutionsChecks())
EnvaultStack(
    app,
    "EnvaultStack",
    description="envault — KMS envelope encryption state management infrastructure",
)
app.synth()
