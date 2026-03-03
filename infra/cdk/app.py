#!/usr/bin/env python3
"""CDK app entry point for envault infrastructure."""

import aws_cdk as cdk
from stacks.envault_stack import EnvaultStack

app = cdk.App()
EnvaultStack(
    app,
    "EnvaultStack",
    description="envault — KMS envelope encryption state management infrastructure",
)
app.synth()
