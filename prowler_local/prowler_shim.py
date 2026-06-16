"""
prowler_shim.py — Minimal AwsProvider shim.

Replaces the full Prowler AwsProvider with a lightweight version
that accepts a boto3 session directly. This allows running all 608
Prowler checks without installing prowler as a package.
"""
import sys
import os
from dataclasses import dataclass, field
from typing import Optional, List, Dict
import boto3
import botocore

@dataclass
class AWSIdentity:
    account: str
    account_arn: str
    partition: str
    audited_regions: list
    user_id: str = ""

@dataclass  
class AWSSession:
    current_session: boto3.Session

@dataclass
class AuditMetadata:
    expected_checks: list = field(default_factory=list)
    services_scanned: int = 0
    completed_checks: int = 0
    audit_progress: float = 0.0

class MinimalAwsProvider:
    """
    Minimal shim that satisfies AWSService.__init__ requirements.
    Takes a boto3 session and account info directly.
    """
    def __init__(
        self,
        boto3_session: boto3.Session,
        account_id: str,
        account_name: str,
        regions: List[str],
        checks: List[str] = None,
    ):
        self._boto3_session = boto3_session
        self._regions = regions
        self._account_name = account_name

        # Detect partition from region
        partition = "aws"
        if regions and regions[0].startswith("cn-"):
            partition = "aws-cn"
        elif regions and regions[0].startswith("us-gov"):
            partition = "aws-us-gov"

        self.identity = AWSIdentity(
            account=account_id,
            account_arn=f"arn:{partition}:iam::{account_id}:root",
            partition=partition,
            audited_regions=regions,
        )

        self.session = AWSSession(current_session=boto3_session)
        self.audit_metadata = AuditMetadata(expected_checks=checks or [])
        self.audit_config = {}
        self.fixer_config = {}
        self.audit_resources = []
        self.output_options = None
        self.mutelist = None

    def generate_regional_clients(self, service: str) -> Dict[str, any]:
        """Return {region: boto3_client} for each audited region."""
        clients = {}
        for region in self._regions:
            try:
                clients[region] = self._boto3_session.client(
                    service, region_name=region
                )
            except Exception:
                pass
        return clients

    def get_global_region(self) -> str:
        return self._regions[0] if self._regions else "eu-west-1"
