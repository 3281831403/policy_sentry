import unittest
import json
import os
from policy_sentry.writing.sid_group import SidGroup

crud_with_override_template = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        os.path.pardir,
        os.path.pardir,
        "examples",
        "crud-with-override.yml",
    )
)


class SidGroupActionsTestCase(unittest.TestCase):
    def test_actions_test_case(self):
        cfg = {
            "mode": "actions",
            "name": "RoleNameWithCRUD",
            "actions": [
                "codestar-connections:UseConnection",
                "kms:CreateGrant",
                "kms:CreateCustomKeyStore",
                "ec2:AuthorizeSecurityGroupEgress",
                "ec2:AuthorizeSecurityGroupIngress",
            ],
        }
        sid_group = SidGroup()
        output = sid_group.process_template(cfg)
        print(json.dumps(output, indent=4))
        desired_output = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "CodestarconnectionsReadConnection",
                    "Effect": "Allow",
                    "Action": ["codestar-connections:UseConnection"],
                    "Resource": [
                        "arn:${Partition}:codestar-connections:${Region}:${Account}:connection/${ConnectionId}"
                    ],
                },
                {
                    "Sid": "KmsPermissionsmanagementKey",
                    "Effect": "Allow",
                    "Action": ["kms:CreateGrant"],
                    "Resource": ["arn:${Partition}:kms:${Region}:${Account}:key/${KeyId}"],
                },
                {
                    "Sid": "MultMultNone",
                    "Effect": "Allow",
                    "Action": ["cloudhsm:DescribeClusters", "kms:CreateCustomKeyStore"],
                    "Resource": ["*"],
                },
                {
                    "Sid": "Ec2WriteSecuritygroup",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:AuthorizeSecurityGroupEgress",
                        "ec2:AuthorizeSecurityGroupIngress",
                    ],
                    "Resource": ["arn:${Partition}:ec2:${Region}:${Account}:security-group/${SecurityGroupId}"],
                },
            ],
        }
        expected_statement_ids = [
            "CodestarconnectionsReadConnection",
            "KmsPermissionsmanagementKey",
            "MultMultNone",
            "Ec2WriteSecuritygroup",
            "Ec2WriteSecuritygrouprule",
        ]
        for statement in output.get("Statement"):
            self.assertTrue(statement.get("Sid") in expected_statement_ids)

    def test_actions_with_resource_arns_from_other_services(self) -> None:
        """Actions whose resource ARN belongs to a different service (or a placeholder
        like ${Vendor}) must be scoped to the raw ARN of their declared resource type,
        not silently dropped."""
        cfg = {
            "mode": "actions",
            "name": "ForeignArns",
            "actions": [
                "kafka-cluster:DescribeCluster",
                "cloudfront-keyvaluestore:GetKey",
                "backup:DescribeRecoveryPoint",
            ],
        }
        sid_group = SidGroup()
        output = sid_group.process_template(cfg)
        print(json.dumps(output, indent=4))
        desired_output = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "KafkaclusterListCluster",
                    "Effect": "Allow",
                    "Action": ["kafka-cluster:DescribeCluster"],
                    "Resource": [
                        "arn:${Partition}:kafka:${Region}:${Account}:cluster/${ClusterName}/${ClusterUuid}"
                    ],
                },
                {
                    "Sid": "CloudfrontkeyvaluestoreReadKeyvaluestore",
                    "Effect": "Allow",
                    "Action": ["cloudfront-keyvaluestore:GetKey"],
                    "Resource": ["arn:${Partition}:cloudfront::${Account}:key-value-store/${ResourceId}"],
                },
                {
                    "Sid": "BackupReadRecoverypoint",
                    "Effect": "Allow",
                    "Action": ["backup:DescribeRecoveryPoint"],
                    "Resource": ["arn:${Partition}:${Vendor}:${Region}:*:${ResourceType}:${RecoveryPointId}"],
                },
                {
                    "Sid": "KafkaclusterWriteCluster",
                    "Effect": "Allow",
                    "Action": ["kafka-cluster:Connect"],
                    "Resource": [
                        "arn:${Partition}:kafka:${Region}:${Account}:cluster/${ClusterName}/${ClusterUuid}"
                    ],
                },
            ],
        }
        self.maxDiff = None
        self.assertDictEqual(output, desired_output)

    def test_actions_with_foreign_resource_arns_are_not_wildcard_only(self) -> None:
        """An action that declares resource types must not be scoped to '*' only, even
        when it also supports wildcard ARNs and its resource ARN belongs to another service."""
        cfg = {
            "mode": "actions",
            "name": "ForeignArnNotWildcard",
            "actions": ["rds-data:BeginTransaction"],
        }
        sid_group = SidGroup()
        output = sid_group.process_template(cfg)
        print(json.dumps(output, indent=4))
        desired_output = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RdsdataWriteCluster",
                    "Effect": "Allow",
                    "Action": ["rds-data:BeginTransaction"],
                    "Resource": ["arn:${Partition}:rds:${Region}:${Account}:cluster:${DbClusterInstanceName}"],
                },
            ],
        }
        self.maxDiff = None
        self.assertDictEqual(output, desired_output)

    def test_dependent_actions_with_foreign_resource_arns_are_scoped(self) -> None:
        """Dependent actions whose only resource types belong to another service must be
        scoped to the declared raw ARN instead of being dumped into MultMultNone with '*'."""
        cfg = {
            "mode": "actions",
            "name": "ForeignArnDependents",
            "actions": ["kafka-cluster:DescribeCluster", "kafka-cluster:DescribeTopic"],
        }
        sid_group = SidGroup()
        output = sid_group.process_template(cfg)
        print(json.dumps(output, indent=4))
        desired_output = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "KafkaclusterListCluster",
                    "Effect": "Allow",
                    "Action": ["kafka-cluster:DescribeCluster"],
                    "Resource": [
                        "arn:${Partition}:kafka:${Region}:${Account}:cluster/${ClusterName}/${ClusterUuid}"
                    ],
                },
                {
                    "Sid": "KafkaclusterListTopic",
                    "Effect": "Allow",
                    "Action": ["kafka-cluster:DescribeTopic"],
                    "Resource": [
                        "arn:${Partition}:kafka:${Region}:${Account}:topic/${ClusterName}/${ClusterUuid}/${TopicName}"
                    ],
                },
                {
                    "Sid": "KafkaclusterWriteCluster",
                    "Effect": "Allow",
                    "Action": ["kafka-cluster:Connect"],
                    "Resource": [
                        "arn:${Partition}:kafka:${Region}:${Account}:cluster/${ClusterName}/${ClusterUuid}"
                    ],
                },
            ],
        }
        self.maxDiff = None
        self.assertDictEqual(output, desired_output)
