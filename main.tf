# S3 Bucket for AWS Config
resource "aws_s3_bucket" "config" {
  bucket = "${var.project_name}-${var.environment}-config-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    var.tags,
    {
      Name = "${var.project_name}-${var.environment}-config"
      Type = "config-storage"
    }
  )
}

# S3 Bucket Versioning
resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id

  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket Server Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_id != null ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_id
    }
  }
}

# S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "config" {
  bucket = aws_s3_bucket.config.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket Lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    id     = "config-retention"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = var.config_retention_days
    }
  }
}

# S3 Bucket Policy for AWS Config
resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = data.aws_iam_policy_document.config_bucket_policy.json
}

data "aws_iam_policy_document" "config_bucket_policy" {
  statement {
    sid    = "AWSConfigBucketPermissionsCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config.arn]
  }

  statement {
    sid    = "AWSConfigBucketExistenceCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.config.arn]
  }

  statement {
    sid    = "AWSConfigBucketDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config.arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

# IAM Role for Config
resource "aws_iam_role" "config" {
  name               = "${var.project_name}-${var.environment}-config-role"
  assume_role_policy = data.aws_iam_policy_document.config_assume_role.json

  tags = var.tags
}

data "aws_iam_policy_document" "config_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

# IAM Policy for Config
resource "aws_iam_role_policy" "config" {
  name   = "${var.project_name}-${var.environment}-config-policy"
  role   = aws_iam_role.config.id
  policy = data.aws_iam_policy_document.config_permissions.json
}

data "aws_iam_policy_document" "config_permissions" {
  # S3 permissions
  statement {
    effect = "Allow"
    actions = [
      "s3:GetBucketVersioning",
      "s3:PutBucketVersioning",
      "s3:GetBucketNotification",
      "s3:PutBucketNotification",
      "s3:GetBucketAcl",
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.config.arn,
      "${aws_s3_bucket.config.arn}/*"
    ]
  }

  # Resource permissions
  statement {
    effect = "Allow"
    actions = [
      "config:Put*",
      "ec2:Describe*",
      "elasticloadbalancing:Describe*",
      "rds:Describe*",
      "s3:GetBucket*",
      "s3:List*",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:GetUser",
      "iam:GetUserPolicy",
      "iam:ListUserPolicies",
      "iam:ListAttachedUserPolicies",
      "tag:GetResources",
      "tag:GetTagKeys",
      "tag:GetTagValues",
      "lambda:List*",
      "lambda:Get*"
    ]
    resources = ["*"]
  }
}

# Config Recorder
resource "aws_config_configuration_recorder" "main" {
  name     = "${var.project_name}-${var.environment}-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = var.record_all_resources
    include_global_resource_types = true
    resource_types                = var.record_all_resources ? null : var.selected_resource_types
  }

  depends_on = [aws_config_delivery_channel.main]
}

# Config Delivery Channel
resource "aws_config_delivery_channel" "main" {
  name           = "${var.project_name}-${var.environment}-delivery"
  s3_bucket_name = aws_s3_bucket.config.bucket

  dynamic "snapshot_delivery_properties" {
    for_each = var.enable_config_snapshots ? [1] : []
    content {
      delivery_frequency = var.snapshot_delivery_frequency
    }
  }

  depends_on = [aws_s3_bucket_policy.config]
}

# Start Config Recorder
resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_configuration_recorder.main]
}

# Config Rules
resource "aws_config_config_rule" "rules" {
  for_each = var.config_rules

  name        = "${var.project_name}-${var.environment}-${each.key}"
  description = each.value.description

  source {
    owner             = each.value.source_owner
    source_identifier = each.value.source_identifier
  }

  input_parameters = each.value.input_parameters

  maximum_execution_frequency = each.value.maximum_execution_frequency

  dynamic "scope" {
    for_each = each.value.scope != null ? [each.value.scope] : []
    content {
      compliance_resource_id    = scope.value.compliance_resource_id
      compliance_resource_types = scope.value.compliance_resource_types
      tag_key                   = scope.value.tag_key
      tag_value                 = scope.value.tag_value
    }
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# SNS Topic for Alerts
resource "aws_sns_topic" "alerts" {
  name              = "${var.project_name}-${var.environment}-monitoring-alerts"
  kms_master_key_id = var.sns_kms_key_id

  tags = merge(
    var.tags,
    {
      Name = "${var.project_name}-${var.environment}-monitoring-alerts"
    }
  )
}

# SNS Topic Policy
resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.sns_topic_policy.json
}

data "aws_iam_policy_document" "sns_topic_policy" {
  statement {
    sid    = "AllowServicesToPublish"
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = [
        "cloudwatch.amazonaws.com",
        "config.amazonaws.com",
        "events.amazonaws.com"
      ]
    }
    actions = [
      "SNS:Publish",
      "SNS:GetTopicAttributes",
      "SNS:SetTopicAttributes"
    ]
    resources = [aws_sns_topic.alerts.arn]
  }
}

# SNS Topic Subscriptions
resource "aws_sns_topic_subscription" "email_alerts" {
  for_each = toset(var.alert_emails)

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

# CloudWatch Log Group for Config
resource "aws_cloudwatch_log_group" "config" {
  count = var.enable_cloudwatch_logs_for_config ? 1 : 0

  name              = "/aws/config/${var.project_name}-${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.cloudwatch_kms_key_arn

  tags = var.tags
}

# CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.project_name}-${var.environment}-monitoring"

  dashboard_body = jsonencode({
    widgets = concat(
      # EC2 Widgets
      var.monitored_resources.instance_ids != null ? [
        {
          type   = "metric"
          x      = 0
          y      = 0
          width  = 12
          height = 6
          properties = {
            metrics = [
              for instance_id in var.monitored_resources.instance_ids : [
                "AWS/EC2", "CPUUtilization",
                { stat = "Average", dimensions = { InstanceId = instance_id } }
              ]
            ]
            period = 300
            stat   = "Average"
            region = data.aws_region.current.name
            title  = "EC2 CPU Utilization"
            yAxis = {
              left = {
                min = 0
                max = 100
              }
            }
          }
        },
        {
          type   = "metric"
          x      = 12
          y      = 0
          width  = 12
          height = 6
          properties = {
            metrics = [
              for instance_id in var.monitored_resources.instance_ids : [
                ["AWS/EC2", "StatusCheckFailed", { dimensions = { InstanceId = instance_id } }],
                [".", "StatusCheckFailed_Instance", { dimensions = { InstanceId = instance_id } }],
                [".", "StatusCheckFailed_System", { dimensions = { InstanceId = instance_id } }]
              ]
            ]
            period = 60
            stat   = "Sum"
            region = data.aws_region.current.name
            title  = "EC2 Status Checks"
          }
        }
      ] : [],
      
      # VPC Widgets
      var.monitored_resources.vpc_id != null ? [
        {
          type   = "metric"
          x      = 0
          y      = 6
          width  = 12
          height = 6
          properties = {
            metrics = [
              ["AWS/VPC", "BytesIn", { dimensions = { VPC = var.monitored_resources.vpc_id } }],
              [".", "BytesOut", { dimensions = { VPC = var.monitored_resources.vpc_id } }]
            ]
            period = 300
            stat   = "Sum"
            region = data.aws_region.current.name
            title  = "VPC Network Traffic"
          }
        }
      ] : [],
      
      # Config Compliance Widget
      [
        {
          type   = "metric"
          x      = 12
          y      = 6
          width  = 12
          height = 6
          properties = {
            metrics = [
              ["AWS/Config", "ComplianceScore", { stat = "Average" }]
            ]
            period = 300
            stat   = "Average"
            region = data.aws_region.current.name
            title  = "Config Compliance Score"
            yAxis = {
              left = {
                min = 0
                max = 100
              }
            }
          }
        }
      ],
      
      # Custom Widgets
      var.custom_dashboard_widgets
    )
  })
}

# CloudWatch Alarms for Config Compliance
resource "aws_cloudwatch_metric_alarm" "config_compliance" {
  for_each = var.enable_config_compliance_alarms ? var.config_rules : {}

  alarm_name          = "${var.project_name}-${var.environment}-config-${each.key}-non-compliant"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ComplianceByConfigRule"
  namespace           = "AWS/Config"
  period              = "300"
  statistic           = "Average"
  threshold           = "1"
  alarm_description   = "Config rule ${each.key} has non-compliant resources"
  treat_missing_data  = "breaching"

  dimensions = {
    ConfigRuleName = aws_config_config_rule.rules[each.key].name
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  tags = var.tags
}

# EventBridge Rule for Config Changes
resource "aws_cloudwatch_event_rule" "config_changes" {
  count = var.enable_config_change_notifications ? 1 : 0

  name        = "${var.project_name}-${var.environment}-config-changes"
  description = "Capture Config compliance changes"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      messageType = ["ComplianceChangeNotification"]
    }
  })

  tags = var.tags
}

# EventBridge Target for Config Changes
resource "aws_cloudwatch_event_target" "config_sns" {
  count = var.enable_config_change_notifications ? 1 : 0

  rule      = aws_cloudwatch_event_rule.config_changes[0].name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn
}

# Lambda for Custom Metrics (Optional)
resource "aws_lambda_function" "custom_metrics" {
  count = var.enable_custom_metrics ? 1 : 0

  filename         = data.archive_file.custom_metrics_lambda[0].output_path
  function_name    = "${var.project_name}-${var.environment}-custom-metrics"
  role            = aws_iam_role.lambda_custom_metrics[0].arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.custom_metrics_lambda[0].output_base64sha256
  runtime         = "python3.9"
  timeout         = 60

  environment {
    variables = {
      PROJECT_NAME = var.project_name
      ENVIRONMENT  = var.environment
    }
  }

  tags = var.tags
}

# Lambda code archive
data "archive_file" "custom_metrics_lambda" {
  count = var.enable_custom_metrics ? 1 : 0

  type        = "zip"
  output_path = "${path.module}/lambda/custom_metrics.zip"

  source {
    content  = <<-EOT
import json
import boto3
import os
from datetime import datetime
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client('ec2')
cloudwatch = boto3.client('cloudwatch')

PROJECT_NAME = os.environ['PROJECT_NAME']
ENVIRONMENT = os.environ['ENVIRONMENT']

def handler(event, context):
    """
    Collect and publish custom metrics to CloudWatch
    """
    logger.info(f"Starting custom metrics collection for {PROJECT_NAME}-{ENVIRONMENT}")
    
    try:
        # Collect EC2 metrics
        ec2_metrics = collect_ec2_metrics()
        
        # Collect VPC metrics
        vpc_metrics = collect_vpc_metrics()
        
        # Collect tag compliance metrics
        tag_metrics = collect_tag_compliance_metrics()
        
        # Combine all metrics
        all_metrics = ec2_metrics + vpc_metrics + tag_metrics
        
        # Publish to CloudWatch
        if all_metrics:
            publish_metrics(all_metrics)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Custom metrics published successfully',
                'metrics_count': len(all_metrics)
            })
        }
        
    except Exception as e:
        logger.error(f"Error collecting custom metrics: {str(e)}")
        raise

def collect_ec2_metrics():
    """Collect custom EC2 metrics"""
    metrics = []
    
    try:
        # Get all instances for the project
        response = ec2.describe_instances(
            Filters=[
                {'Name': 'tag:Project', 'Values': [PROJECT_NAME]},
                {'Name': 'tag:Environment', 'Values': [ENVIRONMENT]},
                {'Name': 'instance-state-name', 'Values': ['running']}
            ]
        )
        
        # Count instances by type
        instance_types = {}
        total_instances = 0
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_type = instance['InstanceType']
                instance_types[instance_type] = instance_types.get(instance_type, 0) + 1
                total_instances += 1
        
        # Create metrics
        metrics.append({
            'MetricName': 'TotalRunningInstances',
            'Value': total_instances,
            'Unit': 'Count',
            'Dimensions': [
                {'Name': 'Project', 'Value': PROJECT_NAME},
                {'Name': 'Environment', 'Value': ENVIRONMENT}
            ]
        })
        
        # Metrics per instance type
        for instance_type, count in instance_types.items():
            metrics.append({
                'MetricName': 'InstancesByType',
                'Value': count,
                'Unit': 'Count',
                'Dimensions': [
                    {'Name': 'Project', 'Value': PROJECT_NAME},
                    {'Name': 'Environment', 'Value': ENVIRONMENT},
                    {'Name': 'InstanceType', 'Value': instance_type}
                ]
            })
        
    except Exception as e:
        logger.error(f"Error collecting EC2 metrics: {str(e)}")
    
    return metrics

def collect_vpc_metrics():
    """Collect custom VPC metrics"""
    metrics = []
    
    try:
        # Get VPCs
        vpcs_response = ec2.describe_vpcs(
            Filters=[
                {'Name': 'tag:Project', 'Values': [PROJECT_NAME]},
                {'Name': 'tag:Environment', 'Values': [ENVIRONMENT]}
            ]
        )
        
        for vpc in vpcs_response['Vpcs']:
            vpc_id = vpc['VpcId']
            
            # Count subnets
            subnets_response = ec2.describe_subnets(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )
            
            metrics.append({
                'MetricName': 'SubnetCount',
                'Value': len(subnets_response['Subnets']),
                'Unit': 'Count',
                'Dimensions': [
                    {'Name': 'Project', 'Value': PROJECT_NAME},
                    {'Name': 'Environment', 'Value': ENVIRONMENT},
                    {'Name': 'VpcId', 'Value': vpc_id}
                ]
            })
            
    except Exception as e:
        logger.error(f"Error collecting VPC metrics: {str(e)}")
    
    return metrics

def collect_tag_compliance_metrics():
    """Collect tag compliance metrics"""
    metrics = []
    required_tags = ['Project', 'Environment', 'Owner']
    
    try:
        # Check EC2 instances
        instances_response = ec2.describe_instances()
        total_instances = 0
        compliant_instances = 0
        
        for reservation in instances_response['Reservations']:
            for instance in reservation['Instances']:
                if instance['State']['Name'] == 'running':
                    total_instances += 1
                    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    
                    if all(tag in tags for tag in required_tags):
                        compliant_instances += 1
        
        if total_instances > 0:
            metrics.append({
                'MetricName': 'TagComplianceRate',
                'Value': (compliant_instances / total_instances) * 100,
                'Unit': 'Percent',
                'Dimensions': [
                    {'Name': 'Project', 'Value': PROJECT_NAME},
                    {'Name': 'Environment', 'Value': ENVIRONMENT},
                    {'Name': 'ResourceType', 'Value': 'EC2Instance'}
                ]
            })
        
    except Exception as e:
        logger.error(f"Error collecting tag compliance metrics: {str(e)}")
    
    return metrics

def publish_metrics(metrics):
    """Publish metrics to CloudWatch"""
    namespace = f"{PROJECT_NAME}/{ENVIRONMENT}/Custom"
    
    # CloudWatch PutMetricData accepts max 20 metrics per call
    for i in range(0, len(metrics), 20):
        batch = metrics[i:i+20]
        
        try:
            cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=batch
            )
            logger.info(f"Published {len(batch)} metrics to CloudWatch")
        except Exception as e:
            logger.error(f"Error publishing metrics batch: {str(e)}")
            raise
    EOT
    filename = "index.py"
  }
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda_custom_metrics" {
  count = var.enable_custom_metrics ? 1 : 0

  name = "${var.project_name}-${var.environment}-lambda-metrics-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# Lambda Policy
resource "aws_iam_role_policy" "lambda_custom_metrics" {
  count = var.enable_custom_metrics ? 1 : 0

  name = "${var.project_name}-${var.environment}-lambda-metrics-policy"
  role = aws_iam_role.lambda_custom_metrics[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "rds:DescribeDBInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

# EventBridge Rule for Custom Metrics
resource "aws_cloudwatch_event_rule" "custom_metrics_schedule" {
  count = var.enable_custom_metrics ? 1 : 0

  name                = "${var.project_name}-${var.environment}-custom-metrics-schedule"
  description         = "Trigger custom metrics collection"
  schedule_expression = var.custom_metrics_schedule

  tags = var.tags
}

# EventBridge Target for Custom Metrics
resource "aws_cloudwatch_event_target" "custom_metrics_lambda" {
  count = var.enable_custom_metrics ? 1 : 0

  rule      = aws_cloudwatch_event_rule.custom_metrics_schedule[0].name
  target_id = "CustomMetricsLambda"
  arn       = aws_lambda_function.custom_metrics[0].arn
}

# Lambda Permission for EventBridge
resource "aws_lambda_permission" "allow_eventbridge_custom_metrics" {
  count = var.enable_custom_metrics ? 1 : 0

  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.custom_metrics[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.custom_metrics_schedule[0].arn
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
