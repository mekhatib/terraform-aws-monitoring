# Config outputs
output "config_recorder_name" {
  description = "Name of the AWS Config recorder"
  value       = aws_config_configuration_recorder.main.name
}

output "config_recorder_arn" {
  description = "ARN of the AWS Config recorder"
  value       = aws_config_configuration_recorder.main.arn
}

output "config_bucket_name" {
  description = "Name of the S3 bucket for Config"
  value       = aws_s3_bucket.config.id
}

output "config_bucket_arn" {
  description = "ARN of the S3 bucket for Config"
  value       = aws_s3_bucket.config.arn
}

output "config_delivery_channel_name" {
  description = "Name of the Config delivery channel"
  value       = aws_config_delivery_channel.main.name
}

output "config_role_arn" {
  description = "ARN of the IAM role for Config"
  value       = aws_iam_role.config.arn
}

output "config_rules" {
  description = "Map of Config rule names to their ARNs"
  value = {
    for name, rule in aws_config_config_rule.rules :
    name => rule.arn
  }
}

# SNS outputs
output "sns_topic_arn" {
  description = "ARN of the SNS topic for alerts"
  value       = aws_sns_topic.alerts.arn
}

output "sns_topic_name" {
  description = "Name of the SNS topic for alerts"
  value       = aws_sns_topic.alerts.name
}

# CloudWatch outputs
output "dashboard_url" {
  description = "URL of the CloudWatch dashboard"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.main.dashboard_name}"
}

output "dashboard_name" {
  description = "Name of the CloudWatch dashboard"
  value       = aws_cloudwatch_dashboard.main.dashboard_name
}

output "cloudwatch_alarms" {
  description = "Map of CloudWatch alarm names"
  value = {
    for name, alarm in aws_cloudwatch_metric_alarm.config_compliance :
    name => alarm.arn
  }
}

# Lambda outputs (if enabled)
output "custom_metrics_lambda_arn" {
  description = "ARN of the custom metrics Lambda function"
  value       = var.enable_custom_metrics ? aws_lambda_function.custom_metrics[0].arn : null
}

output "custom_metrics_lambda_name" {
  description = "Name of the custom metrics Lambda function"
  value       = var.enable_custom_metrics ? aws_lambda_function.custom_metrics[0].function_name : null
}

# EventBridge outputs
output "eventbridge_rules" {
  description = "Map of EventBridge rule ARNs"
  value = {
    config_changes = var.enable_config_change_notifications ? aws_cloudwatch_event_rule.config_changes[0].arn : null
    custom_metrics = var.enable_custom_metrics ? aws_cloudwatch_event_rule.custom_metrics_schedule[0].arn : null
  }
}

# Summary
output "monitoring_summary" {
  description = "Summary of monitoring configuration"
  value = {
    config_enabled              = true
    config_rules_count          = length(aws_config_config_rule.rules)
    recording_all_resources     = var.record_all_resources
    sns_subscriptions_count     = length(var.alert_emails)
    dashboard_widgets_count     = length(jsondecode(aws_cloudwatch_dashboard.main.dashboard_body).widgets)
    compliance_alarms_enabled   = var.enable_config_compliance_alarms
    custom_metrics_enabled      = var.enable_custom_metrics
  }
}

# Useful information for integration
output "integration_info" {
  description = "Information needed for integration with other systems"
  value = {
    sns_topic_arn        = aws_sns_topic.alerts.arn
    config_bucket_name   = aws_s3_bucket.config.id
    config_role_arn      = aws_iam_role.config.arn
    dashboard_url        = "https://console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.main.dashboard_name}"
  }
}