variable "environment" {
  description = "Environment name"
  type        = string
}

variable "project_name" {
  description = "Project name"
  type        = string
}

variable "monitored_resources" {
  description = "Map of resources to monitor"
  type = object({
    vpc_id             = string
    instance_ids       = list(string)
    transit_gateway_id = string
  })
  default = {
    vpc_id             = null
    instance_ids       = []
    transit_gateway_id = null
  }
}

variable "enable_config_rules" {
  description = "Enable AWS Config rules"
  type        = bool
  default     = true
}

variable "config_rules" {
  description = "Map of Config rules to create"
  type = map(object({
    description                 = string
    source_owner               = string
    source_identifier          = string
    input_parameters           = string
    maximum_execution_frequency = string
    scope = object({
      compliance_resource_id    = string
      compliance_resource_types = list(string)
      tag_key                  = string
      tag_value                = string
    })
  }))
  default = {
    required-tags = {
      description                 = "Ensure required tags are present on resources"
      source_owner               = "AWS"
      source_identifier          = "REQUIRED_TAGS"
      input_parameters           = "{\"tag1Key\":\"Project\",\"tag2Key\":\"Environment\"}"
      maximum_execution_frequency = "TwentyFour_Hours"
      scope                      = null
    }
    encrypted-volumes = {
      description                 = "Ensure EBS volumes are encrypted"
      source_owner               = "AWS"
      source_identifier          = "ENCRYPTED_VOLUMES"
      input_parameters           = null
      maximum_execution_frequency = null
      scope                      = null
    }
    instances-in-vpc = {
      description                 = "Ensure EC2 instances are in VPC"
      source_owner               = "AWS"
      source_identifier          = "INSTANCES_IN_VPC"
      input_parameters           = null
      maximum_execution_frequency = null
      scope                      = null
    }
  }
}

variable "record_all_resources" {
  description = "Record all supported resources in Config"
  type        = bool
  default     = true
}

variable "include_global_resources" {
  description = "Include global resources in Config recording"
  type        = bool
  default     = true
}

variable "specific_resource_types" {
  description = "Specific resource types to record if not recording all"
  type        = list(string)
  default     = []
}

variable "enable_config_snapshots" {
  description = "Enable configuration snapshots"
  type        = bool
  default     = true
}

variable "snapshot_delivery_frequency" {
  description = "Frequency for configuration snapshots"
  type        = string
  default     = "TwentyFour_Hours"
}

variable "config_retention_days" {
  description = "Number of days to retain Config data"
  type        = number
  default     = 365
}

variable "alert_emails" {
  description = "List of email addresses for alerts"
  type        = list(string)
  default     = []
}

variable "enable_cloudwatch_logs_for_config" {
  description = "Enable CloudWatch Logs for Config"
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period"
  type        = number
  default     = 7
}

variable "kms_key_id" {
  description = "KMS key ID for S3 bucket encryption"
  type        = string
  default     = null
}

variable "sns_kms_key_id" {
  description = "KMS key ID for SNS topic encryption"
  type        = string
  default     = null
}

variable "cloudwatch_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption"
  type        = string
  default     = null
}

variable "enable_config_compliance_alarms" {
  description = "Enable CloudWatch alarms for Config compliance"
  type        = bool
  default     = true
}

variable "enable_config_change_notifications" {
  description = "Enable notifications for Config compliance changes"
  type        = bool
  default     = true
}

variable "custom_dashboard_widgets" {
  description = "List of custom CloudWatch dashboard widgets"
  type        = list(any)
  default     = []
}

variable "enable_custom_metrics" {
  description = "Enable custom metrics collection via Lambda"
  type        = bool
  default     = false
}

variable "custom_metrics_schedule" {
  description = "Schedule expression for custom metrics collection"
  type        = string
  default     = "rate(5 minutes)"
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

variable "selected_resource_types" {
  type        = list(string)
  description = "List of specific AWS resource types to record when record_all_resources is false"
  default     = [] # or provide a sensible default
}
