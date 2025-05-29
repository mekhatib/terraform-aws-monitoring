# Terraform AWS monitoring Module

This Terraform module manages AWS monitoring resources.

## Usage

```hcl
module "monitoring" {
  source  = "app.terraform.io/YOUR-ORG/monitoring/aws"
  version = "1.0.0"
  
  # Required variables
  environment  = "dev"
  project_name = "my-project"
  
  # Module-specific variables
  # Add based on variables.tf
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| aws | >= 5.0 |

## Inputs

See [variables.tf](./variables.tf)

## Outputs

See [outputs.tf](./outputs.tf)
