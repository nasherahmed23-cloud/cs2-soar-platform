variable "aws_region" {
  description = "AWS region used for the Innovatech SOAR environment"
  type        = string
  default     = "eu-central-1"
}

variable "project_name" {
  description = "Name used for Innovatech SOAR resources"
  type        = string
  default     = "innovatech-soar"
}