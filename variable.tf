# variables.tf
variable "aws_regions" {
  description = "List of AWS regions to use"
  type        = map(string)
}

variable "default_network_acl_ids" {
  description = "Map of default network ACL IDs for each region"
  type        = map(string)
}

variable "rule_action" {
  description = "The rule action to be used in the network ACL rule"
  type        = string
}

variable "cidr_block" {
  description = "The CIDR block for the network ACL rule"
  type        = string
}

variable "from_port" {
  description = "The starting port for the network ACL rule"
  type        = number
}

variable "to_port" {
  description = "The ending port for the network ACL rule"
  type        = number
}
