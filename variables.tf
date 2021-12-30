##################################################################################
# VPC
##################################################################################
variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "public_subnets_ids" {
  description = "Public Subnet Ids"
  type        = list(string)
}

variable "private_subnets_ids" {
  description = "Private Subnet Ids"
  type        = list(string)
}

##################################################################################
# S3 For logs
##################################################################################
variable "s3_logs_bucket_name" {
  description = "Logs Bucket Name (lowercase only, no spaces)"
  type        = string
}

variable "elb_account_id" {
  description = "ELB Account ID - pick one according to region https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html#access-logging-bucket-permissions"
  type        = string
}

##################################################################################
# Servers
##################################################################################
variable "instance_type" {
  description = "Servers Instance Type"
  type        = string
}

variable "consul_servers_count" {
  description = "How many Consul servers to create"
  type        = number
}

variable "jenkins_nodes_count" {
  description = "How many Jenkins nodes to create"
  type        = number
}

##################################################################################
# Security Groups Ports
##################################################################################
variable "bastion_ingress_ports" {
  type        = list(number)
  description = "Bastion host ingress ports list"
  default     = [22]
}

variable "consul_ingress_ports" {
  type        = list(number)
  description = "Consul ingress ports list"
  default     = [8600, 8500, 8300, 8301, 8302, 22, 80]
}

variable "jenkins_ingress_ports" {
  type        = list(number)
  description = "Jenkins ingress ports list"
  default     = [49187, 80, 8080, 22]
}

variable "ansible_ingress_ports" {
  type        = list(number)
  description = "Ansible host ingress ports list"
  default     = [80, 8080, 22]
}

##################################################################################
# Tags
##################################################################################
variable "project_name" {
  description = "Project Name"
  type        = string
}

variable "owner_name" {
  description = "Owner Name"
  type        = string
}

variable "servers_tags_structure" {
  type        = list(string)
  description = "Consul server tags map"
  default     = ["service", "service_role", "instance_type", "Name", "subnet_type", "project", "owner", "is_consul_monitored", "os_type"]
}

##################################################################################
# Keys
##################################################################################
variable "aws_server_key_name" {
  description = "AWS EC2 Key pair Name"
}
