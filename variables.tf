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
variable "ssh_ingress_ports" {
  type        = list(number)
  description = "HTTP ingress ports"
  default     = [22]
}

variable "http_ingress_ports" {
  type        = list(number)
  description = "HTTP ingress ports"
  default     = [80, 443]
}


variable "consul_agent_ingress_ports" {
  type        = list(number)
  description = "Consul ingress ports list"
  default     = [8301, 8302]
}

variable "consul_server_ingress_ports" {
  type        = list(number)
  description = "Consul ingress ports list"
  default     = [8600, 8500, 8300, 8301, 8302]
}

variable "jenkins_ingress_ports" {
  type        = list(number)
  description = "Jenkins ingress ports list"
  default     = [49187, 8080]
}

variable "node_exporter_ingress_ports" {
  type        = list(string)
  description = "Node Exporter ingress ports"
  default     = [9100]
}

variable "prometheus_ingress_ports" {
  type        = list(number)
  description = "Prometheus ingress ports"
  default     = [9090]
}

variable "grafana_ingress_ports" {
  type        = list(number)
  description = "Grafana ingress ports"
  default     = [3000]
}

variable "elk_ingress_ports" {
  type        = list(number)
  description = "ELK ingress ports"
  default     = [5601, 9200, 9300]
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

##################################################################################
# Certificate
##################################################################################
variable "aws_iam_server_certificate_arn" {
  description = "AWS IAM Server Certificate ARN For ALBs"
}

variable "ssl_security_policy" {
  description = "SSL Security Policy"
  type        = string
  default     = "ELBSecurityPolicy-FS-1-2-Res-2020-10"
}

##################################################################################
# IAM
##################################################################################
variable "ec2_describe_instances_instance_profile_id" {
  description = "EC2 Describe Instances Instance Profile ID"
}
