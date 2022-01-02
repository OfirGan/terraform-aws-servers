###################################################################################
# OUTPUT
###################################################################################

output "bastion_server_public_ip" {
  description = "Bastion host Public IP"
  value       = aws_instance.bastion_server.*.public_ip
}

output "bastion_server_private_ip" {
  description = "Bastion host Private IP"
  value       = aws_instance.bastion_server.*.private_ip
}

output "consul_servers_private_ips" {
  description = "Consul Servers Private IP's"
  value       = aws_instance.consul_servers.*.private_ip
}

output "jenkins_server_private_ip" {
  description = "Jenkins server Private IP"
  value       = aws_instance.jenkins_server.*.private_ip
}

output "jenkins_nodes_private_ip" {
  description = "Private IP's of the Jenkins nodes"
  value       = aws_instance.jenkins_nodes.*.private_ip
}

output "ansible_server_private_ip" {
  description = "Ansible Server Private IP"
  value       = aws_instance.ansible_server.*.private_ip
}

output "consul_alb_public_dns" {
  description = "Consul ALB Public DNS name"
  value       = aws_alb.consul_alb.dns_name
}

output "jenkins_alb_public_dns" {
  description = "Jenkins ALB Public DNS name"
  value       = aws_alb.jenkins_alb.dns_name
}

output "jenkins_nodes_arns" {
  description = "ARN of the Jenkins Nodes Instances"
  value       = aws_instance.jenkins_nodes.*.arn
}

output "jenkins_nodes_ids" {
  description = "ID of the Jenkins Nodes Instances"
  value       = aws_instance.jenkins_nodes.*.id
}

output "iam_role_arn" {
  description = "Describe Instances Role ARN"
  value       = aws_iam_role.ec2_describe_instances_role.arn
}
