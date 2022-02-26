##################################################################################
# AMI - Ubuntu 18.04 Latest
# IAM - Ansible -> Describe EC2 Instances, 
# IAM - ALB write logs -> S3
# SECURITY GROUPS - Default, Monitor, Consul, Jenkins, Prometheus, Grafana, HTTP/s
# EC2 INSTANCES - Bastion Host, Consul Servers, Jenkins Server & Nodes, Ansible Server, Prometheus, Grafana
# S3 BUCKET - For ALB Logs
# APP LOAD-BALANCER - Consul, Jenkins, Prometheus, Grafana
##################################################################################

##################################################################################
# AMI
##################################################################################

data "aws_ami" "ubuntu_ami" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server*"]
  }
}

##################################################################################
# IAM - Describe EC2 Instances
##################################################################################

resource "aws_iam_role" "ec2_describe_instances_role" {
  name = "ec2_describe_instances_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_policy" "ec2_describe_instances_policy" {
  name = "ec2_describe_instances_policy"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:Describe*",
          "sts:AssumeRole",
          "eks:DescribeCluster"
        ],
        "Resource" : "*"
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "ec2_describe_instances_policy_attachment" {
  name       = "ec2_describe_instances_policy_attachment"
  roles      = [resource.aws_iam_role.ec2_describe_instances_role.name]
  policy_arn = resource.aws_iam_policy.ec2_describe_instances_policy.arn
}

resource "aws_iam_instance_profile" "ec2_describe_instances_instance_profile" {
  name = "ec2_describe_instances_instance_profile"
  role = resource.aws_iam_role.ec2_describe_instances_role.name
}

##################################################################################
# SECURITY GROUPS
##################################################################################

#####################################################
# Default Security Group
#####################################################

resource "aws_security_group" "default_sg" {
  name        = "default-sg"
  description = "Default Security Group"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }

  dynamic "ingress" {
    iterator = port
    for_each = var.ssh_ingress_ports
    content {
      from_port   = port.value
      to_port     = port.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  ingress {
    from_port   = 8
    to_port     = 0
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    "Name" = "${var.project_name}-default-sg"
  }
}

#####################################################
# Monitor Agent Security Group
#####################################################

resource "aws_security_group" "monitor_agent_sg" {
  name        = "monitor_agent_sg"
  description = "Monitor Agent Security Group"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    iterator = port
    for_each = var.consul_agent_ingress_ports
    content {
      from_port   = port.value
      to_port     = port.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  dynamic "ingress" {
    iterator = port
    for_each = var.node_exporter_ingress_ports
    content {
      from_port   = port.value
      to_port     = port.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = {
    "Name" = "${var.project_name}-monitor-agent-sg"
  }
}

#####################################################
# Consul Server Security Group
#####################################################

resource "aws_security_group" "consul_server_sg" {
  name        = "consul_server_sg"
  description = "Consul Server Security Group"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    iterator = port
    for_each = var.consul_server_ingress_ports
    content {
      from_port   = port.value
      to_port     = port.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = {
    "Name" = "${var.project_name}-consul-server-sg"
  }
}

#####################################################
# Jenkins Security Group
#####################################################

resource "aws_security_group" "jenkins_server_sg" {
  name        = "jenkins_server_sg"
  description = "Jenkins Server Security Group"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    iterator = port
    for_each = var.jenkins_ingress_ports
    content {
      from_port   = port.value
      to_port     = port.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = {
    "Name" = "${var.project_name}-jenkins-server-sg"
  }
}

#####################################################
# Prometheus Security Group
#####################################################

resource "aws_security_group" "prometheus_sg" {
  name        = "prometheus_sg"
  description = "Prometheus Security Group"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    iterator = port
    for_each = var.prometheus_ingress_ports
    content {
      from_port   = port.value
      to_port     = port.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = {
    "Name" = "${var.project_name}-prometheus-sg"
  }
}

#####################################################
# Grafana Security Group
#####################################################

resource "aws_security_group" "grafana_sg" {
  name        = "grafana_sg"
  description = "Grafana Security Group"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    iterator = port
    for_each = var.grafana_ingress_ports
    content {
      from_port   = port.value
      to_port     = port.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = {
    "Name" = "${var.project_name}-grafana-sg"
  }
}

#####################################################
# HTTP\S Agent Security Group
#####################################################

resource "aws_security_group" "http_sg" {
  name        = "http_sg"
  description = "HTTP Security Group"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    iterator = port
    for_each = var.http_ingress_ports
    content {
      from_port   = port.value
      to_port     = port.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = {
    "Name" = "${var.project_name}-http-sg"
  }
}

##################################################################################
# EC2 INSTANCES
##################################################################################

#####################################################
# Bastion Host
#####################################################

resource "aws_instance" "bastion_server" {
  ami                         = data.aws_ami.ubuntu_ami.id
  instance_type               = var.instance_type
  subnet_id                   = var.public_subnets_ids[0]
  vpc_security_group_ids      = [aws_security_group.default_sg.id, aws_security_group.monitor_agent_sg.id]
  key_name                    = var.aws_server_key_name
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ec2_describe_instances_instance_profile.id
  tags                        = zipmap(var.servers_tags_structure, ["bastion", "bastion", "server", "Bastion-Server", "public", "${var.project_name}", "${var.owner_name}", "true", "ubuntu"])
}

#####################################################
# Consul Servers
#####################################################

resource "aws_instance" "consul_servers" {
  count                  = var.consul_servers_count
  ami                    = data.aws_ami.ubuntu_ami.id
  instance_type          = var.instance_type
  subnet_id              = element(var.private_subnets_ids, count.index % length(var.private_subnets_ids))
  vpc_security_group_ids = [aws_security_group.consul_server_sg.id, aws_security_group.default_sg.id, aws_security_group.monitor_agent_sg.id]
  key_name               = var.aws_server_key_name
  source_dest_check      = false
  iam_instance_profile   = aws_iam_instance_profile.ec2_describe_instances_instance_profile.id
  tags                   = zipmap(var.servers_tags_structure, ["consul", "service_discovery", "server", "Consul-Server-${count.index + 1}", "private", "${var.project_name}", "${var.owner_name}", "true", "ubuntu"])
}

#####################################################
# Jenkins Server
#####################################################

resource "aws_instance" "jenkins_server" {
  ami                    = data.aws_ami.ubuntu_ami.id
  instance_type          = var.instance_type
  subnet_id              = var.private_subnets_ids[0]
  vpc_security_group_ids = [aws_security_group.jenkins_server_sg.id, aws_security_group.default_sg.id, aws_security_group.monitor_agent_sg.id]
  key_name               = var.aws_server_key_name
  source_dest_check      = false
  iam_instance_profile   = aws_iam_instance_profile.ec2_describe_instances_instance_profile.id
  tags                   = zipmap(var.servers_tags_structure, ["jenkins", "cicd", "server", "Jenkins-Server", "private", "${var.project_name}", "${var.owner_name}", "true", "ubuntu"])
}

#####################################################
# Jenkins Nodes
#####################################################

resource "aws_instance" "jenkins_nodes" {
  count                  = var.jenkins_nodes_count
  ami                    = data.aws_ami.ubuntu_ami.id
  instance_type          = var.instance_type
  subnet_id              = element(var.private_subnets_ids, count.index % length(var.private_subnets_ids))
  vpc_security_group_ids = [aws_security_group.default_sg.id, aws_security_group.monitor_agent_sg.id]
  key_name               = var.aws_server_key_name
  source_dest_check      = false
  iam_instance_profile   = aws_iam_instance_profile.ec2_describe_instances_instance_profile.id
  tags                   = zipmap(var.servers_tags_structure, ["jenkins", "service_discovery", "node", "Jenkins-Node-${count.index + 1}", "private", "${var.project_name}", "${var.owner_name}", "true", "ubuntu"])
}

#####################################################
# Ansible Server
#####################################################

resource "aws_instance" "ansible_server" {
  ami                    = data.aws_ami.ubuntu_ami.id
  instance_type          = var.instance_type
  subnet_id              = var.private_subnets_ids[0]
  vpc_security_group_ids = [aws_security_group.default_sg.id, aws_security_group.monitor_agent_sg.id]
  key_name               = var.aws_server_key_name
  source_dest_check      = false
  iam_instance_profile   = aws_iam_instance_profile.ec2_describe_instances_instance_profile.id
  tags                   = zipmap(var.servers_tags_structure, ["ansible", "configuration_management", "server", "Ansible-Server", "private", "${var.project_name}", "${var.owner_name}", "true", "ubuntu"])
}

#####################################################
# Prometheus Server
#####################################################

resource "aws_instance" "prometheus_server" {
  ami                    = data.aws_ami.ubuntu_ami.id
  instance_type          = var.instance_type
  subnet_id              = var.private_subnets_ids[0]
  vpc_security_group_ids = [aws_security_group.prometheus_sg.id, aws_security_group.default_sg.id, aws_security_group.monitor_agent_sg.id]
  key_name               = var.aws_server_key_name
  source_dest_check      = false
  iam_instance_profile   = aws_iam_instance_profile.ec2_describe_instances_instance_profile.id
  tags                   = zipmap(var.servers_tags_structure, ["prometheus", "monitoring", "server", "Prometheus-Server", "private", "${var.project_name}", "${var.owner_name}", "true", "ubuntu"])
}

#####################################################
# Grafana Server
#####################################################

resource "aws_instance" "grafana_server" {
  ami                    = data.aws_ami.ubuntu_ami.id
  instance_type          = var.instance_type
  subnet_id              = var.private_subnets_ids[0]
  vpc_security_group_ids = [aws_security_group.grafana_sg.id, aws_security_group.default_sg.id, aws_security_group.monitor_agent_sg.id]
  key_name               = var.aws_server_key_name
  source_dest_check      = false
  iam_instance_profile   = aws_iam_instance_profile.ec2_describe_instances_instance_profile.id
  tags                   = zipmap(var.servers_tags_structure, ["grafana", "monitoring", "server", "Grafana-Server", "private", "${var.project_name}", "${var.owner_name}", "true", "ubuntu"])
}

##################################################################################
# S3 BUCKET
##################################################################################

resource "aws_s3_bucket" "s3_logs_bucket" {
  bucket        = var.s3_logs_bucket_name
  force_destroy = true # only for testing
  acl           = "log-delivery-write"
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.s3_logs_bucket.id
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::${var.elb_account_id}:root"
        },
        "Action" : "s3:PutObject",
        "Resource" : "arn:aws:s3:::${var.s3_logs_bucket_name}/*"
      },
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "delivery.logs.amazonaws.com"
        },
        "Action" : "s3:PutObject",
        "Resource" : "arn:aws:s3:::${var.s3_logs_bucket_name}/*",
        "Condition" : {
          "StringEquals" : {
            "s3:x-amz-acl" : "bucket-owner-full-control"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "delivery.logs.amazonaws.com"
        },
        "Action" : "s3:GetBucketAcl",
        "Resource" : "arn:aws:s3:::${var.s3_logs_bucket_name}"
      }
    ]
  })
}


##################################################################################
# APP LOAD-BALANCER
##################################################################################

#####################################################
# Consul Servers ALB
#####################################################

resource "aws_alb" "consul_alb" {
  name               = "consul-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.http_sg.id]
  subnets            = var.public_subnets_ids

  access_logs {
    bucket  = resource.aws_s3_bucket.s3_logs_bucket.bucket
    prefix  = "logs/consul-alb"
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-consul-alb"
  }
}

resource "aws_alb_target_group_attachment" "consul_servers_alb_tg_attach" {
  count            = length(aws_instance.consul_servers)
  target_group_arn = aws_alb_target_group.consul_alb_tg.arn
  target_id        = aws_instance.consul_servers.*.id[count.index]
  port             = 8500
}

resource "aws_alb_target_group" "consul_alb_tg" {
  name     = "consul-alb-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id
  stickiness {
    type            = "lb_cookie"
    cookie_duration = 60
    enabled         = true
  }
  health_check {
    port                = 8500
    protocol            = "HTTP"
    path                = "/v1/status/leader"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    interval            = 10
  }
}

resource "aws_alb_listener" "consul_alb_listener" {
  load_balancer_arn = aws_alb.consul_alb.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.consul_alb_tg.arn
  }
}

#####################################################
# Jenkins Server ALB
#####################################################

resource "aws_alb" "jenkins_alb" {
  name               = "jenkins-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.http_sg.id]
  subnets            = var.public_subnets_ids

  access_logs {
    bucket  = resource.aws_s3_bucket.s3_logs_bucket.bucket
    prefix  = "logs/jenkins-alb"
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-jenkins-alb"
  }
}

resource "aws_alb_target_group_attachment" "jenkins_server_alb_attach" {
  target_group_arn = aws_alb_target_group.jenkins_alb_tg.arn
  target_id        = aws_instance.jenkins_server.id
  port             = 8080
}


resource "aws_alb_target_group" "jenkins_alb_tg" {
  name     = "jenkins-alb-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id
  stickiness {
    type            = "lb_cookie"
    cookie_duration = 60
    enabled         = true
  }
  health_check {
    port                = 8080
    protocol            = "HTTP"
    path                = "/login"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    interval            = 10
  }
}

resource "aws_alb_listener" "jenkins_alb_listener" {
  load_balancer_arn = aws_alb.jenkins_alb.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.jenkins_alb_tg.arn
  }
}

#####################################################
# Prometheus Server ALB
#####################################################

resource "aws_alb" "prometheus_alb" {
  name               = "prometheus-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.http_sg.id]
  subnets            = var.public_subnets_ids

  access_logs {
    bucket  = resource.aws_s3_bucket.s3_logs_bucket.bucket
    prefix  = "logs/prometheus-alb"
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-prometheus-alb"
  }
}

resource "aws_alb_target_group_attachment" "prometheus_server_alb_attach" {
  target_group_arn = aws_alb_target_group.prometheus_alb_tg.arn
  target_id        = aws_instance.prometheus_server.id
  port             = 9090
}


resource "aws_alb_target_group" "prometheus_alb_tg" {
  name     = "prometheus-alb-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id
  stickiness {
    type            = "lb_cookie"
    cookie_duration = 60
    enabled         = true
  }
  health_check {
    port                = 9090
    protocol            = "HTTP"
    path                = "/login"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    interval            = 10
  }
}

resource "aws_alb_listener" "prometheus_alb_listener" {
  load_balancer_arn = aws_alb.prometheus_alb.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.prometheus_alb_tg.arn
  }
}

#####################################################
# Grafana Server ALB
#####################################################

resource "aws_alb" "grafana_alb" {
  name               = "grafana-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.http_sg.id]
  subnets            = var.public_subnets_ids

  access_logs {
    bucket  = resource.aws_s3_bucket.s3_logs_bucket.bucket
    prefix  = "logs/grafana-alb"
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-grafana-alb"
  }
}

resource "aws_alb_target_group_attachment" "grafana_server_alb_attach" {
  target_group_arn = aws_alb_target_group.grafana_alb_tg.arn
  target_id        = aws_instance.grafana_server.id
  port             = 3000
}


resource "aws_alb_target_group" "grafana_alb_tg" {
  name     = "grafana-alb-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id
  stickiness {
    type            = "lb_cookie"
    cookie_duration = 60
    enabled         = true
  }
  health_check {
    port                = 3000
    protocol            = "HTTP"
    path                = "/login"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    interval            = 10
  }
}

resource "aws_alb_listener" "grafana_alb_listener" {
  load_balancer_arn = aws_alb.grafana_alb.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.grafana_alb_tg.arn
  }
}
