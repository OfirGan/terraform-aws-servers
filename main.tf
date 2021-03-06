##################################################################################
# AMI - Ubuntu 18.04 Latest
# IAM - ALB write logs -> S3
# SECURITY GROUPS - Default, Monitor, Consul, Jenkins, Prometheus, Grafana, Elk, HTTP/s
# EC2 INSTANCES - Bastion Host, Consul Servers, Jenkins Server & Nodes, Ansible Server, 
#                 Prometheus, Grafana, Elk
# S3 BUCKET - For ALB Logs
# APP LOAD-BALANCER - Consul, Jenkins, Prometheus, Grafana, Elk
# Route53 Records
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
    for_each = var.ssh_ports
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
    for_each = var.consul_agent_ports
    content {
      from_port   = port.value
      to_port     = port.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  dynamic "ingress" {
    iterator = port
    for_each = var.consul_agent_ports
    content {
      from_port   = port.value
      to_port     = port.value
      protocol    = "udp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  dynamic "ingress" {
    iterator = port
    for_each = var.node_exporter_ports
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

resource "aws_security_group" "openvpn_sg" {
  name        = "openvpn_sg"
  description = "OpenVPN Security Group"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    iterator = port
    for_each = var.openvpn_tcp_ports
    content {
      from_port   = port.value
      to_port     = port.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  dynamic "ingress" {
    iterator = port
    for_each = var.openvpn_udp_ports
    content {
      from_port   = port.value
      to_port     = port.value
      protocol    = "udp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = {
    "Name" = "${var.project_name}-openvpn-sg"
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
    for_each = var.consul_server_tcp_ports
    content {
      from_port   = port.value
      to_port     = port.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  dynamic "ingress" {
    iterator = port
    for_each = var.consul_server_udp_ports
    content {
      from_port   = port.value
      to_port     = port.value
      protocol    = "udp"
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
    for_each = var.jenkins_ports
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
    for_each = var.prometheus_ports
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
    for_each = var.grafana_ports
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
# Elasticsearch & Kibana Security Group
#####################################################

resource "aws_security_group" "elk_servers_sg" {
  name        = "elk_servers_sg"
  description = "Elasticsearch And Kibana Security Group"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    iterator = port
    for_each = var.elk_ports
    content {
      from_port   = port.value
      to_port     = port.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = {
    "Name" = "${var.project_name}-elk-sg"
  }
}

#####################################################
# HTTP\S Agent Security Group
#####################################################

resource "aws_security_group" "http_sg" {
  name        = "http_sg"
  description = "HTTP Security Group"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }

  dynamic "ingress" {
    iterator = port
    for_each = var.http_ports
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
  vpc_security_group_ids      = [aws_security_group.default_sg.id, aws_security_group.monitor_agent_sg.id, aws_security_group.openvpn_sg.id]
  key_name                    = var.aws_server_key_name
  associate_public_ip_address = true
  iam_instance_profile        = var.ec2_describe_instances_instance_profile_id
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
  iam_instance_profile   = var.ec2_describe_instances_instance_profile_id
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
  iam_instance_profile   = var.ec2_describe_instances_instance_profile_id
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
  iam_instance_profile   = var.ec2_describe_instances_instance_profile_id
  tags                   = zipmap(var.servers_tags_structure, ["jenkins", "cicd", "node", "Jenkins-Node-${count.index + 1}", "private", "${var.project_name}", "${var.owner_name}", "true", "ubuntu"])
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
  iam_instance_profile   = var.ec2_describe_instances_instance_profile_id
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
  iam_instance_profile   = var.ec2_describe_instances_instance_profile_id
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
  iam_instance_profile   = var.ec2_describe_instances_instance_profile_id
  tags                   = zipmap(var.servers_tags_structure, ["grafana", "monitoring", "server", "Grafana-Server", "private", "${var.project_name}", "${var.owner_name}", "true", "ubuntu"])
}

#####################################################
# Elasticsearch & Kibana Server
#####################################################
resource "aws_instance" "elk_server" {
  ami                    = data.aws_ami.ubuntu_ami.id
  instance_type          = "t3.small"
  subnet_id              = var.private_subnets_ids[0]
  vpc_security_group_ids = [aws_security_group.elk_servers_sg.id, aws_security_group.default_sg.id, aws_security_group.monitor_agent_sg.id]
  key_name               = var.aws_server_key_name
  source_dest_check      = false
  iam_instance_profile   = var.ec2_describe_instances_instance_profile_id
  tags                   = zipmap(var.servers_tags_structure, ["elk", "logging", "server", "ELK-Server", "private", "${var.project_name}", "${var.owner_name}", "true", "ubuntu"])
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

resource "aws_alb_listener" "consul_https_alb_listener" {
  load_balancer_arn = aws_alb.consul_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_security_policy
  certificate_arn   = var.aws_iam_server_certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.consul_alb_tg.arn
  }
}

resource "aws_alb_listener" "consul_http_alb_listener" {
  load_balancer_arn = aws_alb.consul_alb.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
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

resource "aws_alb_listener" "jenkins_https_alb_listener" {
  load_balancer_arn = aws_alb.jenkins_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_security_policy
  certificate_arn   = var.aws_iam_server_certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.jenkins_alb_tg.arn
  }
}

resource "aws_alb_listener" "jenkins_http_alb_listener" {
  load_balancer_arn = aws_alb.jenkins_alb.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
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
    path                = "/-/healthy"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    interval            = 10
  }
}

resource "aws_alb_listener" "prometheus_https_alb_listener" {
  load_balancer_arn = aws_alb.prometheus_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_security_policy
  certificate_arn   = var.aws_iam_server_certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.prometheus_alb_tg.arn
  }
}

resource "aws_alb_listener" "prometheus_http_alb_listener" {
  load_balancer_arn = aws_alb.prometheus_alb.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
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
    path                = "/api/health"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    interval            = 10
  }
}

resource "aws_alb_listener" "grafana_https_alb_listener" {
  load_balancer_arn = aws_alb.grafana_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_security_policy
  certificate_arn   = var.aws_iam_server_certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.grafana_alb_tg.arn
  }
}

resource "aws_alb_listener" "grafana_http_alb_listener" {
  load_balancer_arn = aws_alb.grafana_alb.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

#####################################################
# Elasticsearch & Kibana Server ALB
#####################################################

resource "aws_alb" "elk_alb" {
  name               = "elk-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.http_sg.id]
  subnets            = var.public_subnets_ids

  access_logs {
    bucket  = resource.aws_s3_bucket.s3_logs_bucket.bucket
    prefix  = "logs/elk-alb"
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-elk-alb"
  }
}

resource "aws_alb_target_group_attachment" "elk_server_alb_attach" {
  target_group_arn = aws_alb_target_group.elk_alb_tg.arn
  target_id        = aws_instance.elk_server.id
  port             = 5601
}


resource "aws_alb_target_group" "elk_alb_tg" {
  name     = "elk-alb-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id
  stickiness {
    type            = "lb_cookie"
    cookie_duration = 60
    enabled         = true
  }
  health_check {
    port                = 5601
    protocol            = "HTTP"
    path                = "/status"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    interval            = 10
  }
}

resource "aws_alb_listener" "elk_https_alb_listener" {
  load_balancer_arn = aws_alb.elk_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_security_policy
  certificate_arn   = var.aws_iam_server_certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.elk_alb_tg.arn
  }
}

resource "aws_alb_listener" "elk_http_alb_listener" {
  load_balancer_arn = aws_alb.elk_alb.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}


##################################################################################
# Route53 Records
##################################################################################

resource "aws_route53_record" "bastion_server" {
  zone_id = var.route53_zone_zone_id
  name    = "bastion.kandula"
  type    = "A"
  ttl     = "300"
  records = ["${aws_instance.bastion_server.private_ip}"]
}

resource "aws_route53_record" "ansible_server" {
  zone_id = var.route53_zone_zone_id
  name    = "ansible.kandula"
  type    = "A"
  ttl     = "300"
  records = ["${aws_instance.ansible_server.private_ip}"]
}

resource "aws_route53_record" "consul_servers" {
  count   = length(aws_instance.consul_servers)
  zone_id = var.route53_zone_zone_id
  name    = "consul${count.index + 1}.kandula"
  type    = "A"
  ttl     = "300"
  records = ["${aws_instance.consul_servers[count.index].private_ip}"]
}

resource "aws_route53_record" "jenkins_server" {
  zone_id = var.route53_zone_zone_id
  name    = "jenkins.kandula"
  type    = "A"
  ttl     = "300"
  records = ["${aws_instance.jenkins_server.private_ip}"]
}
resource "aws_route53_record" "jenkins_nodes" {
  count   = length(aws_instance.jenkins_nodes)
  zone_id = var.route53_zone_zone_id
  name    = "jenkins-n${count.index + 1}.kandula"
  type    = "A"
  ttl     = "300"
  records = ["${aws_instance.jenkins_nodes[count.index].private_ip}"]
}

resource "aws_route53_record" "prometheus_server" {
  zone_id = var.route53_zone_zone_id
  name    = "prometheus.kandula"
  type    = "A"
  ttl     = "300"
  records = ["${aws_instance.prometheus_server.private_ip}"]
}

resource "aws_route53_record" "grafana_server" {
  zone_id = var.route53_zone_zone_id
  name    = "grafana.kandula"
  type    = "A"
  ttl     = "300"
  records = ["${aws_instance.grafana_server.private_ip}"]
}

resource "aws_route53_record" "elk_server" {
  zone_id = var.route53_zone_zone_id
  name    = "elk.kandula"
  type    = "A"
  ttl     = "300"
  records = ["${aws_instance.elk_server.private_ip}"]
}
