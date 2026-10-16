# File:    main.tf
# Purpose: IaC fixture. AWS Terraform resources with public exposure, missing
#          encryption, missing logging and over-broad IAM.
#          Intentionally misconfigured - never apply.
# Author:  Vigilnz Security Engineering
# Date:    2026-10-16
#
# Expected rules: TF-AWS-S3-001..004, TF-AWS-SG-004..006, TF-AWS-EC2-001..005,
#   TF-AWS-RDS-001..004, TF-AWS-IAM-001..003, TF-AWS-CLOUDTRAIL-001/002,
#   TF-AWS-ECR-001..003, TF-AWS-KMS-001, TF-AWS-SQS-001, TF-AWS-VPC-001

provider "aws" {
  region = "us-east-1"
}

# S3: public ACL, no encryption, no versioning, no access logging
resource "aws_s3_bucket" "public_assets" {
  bucket = "vigilnz-fixture-public-assets"
  acl    = "public-read-write"
}

resource "aws_s3_bucket_public_access_block" "public_assets" {
  bucket                  = aws_s3_bucket.public_assets.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Security group: SSH, RDP and all egress open to the internet
resource "aws_security_group" "wide_open" {
  name        = "vigilnz-fixture-open"
  description = "Fixture security group with unrestricted ingress"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# EC2: public IP, unencrypted root volume, IMDSv1 still allowed
resource "aws_instance" "app" {
  ami                         = "ami-0fixture00000000"
  instance_type               = "t3.medium"
  associate_public_ip_address = true
  monitoring                  = false
  vpc_security_group_ids      = [aws_security_group.wide_open.id]

  root_block_device {
    encrypted = false
  }

  metadata_options {
    http_tokens = "optional"
  }

  user_data = <<-EOT
    #!/bin/bash
    export DB_PASSWORD="FixturePassw0rd"
    echo "$DB_PASSWORD" > /etc/app/db.pass
  EOT
}

# RDS: publicly reachable, unencrypted, no backups, no deletion protection
resource "aws_db_instance" "app" {
  identifier                 = "vigilnz-fixture-db"
  engine                     = "postgres"
  instance_class             = "db.t3.medium"
  allocated_storage          = 20
  username                   = "postgres"
  password                   = "FixturePassw0rd"
  publicly_accessible        = true
  storage_encrypted          = false
  backup_retention_period    = 0
  deletion_protection        = false
  skip_final_snapshot        = true
  auto_minor_version_upgrade = false
}

# IAM: wildcard action on wildcard resource
resource "aws_iam_policy" "admin_everything" {
  name = "vigilnz-fixture-admin"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "assume_anyone" {
  name = "vigilnz-fixture-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# CloudTrail: no multi-region coverage, no log validation, no KMS
resource "aws_cloudtrail" "audit" {
  name                          = "vigilnz-fixture-trail"
  s3_bucket_name                = aws_s3_bucket.public_assets.id
  is_multi_region_trail         = false
  enable_log_file_validation    = false
  include_global_service_events = false
}

# ECR: mutable tags, no scan on push
resource "aws_ecr_repository" "app" {
  name                 = "vigilnz-fixture-app"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }
}

# KMS: key rotation disabled
resource "aws_kms_key" "app" {
  description         = "Fixture key"
  enable_key_rotation = false
}

# SQS: queue without server-side encryption
resource "aws_sqs_queue" "jobs" {
  name              = "vigilnz-fixture-jobs"
  kms_master_key_id = null
}

# VPC: flow logs never created for this VPC
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
