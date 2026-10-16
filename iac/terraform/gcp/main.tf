# File:    main.tf
# Purpose: IaC fixture. GCP Terraform resources with public buckets, open
#          firewalls, public SQL, over-broad IAM and unhardened GKE.
#          Intentionally misconfigured - never apply.
# Author:  Vigilnz Security Engineering
# Date:    2026-10-16
#
# Expected rules: TF-GCP-GCS-001..005, TF-GCP-FIREWALL-001..006,
#   TF-GCP-COMPUTE-001..006, TF-GCP-SQL-001..003, TF-GCP-IAM-001/002,
#   TF-GCP-KMS-001, TF-GCP-LOG-001, TF-GCP-GKE-001..006

provider "google" {
  project = "vigilnz-fixture"
  region  = "us-central1"
}

# GCS: world-readable bucket, no uniform access, no versioning
resource "google_storage_bucket" "public_assets" {
  name                        = "vigilnz-fixture-public-assets"
  location                    = "US"
  uniform_bucket_level_access = false
  force_destroy               = true

  versioning {
    enabled = false
  }
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.public_assets.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_storage_bucket_iam_member" "all_authenticated" {
  bucket = google_storage_bucket.public_assets.name
  role   = "roles/storage.objectAdmin"
  member = "allAuthenticatedUsers"
}

# Firewall: SSH, RDP and every port open to the internet
resource "google_compute_firewall" "wide_open" {
  name    = "vigilnz-fixture-open"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }

  allow {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

# Compute: public IP, default service account with full scopes, OS Login off,
# serial console enabled, IP forwarding enabled
resource "google_compute_instance" "app" {
  name         = "vigilnz-fixture-vm"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  can_ip_forward = true

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"

    access_config {
      # ephemeral public IP
    }
  }

  service_account {
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  metadata = {
    enable-oslogin         = "FALSE"
    serial-port-enable     = "TRUE"
    block-project-ssh-keys = "false"
    db-password            = "FixturePassw0rd"
  }
}

# Cloud SQL: public, no SSL requirement, no backups
resource "google_sql_database_instance" "app" {
  name             = "vigilnz-fixture-sql"
  database_version = "POSTGRES_13"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true
      require_ssl  = false

      authorized_networks {
        name  = "all"
        value = "0.0.0.0/0"
      }
    }

    backup_configuration {
      enabled = false
    }
  }

  deletion_protection = false
}

# IAM: primitive owner role bound to every internet user
resource "google_project_iam_member" "public_owner" {
  project = "vigilnz-fixture"
  role    = "roles/owner"
  member  = "allUsers"
}

resource "google_project_iam_member" "broad_editor" {
  project = "vigilnz-fixture"
  role    = "roles/editor"
  member  = "allAuthenticatedUsers"
}

# KMS: rotation never configured
resource "google_kms_crypto_key" "app" {
  name     = "vigilnz-fixture-key"
  key_ring  = "projects/vigilnz-fixture/locations/us-central1/keyRings/fixture"
}

# GKE: public endpoint, legacy ABAC, no network policy, no shielded nodes
resource "google_container_cluster" "main" {
  name     = "vigilnz-fixture-gke"
  location = "us-central1"

  initial_node_count = 1
  enable_legacy_abac = true

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "0.0.0.0/0"
      display_name = "all"
    }
  }

  network_policy {
    enabled = false
  }

  node_config {
    machine_type = "e2-medium"

    shielded_instance_config {
      enable_secure_boot          = false
      enable_integrity_monitoring = false
    }

    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  logging_service    = "none"
  monitoring_service = "none"
}
