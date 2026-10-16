# File:    main.tf
# Purpose: IaC fixture. Azure Terraform resources with public exposure, HTTP
#          allowed, missing encryption and unhardened Key Vault / AKS.
#          Intentionally misconfigured - never apply.
# Author:  Vigilnz Security Engineering
# Date:    2026-10-16
#
# Expected rules: TF-AZURE-STORAGE-001..006, TF-AZURE-NSG-001..003,
#   TF-AZURE-VM-001..003, TF-AZURE-SQL-001..003, TF-AZURE-KV-001..004,
#   TF-AZURE-AKS-001/002, TF-AZURE-MONITOR-001

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "main" {
  name     = "vigilnz-fixture-rg"
  location = "eastus"
}

# Storage: plain HTTP allowed, public blobs, old TLS, no infrastructure encryption
resource "azurerm_storage_account" "assets" {
  name                            = "vigilnzfixtureassets"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  enable_https_traffic_only       = false
  min_tls_version                 = "TLS1_0"
  allow_nested_items_to_be_public = true
  infrastructure_encryption_enabled = false

  network_rules {
    default_action = "Allow"
  }
}

resource "azurerm_storage_container" "public" {
  name                  = "public"
  storage_account_name  = azurerm_storage_account.assets.name
  container_access_type = "container"
}

# NSG: SSH, RDP and all ports open to the internet
resource "azurerm_network_security_group" "wide_open" {
  name                = "vigilnz-fixture-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "allow-ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-rdp"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-any"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "0.0.0.0/0"
    destination_address_prefix = "*"
  }
}

# VM: password authentication, credentials in source, no disk encryption
resource "azurerm_linux_virtual_machine" "app" {
  name                            = "vigilnz-fixture-vm"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  size                            = "Standard_B2s"
  admin_username                  = "azureadmin"
  admin_password                  = "FixturePassw0rd!"
  disable_password_authentication = false
  network_interface_ids           = []

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }
}

# SQL: public network access, no auditing, no TDE
resource "azurerm_mssql_server" "app" {
  name                          = "vigilnz-fixture-sql"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  version                       = "12.0"
  administrator_login           = "sqladmin"
  administrator_login_password  = "FixturePassw0rd!"
  public_network_access_enabled = true
  minimum_tls_version           = "1.0"
}

resource "azurerm_mssql_firewall_rule" "allow_all" {
  name             = "allow-all"
  server_id        = azurerm_mssql_server.app.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

# Key Vault: no purge protection, no soft delete, public access
resource "azurerm_key_vault" "main" {
  name                          = "vigilnz-fixture-kv"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  tenant_id                     = "55555555-6666-7777-8888-999999999999"
  sku_name                      = "standard"
  purge_protection_enabled      = false
  soft_delete_retention_days    = 7
  public_network_access_enabled = true

  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }
}

# AKS: public API server, RBAC disabled, no network policy
resource "azurerm_kubernetes_cluster" "main" {
  name                            = "vigilnz-fixture-aks"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  dns_prefix                      = "fixture"
  role_based_access_control_enabled = false
  private_cluster_enabled         = false

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_B2s"
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin = "kubenet"
    network_policy = null
  }
}
