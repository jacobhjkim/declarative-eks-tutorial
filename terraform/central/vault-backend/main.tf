################################################################################
# Credential AWS Provider
################################################################################
provider "aws" {
  alias  = "credential"
  region = local.region
}

################################################################################
# Central AWS Provider
################################################################################
data "aws_secretsmanager_secret" "central_provisioner" {
  provider = aws.credential
  name     = "central-provisioner-credentials"
}

data "aws_secretsmanager_secret_version" "central_provisioner" {
  provider  = aws.credential
  secret_id = data.aws_secretsmanager_secret.central_provisioner.id
}

locals {
  central_provisioner = jsondecode(data.aws_secretsmanager_secret_version.central_provisioner.secret_string)
}

provider "aws" {
  alias = "central"

  region     = local.region
  access_key = local.central_provisioner["accessKey"]
  secret_key = local.central_provisioner["secretKey"]

  assume_role {
    role_arn     = "arn:aws:iam::${local.aws_account_id}:role/${local.cluster_name}-provisioner"
    session_name = "central-vault"
  }

  default_tags {
    tags = {
      Stage              = local.cluster_name
      Owner              = "declarative-eks-tutorial"
      Workspace          = "terraform/${local.cluster_name}/vault-backend"
      ManagedByTerraform = "true"
    }
  }
}

provider "kubernetes" {
  alias = "central"
}

################################################################################
# Dynamo Backend
################################################################################
resource "aws_dynamodb_table" "vault_backend_prod" {
  provider = aws.central

  name         = "vault-backend"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "Path"
  range_key    = "Key"

  attribute {
    name = "Path"
    type = "S"
  }

  attribute {
    name = "Key"
    type = "S"
  }
}

################################################################################
# IAM & Keys
################################################################################
resource "aws_kms_key" "vault_unseal" {
  provider = aws.central

  description             = "Vault Auto Unseal Encrypt Key"
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "vault_unseal_alias" {
  provider = aws.central

  target_key_id = aws_kms_key.vault_unseal.id
  name          = "alias/vault-auto-unseal"
}

data "aws_iam_policy_document" "app_vault_cluster" {
  provider = aws.central

  statement {
    sid    = "VaultClusterPod"
    effect = "Allow"

    actions = [
      "kms:*",
      "dynamodb:DescribeLimits",
      "dynamodb:DescribeTimeToLive",
      "dynamodb:ListTagsOfResource",
      "dynamodb:DescribeReservedCapacityOfferings",
      "dynamodb:DescribeReservedCapacity",
      "dynamodb:ListTables",
      "dynamodb:BatchGetItem",
      "dynamodb:BatchWriteItem",
      "dynamodb:CreateTable",
      "dynamodb:DeleteItem",
      "dynamodb:GetItem",
      "dynamodb:GetRecords",
      "dynamodb:PutItem",
      "dynamodb:Query",
      "dynamodb:UpdateItem",
      "dynamodb:Scan",
      "dynamodb:DescribeTable",
      "iam:GetUser",
    ]

    resources = ["*"]
  }
}

resource "aws_iam_policy" "app_vault_cluster" {
  provider = aws.central

  name_prefix = "${local.cluster_name}-vault-cluster"
  description = "Vault cluster pod policy for cluster ${local.cluster_name}"
  policy      = data.aws_iam_policy_document.app_vault_cluster.json
}

data "aws_eks_cluster" "cluster" {
  provider = aws.central

  name = local.cluster_name
}

module "iam_assumable_role_vault_cluster" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version = "5.2.0"

  providers = {
    aws = aws.central
  }

  create_role  = true
  role_name    = "${local.cluster_name}-vault-cluster"
  provider_url = replace(data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer, "https://", "")
  role_policy_arns = [
    aws_iam_policy.app_vault_cluster.arn
  ]
}
