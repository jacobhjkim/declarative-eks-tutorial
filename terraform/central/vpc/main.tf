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
data "terraform_remote_state" "provisioner_state" {
  backend = "s3"
  config = {
    region = local.region
    bucket = local.tfstates_bucket
    key    = "central/iam.tfstate"
  }
}

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
    role_arn     = data.terraform_remote_state.provisioner_state.outputs.provisioner_iam_role_arn
    session_name = "${local.cluster_name}-vpc"
  }

  default_tags {
    tags = {
      Stage              = local.cluster_name
      Owner              = "declarative-eks-tutorial"
      Workspace          = "terraform/${local.cluster_name}/vpc"
      ManagedByTerraform = "true"
    }
  }
}

data "aws_availability_zones" "azs" {
  provider = aws.central
}

################################################################################
# VPC
################################################################################
module "vpc" {
  source  = "registry.terraform.io/terraform-aws-modules/vpc/aws"
  version = "v3.14.4"

  providers = {
    aws = aws.central
  }

  name = "${local.cluster_name}-vpc"
  cidr = local.cidr

  azs             = slice(data.aws_availability_zones.azs.names, 0, 3)
  private_subnets = local.private_subnets
  private_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = "1"
    "karpenter.sh/discovery"                      = local.cluster_name
  }
  public_subnets = local.public_subnets
  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
    "karpenter.sh/discovery" = local.cluster_name
  }
  intra_subnets = local.intra_subnets

  create_database_subnet_group = true
  database_subnets             = local.database_subnets
  database_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = "1"
    "karpenter.sh/discovery"                      = local.cluster_name
  }

  manage_default_network_acl  = true
  default_network_acl_name    = "${local.cluster_name}-vpc-acl-default"
  default_network_acl_ingress = [local.acl_policy_allow_all]
  default_network_acl_egress  = [local.acl_policy_allow_all]

  manage_default_security_group  = true
  default_security_group_name    = "${local.cluster_name}-vpc-sg-default"
  default_security_group_ingress = []
  default_security_group_egress  = []

  secondary_cidr_blocks = []

  enable_nat_gateway     = true
  single_nat_gateway     = false
  one_nat_gateway_per_az = false
  enable_dns_hostnames   = true
  enable_dns_support     = true

  tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
  }
}
