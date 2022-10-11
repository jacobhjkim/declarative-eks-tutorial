provider "vault" {
  address = local.vault_address
}

data "vault_aws_access_credentials" "aws_credentials" {
  backend = "aws/${local.aws_account_id}"
  role    = "terraform-provisioner"
  type    = "sts"
}

provider "aws" {
  region     = local.region
  access_key = data.vault_aws_access_credentials.aws_credentials.access_key
  secret_key = data.vault_aws_access_credentials.aws_credentials.secret_key
  token      = data.vault_aws_access_credentials.aws_credentials.security_token
}

################################################################################
# VPC
################################################################################
data "aws_availability_zones" "azs" {}

module "vpc" {
  source  = "registry.terraform.io/terraform-aws-modules/vpc/aws"
  version = "v3.14.4"

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
