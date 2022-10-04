################################################################################
# Credential AWS Provider
################################################################################
provider "aws" {
  alias  = "credential"
  region = local.credentials_region
}

################################################################################
# Central AWS Provider
################################################################################
data "terraform_remote_state" "provisioner_state" {
  backend = "s3"
  config = {
    region = local.cluster_region
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

  region     = local.cluster_region
  access_key = local.central_provisioner["accessKey"]
  secret_key = local.central_provisioner["secretKey"]

  assume_role {
    role_arn     = data.terraform_remote_state.provisioner_state.outputs.provisioner_iam_role_arn
    session_name = "${local.cluster_name}-eks"
  }

  default_tags {
    tags = {
      Stage              = local.cluster_name
      Owner              = "declarative-eks-tutorial"
      Workspace          = "terraform/${local.cluster_name}/eks"
      ManagedByTerraform = "true"
    }
  }
}

################################################################################
# Kubernetes Provider for configuring aws-auth configmap
################################################################################
data "aws_eks_cluster_auth" "eks_auth" {
  provider = aws.central
  name     = module.eks.cluster_id
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  token                  = data.aws_eks_cluster_auth.eks_auth.token
}

################################################################################
# Central EKS Cluster
################################################################################
data "terraform_remote_state" "vpc_state" {
  backend = "s3"
  config = {
    region = local.cluster_region
    bucket = local.tfstates_bucket
    key    = "${local.cluster_name}/vpc.tfstate"
  }
}

data "aws_ami" "eks_default" {
  provider    = aws.central
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amazon-eks-node-${local.cluster_version}-v*"]
  }
}

module "eks" {
  source  = "registry.terraform.io/terraform-aws-modules/eks/aws"
  version = "v18.29.0"

  providers = {
    aws        = aws.central
    kubernetes = kubernetes
  }

  cluster_name                    = local.cluster_name
  cluster_version                 = local.cluster_version
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = true

  cluster_addons = {
    coredns = {
      resolve_conflicts = "OVERWRITE"
    }
    kube-proxy = {}
    vpc-cni = {
      addon_version            = "v1.11.4-eksbuild.1"
      resolve_conflicts        = "OVERWRITE"
      service_account_role_arn = module.vpc_cni_irsa.iam_role_arn
    }
  }

  vpc_id                   = local.vpc_id
  subnet_ids               = local.vpc_private_subnets
  control_plane_subnet_ids = local.vpc_intra_subnets

  node_security_group_additional_rules = {
    # Control plane invoke Karpenter webhook
    ingress_karpenter_webhook_tcp = {
      description                   = "Control plane invoke Karpenter webhook"
      protocol                      = "tcp"
      from_port                     = 8443
      to_port                       = 8443
      type                          = "ingress"
      source_cluster_security_group = true
    }
  }

  create_cluster_primary_security_group_tags = false

  eks_managed_node_groups = {
    karpenter = {
      name           = "karpenter"
      ami_id         = data.aws_ami.eks_default.image_id
      instance_types = ["m5.large"]

      min_size     = 1
      max_size     = 2
      desired_size = 1

      # This will ensure the boostrap user data is used to join the node
      # By default, EKS managed node groups will not append bootstrap script;
      # this adds it back in using the default template provided by the module
      # Note: this assumes the AMI provided is an EKS optimized AMI derivative
      enable_bootstrap_user_data = true

      vpc_security_group_ids = [aws_security_group.additional.id]

      iam_role_additional_policies = [
        # Required by Karpenter
        "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      ]
    }
  }

  // Setup EKS Auth
  create_aws_auth_configmap = false
  manage_aws_auth_configmap = true
  aws_auth_accounts         = [local.aws_account_id]
  aws_auth_roles = [
    {
      rolearn  = "arn:aws:iam::${local.aws_account_id}:role/${local.cluster_name}-provisioner"
      username = "${local.cluster_name}-provisioner"
      groups   = ["system:bootstrappers", "system:masters", "system:nodes"]
    }
  ]

  aws_auth_users = [
    {
      userarn  = "arn:aws:iam::${local.aws_account_id}:user/${local.cluster_name}-provisioner"
      username = "${local.cluster_name}-provisioner"
      groups   = ["system:masters"]
    },
    {
      userarn  = local.initial_user_arn
      username = local.initial_user
      groups   = ["system:masters"]
    }
  ]

  tags = {
    # NOTE - if creating multiple security groups with this module, only tag the
    # security group that Karpenter should utilize with the following tag
    # (i.e. - at most, only one security group should have this tag in your account)
    "karpenter.sh/discovery" = local.cluster_name
  }
}

################################################################################
# Security Groups
################################################################################

resource "aws_security_group_rule" "workers_access_self_ingress" {
  provider    = aws.central
  description = "Workers Self Access"

  security_group_id = module.eks.node_security_group_id

  type      = "ingress"
  from_port = 0
  to_port   = 0
  protocol  = "-1"
  self      = true
}

resource "aws_security_group_rule" "workers_access_internet_egress" {
  provider    = aws.central
  description = "Workers to Internet Access"

  security_group_id = module.eks.node_security_group_id

  type        = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "worker_access_from_cluster" {
  provider    = aws.central
  description = "Cluster to Worker Access for Extension ex.Admission"

  security_group_id = module.eks.node_security_group_id

  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  source_security_group_id = module.eks.cluster_primary_security_group_id
}

resource "aws_security_group" "additional" {
  provider    = aws.central
  name_prefix = "${local.cluster_name}-additional"
  vpc_id      = local.vpc_id

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
    ]
  }
}
