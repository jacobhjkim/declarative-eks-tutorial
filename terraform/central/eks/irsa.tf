################################################################################
# EKS IRSA
################################################################################
module "vpc_cni_irsa" {
  source  = "registry.terraform.io/terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.4.0"

  providers = { aws = aws.central }

  role_name             = "${local.cluster_name}-vpc-cni"
  attach_vpc_cni_policy = true
  vpc_cni_enable_ipv6   = true
  vpc_cni_enable_ipv4   = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-node"]
    }
  }
}

module "karpenter_irsa" {
  source  = "registry.terraform.io/terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.4.0"

  providers = { aws = aws.central }

  role_name                          = "${local.cluster_name}-karpenter-controller"
  attach_karpenter_controller_policy = true

  karpenter_controller_cluster_id = module.eks.cluster_id
  karpenter_controller_ssm_parameter_arns = [
    "arn:aws:ssm:*:*:parameter/aws/service/*"
  ]
  karpenter_controller_node_iam_role_arns = [
    module.eks.eks_managed_node_groups["karpenter"].iam_role_arn
  ]

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:karpenter"]
    }
  }
}

resource "aws_iam_instance_profile" "karpenter" {
  provider = aws.central
  name     = "KarpenterNodeInstanceProfile-${local.cluster_name}"
  role     = module.eks.eks_managed_node_groups["karpenter"].iam_role_name
}

module "external_dns_irsa_role" {
  source  = "registry.terraform.io/terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.4.0"

  providers = { aws = aws.central }

  role_name                     = "${local.cluster_name}-external-dns"
  attach_external_dns_policy    = true
  external_dns_hosted_zone_arns = ["arn:aws:route53:::hostedzone/*"]

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }
}

module "external_secrets_irsa_role" {
  source  = "registry.terraform.io/terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.4.0"

  providers = { aws = aws.central }

  role_name                             = "${local.cluster_name}-external-secrets"
  attach_external_secrets_policy        = true
  external_secrets_ssm_parameter_arns   = ["arn:aws:ssm:*:*:parameter/foo"]
  external_secrets_secrets_manager_arns = ["arn:aws:secretsmanager:*:*:secret:bar"]

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["external-secrets:kubernetes-external-secrets"]
    }
  }
}

module "load_balancer_controller_irsa_role" {
  source  = "registry.terraform.io/terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.4.0"

  providers = { aws = aws.central }

  role_name                              = "${local.cluster_name}-load-balancer-controller"
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

module "ebs_csi_driver_irsa_role" {
  source  = "registry.terraform.io/terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.4.0"

  providers = { aws = aws.central }

  role_name             = "${local.cluster_name}-ebs-csi-driver"
  attach_ebs_csi_policy = true

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa", "kube-system:ebs-csi-node-sa"]
    }
  }
}

module "node_termination_handler_irsa_role" {
  source  = "registry.terraform.io/terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.4.0"

  providers = { aws = aws.central }

  role_name                              = "${local.cluster_name}-node-termination-handler"
  attach_node_termination_handler_policy = true

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-node"]
    }
  }
}

module "iam_assumable_role_github_actions_ecr" {
  source    = "registry.terraform.io/terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version   = "5.4.0"
  providers = { aws = aws.central }

  create_role = true

  role_name        = "${local.cluster_name}-gha-runner"
  provider_url     = module.eks.oidc_provider
  role_policy_arns = [aws_iam_policy.github_actions_ecr.arn]
}

module "iam_assumable_role_atlantis_s3" {
  source    = "registry.terraform.io/terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version   = "5.4.0"
  providers = { aws = aws.central }

  create_role = true

  role_name        = "${local.cluster_name}-atlantis"
  provider_url     = module.eks.oidc_provider
  role_policy_arns = [aws_iam_policy.app_atlantis_s3.arn]
}

################################################################################
# EKS IRSA POLICIES
################################################################################

data "aws_iam_policy_document" "app_github_actions_ecr" {
  provider = aws.central

  statement {
    sid    = "GithubActionsEcr"
    effect = "Allow"

    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetRepositoryPolicy",
      "ecr:DescribeRepositories",
      "ecr:ListImages",
      "ecr:DescribeImages",
      "ecr:BatchGetImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
      "ecr-public:DescribeImageTags",
      "ecr-public:DescribeImages",
      "ecr-public:PutRepositoryCatalogData",
      "ecr-public:UploadLayerPart",
      "ecr-public:UntagResource",
      "ecr-public:DescribeRegistries",
      "ecr-public:GetRepositoryCatalogData",
      "ecr-public:TagResource",
      "ecr-public:CompleteLayerUpload",
      "ecr-public:InitiateLayerUpload",
      "ecr-public:PutImage",
      "ecr-public:GetRegistryCatalogData",
      "ecr-public:ListTagsForResource",
      "ecr-public:PutRegistryCatalogData",
      "ecr-public:BatchCheckLayerAvailability",
    ]

    resources = ["*"]
  }

  statement {
    sid = "GetToken"

    effect = "Allow"

    actions = [
      "ecr-public:GetAuthorizationToken",
      "sts:GetServiceBearerToken",
      "ecr:GetAuthorizationToken",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "github_actions_ecr" {
  provider = aws.central

  name_prefix = "${local.cluster_name}-gha-runner"
  description = "Grants ECR access to github actions for cluster: ${local.cluster_name}"
  policy      = data.aws_iam_policy_document.app_github_actions_ecr.json
}

data "terraform_remote_state" "terraform_backend" {
  backend = "s3"
  config = {
    region = local.cluster_region
    bucket = local.tfstates_bucket
    key    = "${local.cluster_name}/dynamo.tfstate"
  }
}

data "aws_iam_policy_document" "app_atlantis_s3" {
  provider = aws.central

  statement {
    sid = "AtlantisListAllS3Buckets"

    effect = "Allow"

    actions   = ["s3:ListAllMyBuckets"]
    resources = ["arn:aws:s3:::*"]
  }

  statement {
    sid    = "AtlantisS3AllAccess"
    effect = "Allow"

    actions = ["s3:*"]

    resources = [
      "arn:aws:s3:::${local.tfstates_bucket}",
      "arn:aws:s3:::${local.tfstates_bucket}/*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:DeleteItem",
      "dynamodb:DescribeTable",
    ]
    resources = [data.terraform_remote_state.terraform_backend.outputs.lock_table_arn]
  }
}

resource "aws_iam_policy" "app_atlantis_s3" {
  provider = aws.central

  name_prefix = "${local.cluster_name}-atlantis"
  description = "Grants atlantis access to ${local.tfstates_bucket}"
  policy      = data.aws_iam_policy_document.app_atlantis_s3.json
}
