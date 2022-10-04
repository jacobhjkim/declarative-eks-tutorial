https://github.com/terraform-aws-modules/terraform-aws-eks/issues/2009#issuecomment-1198399600

```shell
$ terraform apply
data.terraform_remote_state.provisioner_state: Reading...
data.terraform_remote_state.terraform_backend: Reading...
data.terraform_remote_state.vpc_state: Reading...
data.terraform_remote_state.provisioner_state: Read complete after 0s
data.terraform_remote_state.terraform_backend: Read complete after 0s
data.terraform_remote_state.vpc_state: Read complete after 0s
data.aws_secretsmanager_secret.central_provisioner: Reading...
data.aws_partition.current: Reading...
data.aws_partition.current: Read complete after 0s [id=aws]
data.aws_secretsmanager_secret.central_provisioner: Read complete after 0s [id=arn:aws:secretsmanager:ap-northeast-2:765355018960:secret:central-provisioner-credentials-fqF9g7]
data.aws_secretsmanager_secret_version.central_provisioner: Reading...
data.aws_secretsmanager_secret_version.central_provisioner: Read complete after 0s [id=arn:aws:secretsmanager:ap-northeast-2:765355018960:secret:central-provisioner-credentials-fqF9g7|AWSCURRENT]
module.eks.data.aws_partition.current: Reading...
module.eks.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks.module.kms.data.aws_partition.current: Reading...
module.node_termination_handler_irsa_role.data.aws_partition.current: Reading...
module.ebs_csi_driver_irsa_role.data.aws_caller_identity.current: Reading...
module.eks.module.kms.data.aws_caller_identity.current: Reading...
module.eks.module.kms.data.aws_partition.current: Read complete after 0s [id=aws]
module.load_balancer_controller_irsa_role.data.aws_caller_identity.current: Reading...
module.node_termination_handler_irsa_role.data.aws_partition.current: Read complete after 0s [id=aws]
module.node_termination_handler_irsa_role.data.aws_iam_policy_document.node_termination_handler[0]: Reading...
module.external_secrets_irsa_role.data.aws_partition.current: Reading...
module.vpc_cni_irsa.data.aws_caller_identity.current: Reading...
module.load_balancer_controller_irsa_role.data.aws_partition.current: Reading...
module.karpenter_irsa.data.aws_caller_identity.current: Reading...
module.eks.data.aws_caller_identity.current: Reading...
module.external_secrets_irsa_role.data.aws_partition.current: Read complete after 0s [id=aws]
module.load_balancer_controller_irsa_role.data.aws_partition.current: Read complete after 0s [id=aws]
data.aws_iam_policy_document.app_atlantis_s3: Reading...
module.node_termination_handler_irsa_role.data.aws_iam_policy_document.node_termination_handler[0]: Read complete after 0s [id=734748348]
module.iam_assumable_role_atlantis_s3.data.aws_caller_identity.current: Reading...
module.node_termination_handler_irsa_role.data.aws_caller_identity.current: Reading...
data.aws_iam_policy_document.app_atlantis_s3: Read complete after 0s [id=4210213403]
data.aws_iam_policy_document.app_github_actions_ecr: Reading...
module.vpc_cni_irsa.data.aws_partition.current: Reading...
module.vpc_cni_irsa.data.aws_partition.current: Read complete after 0s [id=aws]
data.aws_iam_policy_document.app_github_actions_ecr: Read complete after 0s [id=290904615]
module.eks.module.eks_managed_node_group["karpenter"].data.aws_partition.current: Reading...
module.eks.module.eks_managed_node_group["karpenter"].data.aws_partition.current: Read complete after 0s [id=aws]
module.eks.module.eks_managed_node_group["karpenter"].data.aws_caller_identity.current: Reading...
module.external_dns_irsa_role.data.aws_partition.current: Reading...
module.external_dns_irsa_role.data.aws_partition.current: Read complete after 0s [id=aws]
module.karpenter_irsa.data.aws_partition.current: Reading...
module.karpenter_irsa.data.aws_partition.current: Read complete after 0s [id=aws]
module.iam_assumable_role_github_actions_ecr.data.aws_caller_identity.current: Reading...
module.vpc_cni_irsa.data.aws_caller_identity.current: Read complete after 1s [id=765355018960]
module.ebs_csi_driver_irsa_role.data.aws_partition.current: Reading...
module.ebs_csi_driver_irsa_role.data.aws_partition.current: Read complete after 0s [id=aws]
module.external_dns_irsa_role.data.aws_caller_identity.current: Reading...
module.ebs_csi_driver_irsa_role.data.aws_caller_identity.current: Read complete after 1s [id=765355018960]
module.external_secrets_irsa_role.data.aws_caller_identity.current: Reading...
module.karpenter_irsa.data.aws_caller_identity.current: Read complete after 1s [id=765355018960]
module.external_secrets_irsa_role.data.aws_iam_policy_document.external_secrets[0]: Reading...
module.external_secrets_irsa_role.data.aws_iam_policy_document.external_secrets[0]: Read complete after 0s [id=1557395652]
module.load_balancer_controller_irsa_role.data.aws_caller_identity.current: Read complete after 1s [id=765355018960]
module.eks.data.aws_caller_identity.current: Read complete after 1s [id=765355018960]
module.iam_assumable_role_atlantis_s3.data.aws_partition.current: Reading...
module.iam_assumable_role_github_actions_ecr.data.aws_partition.current: Reading...
module.node_termination_handler_irsa_role.data.aws_caller_identity.current: Read complete after 1s [id=765355018960]
module.iam_assumable_role_atlantis_s3.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks.module.kms.data.aws_caller_identity.current: Read complete after 1s [id=765355018960]
module.iam_assumable_role_github_actions_ecr.data.aws_partition.current: Read complete after 0s [id=aws]
module.iam_assumable_role_atlantis_s3.data.aws_caller_identity.current: Read complete after 1s [id=765355018960]
module.external_dns_irsa_role.data.aws_iam_policy_document.external_dns[0]: Reading...
module.external_dns_irsa_role.data.aws_caller_identity.current: Read complete after 0s [id=765355018960]
module.iam_assumable_role_github_actions_ecr.data.aws_caller_identity.current: Read complete after 0s [id=765355018960]
module.external_dns_irsa_role.data.aws_iam_policy_document.external_dns[0]: Read complete after 0s [id=1621011895]
module.eks.module.eks_managed_node_group["karpenter"].data.aws_caller_identity.current: Read complete after 0s [id=765355018960]
module.external_secrets_irsa_role.data.aws_caller_identity.current: Read complete after 0s [id=765355018960]
module.eks.data.aws_iam_policy_document.assume_role_policy[0]: Reading...
module.eks.data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2764486067]
module.eks.module.eks_managed_node_group["karpenter"].data.aws_iam_policy_document.assume_role_policy[0]: Reading...
module.eks.module.eks_managed_node_group["karpenter"].data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2560088296]
module.vpc_cni_irsa.data.aws_iam_policy_document.vpc_cni[0]: Reading...
module.vpc_cni_irsa.data.aws_iam_policy_document.vpc_cni[0]: Read complete after 0s [id=572553129]
module.load_balancer_controller_irsa_role.data.aws_iam_policy_document.load_balancer_controller[0]: Reading...
module.ebs_csi_driver_irsa_role.data.aws_iam_policy_document.ebs_csi[0]: Reading...
module.load_balancer_controller_irsa_role.data.aws_iam_policy_document.load_balancer_controller[0]: Read complete after 0s [id=1283547419]
module.ebs_csi_driver_irsa_role.data.aws_iam_policy_document.ebs_csi[0]: Read complete after 0s [id=1888929143]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create
 <= read (data resources)

Terraform will perform the following actions:

  # data.aws_eks_cluster_auth.eks_auth will be read during apply
  # (config refers to values not yet known)
 <= data "aws_eks_cluster_auth" "eks_auth" {
      + id    = (known after apply)
      + name  = (known after apply)
      + token = (sensitive value)
    }

  # aws_iam_instance_profile.karpenter will be created
  + resource "aws_iam_instance_profile" "karpenter" {
      + arn         = (known after apply)
      + create_date = (known after apply)
      + id          = (known after apply)
      + name        = "KarpenterNodeInstanceProfile-central"
      + path        = "/"
      + role        = (known after apply)
      + tags_all    = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
      + unique_id   = (known after apply)
    }

  # aws_iam_policy.app_atlantis_s3 will be created
  + resource "aws_iam_policy" "app_atlantis_s3" {
      + arn         = (known after apply)
      + description = "Grants atlantis access to declarative-eks-tutorial-tfstates"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "central-atlantis"
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = "s3:ListAllMyBuckets"
                      + Effect   = "Allow"
                      + Resource = "arn:aws:s3:::*"
                      + Sid      = "AtlantisListAllS3Buckets"
                    },
                  + {
                      + Action   = "s3:*"
                      + Effect   = "Allow"
                      + Resource = [
                          + "arn:aws:s3:::declarative-eks-tutorial-tfstates/*",
                          + "arn:aws:s3:::declarative-eks-tutorial-tfstates",
                        ]
                      + Sid      = "AtlantisS3AllAccess"
                    },
                  + {
                      + Action   = [
                          + "dynamodb:PutItem",
                          + "dynamodb:GetItem",
                          + "dynamodb:DescribeTable",
                          + "dynamodb:DeleteItem",
                        ]
                      + Effect   = "Allow"
                      + Resource = "arn:aws:dynamodb:ap-northeast-2:765355018960:table/tutorial-terraform-backend-locks"
                      + Sid      = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags_all    = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
    }

  # aws_iam_policy.github_actions_ecr will be created
  + resource "aws_iam_policy" "github_actions_ecr" {
      + arn         = (known after apply)
      + description = "Grants ECR access to github actions for cluster: central"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "central-gha-runner"
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "ecr:UploadLayerPart",
                          + "ecr:PutImage",
                          + "ecr:ListImages",
                          + "ecr:InitiateLayerUpload",
                          + "ecr:GetRepositoryPolicy",
                          + "ecr:GetDownloadUrlForLayer",
                          + "ecr:DescribeRepositories",
                          + "ecr:DescribeImages",
                          + "ecr:CompleteLayerUpload",
                          + "ecr:BatchGetImage",
                          + "ecr:BatchCheckLayerAvailability",
                          + "ecr-public:UploadLayerPart",
                          + "ecr-public:UntagResource",
                          + "ecr-public:TagResource",
                          + "ecr-public:PutRepositoryCatalogData",
                          + "ecr-public:PutRegistryCatalogData",
                          + "ecr-public:PutImage",
                          + "ecr-public:ListTagsForResource",
                          + "ecr-public:InitiateLayerUpload",
                          + "ecr-public:GetRepositoryCatalogData",
                          + "ecr-public:GetRegistryCatalogData",
                          + "ecr-public:DescribeRegistries",
                          + "ecr-public:DescribeImages",
                          + "ecr-public:DescribeImageTags",
                          + "ecr-public:CompleteLayerUpload",
                          + "ecr-public:BatchCheckLayerAvailability",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = "GithubActionsEcr"
                    },
                  + {
                      + Action   = [
                          + "sts:GetServiceBearerToken",
                          + "ecr:GetAuthorizationToken",
                          + "ecr-public:GetAuthorizationToken",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = "GetToken"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags_all    = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
    }

  # aws_security_group_rule.worker_access_from_cluster will be created
  + resource "aws_security_group_rule" "worker_access_from_cluster" {
      + description              = "Cluster to Worker Access for Extension ex.Admission"
      + from_port                = 0
      + id                       = (known after apply)
      + protocol                 = "-1"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 0
      + type                     = "ingress"
    }

  # aws_security_group_rule.workers_access_internet_egress will be created
  + resource "aws_security_group_rule" "workers_access_internet_egress" {
      + cidr_blocks              = [
          + "0.0.0.0/0",
        ]
      + description              = "Workers to Internet Access"
      + from_port                = 0
      + id                       = (known after apply)
      + protocol                 = "-1"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 0
      + type                     = "egress"
    }

  # aws_security_group_rule.workers_access_self_ingress will be created
  + resource "aws_security_group_rule" "workers_access_self_ingress" {
      + description              = "Workers Self Access"
      + from_port                = 0
      + id                       = (known after apply)
      + protocol                 = "-1"
      + security_group_id        = (known after apply)
      + self                     = true
      + source_security_group_id = (known after apply)
      + to_port                  = 0
      + type                     = "ingress"
    }

  # module.ebs_csi_driver_irsa_role.data.aws_iam_policy_document.this[0] will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "this" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions = [
              + "sts:AssumeRoleWithWebIdentity",
            ]
          + effect  = "Allow"

          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "sts.amazonaws.com",
                ]
              + variable = (known after apply)
            }
          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "system:serviceaccount:kube-system:ebs-csi-controller-sa",
                  + "system:serviceaccount:kube-system:ebs-csi-node-sa",
                ]
              + variable = (known after apply)
            }

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "Federated"
            }
        }
    }

  # module.ebs_csi_driver_irsa_role.aws_iam_policy.ebs_csi[0] will be created
  + resource "aws_iam_policy" "ebs_csi" {
      + arn         = (known after apply)
      + description = "Provides permissions to manage EBS volumes via the container storage interface driver"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "AmazonEKS_EBS_CSI_Policy-"
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "ec2:ModifyVolume",
                          + "ec2:DetachVolume",
                          + "ec2:DescribeVolumesModifications",
                          + "ec2:DescribeVolumes",
                          + "ec2:DescribeTags",
                          + "ec2:DescribeSnapshots",
                          + "ec2:DescribeInstances",
                          + "ec2:DescribeAvailabilityZones",
                          + "ec2:CreateSnapshot",
                          + "ec2:AttachVolume",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = ""
                    },
                  + {
                      + Action    = "ec2:CreateTags"
                      + Condition = {
                          + StringEquals = {
                              + "ec2:CreateAction" = [
                                  + "CreateVolume",
                                  + "CreateSnapshot",
                                ]
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = [
                          + "arn:aws:ec2:*:*:volume/*",
                          + "arn:aws:ec2:*:*:snapshot/*",
                        ]
                      + Sid       = ""
                    },
                  + {
                      + Action   = "ec2:DeleteTags"
                      + Effect   = "Allow"
                      + Resource = [
                          + "arn:aws:ec2:*:*:volume/*",
                          + "arn:aws:ec2:*:*:snapshot/*",
                        ]
                      + Sid      = ""
                    },
                  + {
                      + Action    = "ec2:CreateVolume"
                      + Condition = {
                          + StringLike = {
                              + "aws:RequestTag/ebs.csi.aws.com/cluster" = "true"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "*"
                      + Sid       = ""
                    },
                  + {
                      + Action    = "ec2:CreateVolume"
                      + Condition = {
                          + StringLike = {
                              + "aws:RequestTag/CSIVolumeName" = "*"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "*"
                      + Sid       = ""
                    },
                  + {
                      + Action    = "ec2:CreateVolume"
                      + Condition = {
                          + StringLike = {
                              + "aws:RequestTag/kubernetes.io/cluster/*" = "owned"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "*"
                      + Sid       = ""
                    },
                  + {
                      + Action    = "ec2:DeleteVolume"
                      + Condition = {
                          + StringLike = {
                              + "ec2:ResourceTag/ebs.csi.aws.com/cluster" = "true"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "*"
                      + Sid       = ""
                    },
                  + {
                      + Action    = "ec2:DeleteVolume"
                      + Condition = {
                          + StringLike = {
                              + "ec2:ResourceTag/CSIVolumeName" = "*"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "*"
                      + Sid       = ""
                    },
                  + {
                      + Action    = "ec2:DeleteVolume"
                      + Condition = {
                          + StringLike = {
                              + "ec2:ResourceTag/kubernetes.io/cluster/*" = "owned"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "*"
                      + Sid       = ""
                    },
                  + {
                      + Action    = "ec2:DeleteSnapshot"
                      + Condition = {
                          + StringLike = {
                              + "ec2:ResourceTag/CSIVolumeSnapshotName" = "*"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "*"
                      + Sid       = ""
                    },
                  + {
                      + Action    = "ec2:DeleteSnapshot"
                      + Condition = {
                          + StringLike = {
                              + "ec2:ResourceTag/ebs.csi.aws.com/cluster" = "true"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "*"
                      + Sid       = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags_all    = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
    }

  # module.ebs_csi_driver_irsa_role.aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = (known after apply)
      + create_date           = (known after apply)
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "central-ebs-csi-driver"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.ebs_csi_driver_irsa_role.aws_iam_role_policy_attachment.ebs_csi[0] will be created
  + resource "aws_iam_role_policy_attachment" "ebs_csi" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "central-ebs-csi-driver"
    }

  # module.eks.data.tls_certificate.this[0] will be read during apply
  # (config refers to values not yet known)
 <= data "tls_certificate" "this" {
      + certificates = (known after apply)
      + id           = (known after apply)
      + url          = (known after apply)
    }

  # module.eks.aws_cloudwatch_log_group.this[0] will be created
  + resource "aws_cloudwatch_log_group" "this" {
      + arn               = (known after apply)
      + id                = (known after apply)
      + name              = "/aws/eks/central/cluster"
      + retention_in_days = 90
      + tags              = {
          + "karpenter.sh/discovery" = "central"
        }
      + tags_all          = {
          + "ManagedByTerraform"     = "true"
          + "Owner"                  = "declarative-eks-tutorial"
          + "Stage"                  = "central"
          + "Workspace"              = "terraform/central/eks"
          + "karpenter.sh/discovery" = "central"
        }
    }

  # module.eks.aws_eks_addon.this["coredns"] will be created
  + resource "aws_eks_addon" "this" {
      + addon_name        = "coredns"
      + addon_version     = (known after apply)
      + arn               = (known after apply)
      + cluster_name      = "central"
      + created_at        = (known after apply)
      + id                = (known after apply)
      + modified_at       = (known after apply)
      + resolve_conflicts = "OVERWRITE"
      + tags              = {
          + "karpenter.sh/discovery" = "central"
        }
      + tags_all          = {
          + "ManagedByTerraform"     = "true"
          + "Owner"                  = "declarative-eks-tutorial"
          + "Stage"                  = "central"
          + "Workspace"              = "terraform/central/eks"
          + "karpenter.sh/discovery" = "central"
        }
    }

  # module.eks.aws_eks_addon.this["kube-proxy"] will be created
  + resource "aws_eks_addon" "this" {
      + addon_name    = "kube-proxy"
      + addon_version = (known after apply)
      + arn           = (known after apply)
      + cluster_name  = "central"
      + created_at    = (known after apply)
      + id            = (known after apply)
      + modified_at   = (known after apply)
      + tags          = {
          + "karpenter.sh/discovery" = "central"
        }
      + tags_all      = {
          + "ManagedByTerraform"     = "true"
          + "Owner"                  = "declarative-eks-tutorial"
          + "Stage"                  = "central"
          + "Workspace"              = "terraform/central/eks"
          + "karpenter.sh/discovery" = "central"
        }
    }

  # module.eks.aws_eks_addon.this["vpc-cni"] will be created
  + resource "aws_eks_addon" "this" {
      + addon_name               = "vpc-cni"
      + addon_version            = (known after apply)
      + arn                      = (known after apply)
      + cluster_name             = "central"
      + created_at               = (known after apply)
      + id                       = (known after apply)
      + modified_at              = (known after apply)
      + resolve_conflicts        = "OVERWRITE"
      + service_account_role_arn = (known after apply)
      + tags                     = {
          + "karpenter.sh/discovery" = "central"
        }
      + tags_all                 = {
          + "ManagedByTerraform"     = "true"
          + "Owner"                  = "declarative-eks-tutorial"
          + "Stage"                  = "central"
          + "Workspace"              = "terraform/central/eks"
          + "karpenter.sh/discovery" = "central"
        }
    }

  # module.eks.aws_eks_cluster.this[0] will be created
  + resource "aws_eks_cluster" "this" {
      + arn                       = (known after apply)
      + certificate_authority     = (known after apply)
      + created_at                = (known after apply)
      + enabled_cluster_log_types = [
          + "api",
          + "audit",
          + "authenticator",
        ]
      + endpoint                  = (known after apply)
      + id                        = (known after apply)
      + identity                  = (known after apply)
      + name                      = "central"
      + platform_version          = (known after apply)
      + role_arn                  = (known after apply)
      + status                    = (known after apply)
      + tags                      = {
          + "karpenter.sh/discovery" = "central"
        }
      + tags_all                  = {
          + "ManagedByTerraform"     = "true"
          + "Owner"                  = "declarative-eks-tutorial"
          + "Stage"                  = "central"
          + "Workspace"              = "terraform/central/eks"
          + "karpenter.sh/discovery" = "central"
        }
      + version                   = "1.23"

      + kubernetes_network_config {
          + ip_family         = (known after apply)
          + service_ipv4_cidr = (known after apply)
        }

      + timeouts {}

      + vpc_config {
          + cluster_security_group_id = (known after apply)
          + endpoint_private_access   = true
          + endpoint_public_access    = true
          + public_access_cidrs       = [
              + "0.0.0.0/0",
            ]
          + security_group_ids        = (known after apply)
          + subnet_ids                = [
              + "subnet-0196c2ca53418a26d",
              + "subnet-07d81f0297d037df4",
              + "subnet-0906640cdfba614e9",
            ]
          + vpc_id                    = (known after apply)
        }
    }

  # module.eks.aws_iam_openid_connect_provider.oidc_provider[0] will be created
  + resource "aws_iam_openid_connect_provider" "oidc_provider" {
      + arn             = (known after apply)
      + client_id_list  = [
          + "sts.amazonaws.com",
        ]
      + id              = (known after apply)
      + tags            = {
          + "Name"                   = "central-eks-irsa"
          + "karpenter.sh/discovery" = "central"
        }
      + tags_all        = {
          + "ManagedByTerraform"     = "true"
          + "Name"                   = "central-eks-irsa"
          + "Owner"                  = "declarative-eks-tutorial"
          + "Stage"                  = "central"
          + "Workspace"              = "terraform/central/eks"
          + "karpenter.sh/discovery" = "central"
        }
      + thumbprint_list = (known after apply)
      + url             = (known after apply)
    }

  # module.eks.aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "eks.amazonaws.com"
                        }
                      + Sid       = "EKSClusterAssumeRole"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = (known after apply)
      + name_prefix           = "central-cluster-"
      + path                  = "/"
      + tags                  = {
          + "karpenter.sh/discovery" = "central"
        }
      + tags_all              = {
          + "ManagedByTerraform"     = "true"
          + "Owner"                  = "declarative-eks-tutorial"
          + "Stage"                  = "central"
          + "Workspace"              = "terraform/central/eks"
          + "karpenter.sh/discovery" = "central"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = "central-cluster"
          + policy = (known after apply)
        }
    }

  # module.eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
      + role       = (known after apply)
    }

  # module.eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
      + role       = (known after apply)
    }

  # module.eks.aws_security_group.cluster[0] will be created
  + resource "aws_security_group" "cluster" {
      + arn                    = (known after apply)
      + description            = "EKS cluster security group"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "central-cluster-"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name"                   = "central-cluster"
          + "karpenter.sh/discovery" = "central"
        }
      + tags_all               = {
          + "ManagedByTerraform"     = "true"
          + "Name"                   = "central-cluster"
          + "Owner"                  = "declarative-eks-tutorial"
          + "Stage"                  = "central"
          + "Workspace"              = "terraform/central/eks"
          + "karpenter.sh/discovery" = "central"
        }
      + vpc_id                 = "vpc-020aaebb726af41a4"
    }

  # module.eks.aws_security_group.node[0] will be created
  + resource "aws_security_group" "node" {
      + arn                    = (known after apply)
      + description            = "EKS node shared security group"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "central-node-"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name"                          = "central-node"
          + "karpenter.sh/discovery"        = "central"
          + "kubernetes.io/cluster/central" = "owned"
        }
      + tags_all               = {
          + "ManagedByTerraform"            = "true"
          + "Name"                          = "central-node"
          + "Owner"                         = "declarative-eks-tutorial"
          + "Stage"                         = "central"
          + "Workspace"                     = "terraform/central/eks"
          + "karpenter.sh/discovery"        = "central"
          + "kubernetes.io/cluster/central" = "owned"
        }
      + vpc_id                 = "vpc-020aaebb726af41a4"
    }

  # module.eks.aws_security_group_rule.cluster["egress_nodes_443"] will be created
  + resource "aws_security_group_rule" "cluster" {
      + description              = "Cluster API to node groups"
      + from_port                = 443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.cluster["egress_nodes_kubelet"] will be created
  + resource "aws_security_group_rule" "cluster" {
      + description              = "Cluster API to node kubelets"
      + from_port                = 10250
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 10250
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.cluster["ingress_nodes_443"] will be created
  + resource "aws_security_group_rule" "cluster" {
      + description              = "Node groups to cluster API"
      + from_port                = 443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["egress_cluster_443"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Node groups to cluster API"
      + from_port                = 443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.node["egress_https"] will be created
  + resource "aws_security_group_rule" "node" {
      + cidr_blocks              = [
          + "0.0.0.0/0",
        ]
      + description              = "Egress all HTTPS to internet"
      + from_port                = 443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.node["egress_ntp_tcp"] will be created
  + resource "aws_security_group_rule" "node" {
      + cidr_blocks              = [
          + "0.0.0.0/0",
        ]
      + description              = "Egress NTP/TCP to internet"
      + from_port                = 123
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 123
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.node["egress_ntp_udp"] will be created
  + resource "aws_security_group_rule" "node" {
      + cidr_blocks              = [
          + "0.0.0.0/0",
        ]
      + description              = "Egress NTP/UDP to internet"
      + from_port                = 123
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "udp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 123
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.node["egress_self_coredns_tcp"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Node to node CoreDNS"
      + from_port                = 53
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = true
      + source_security_group_id = (known after apply)
      + to_port                  = 53
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.node["egress_self_coredns_udp"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Node to node CoreDNS"
      + from_port                = 53
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "udp"
      + security_group_id        = (known after apply)
      + self                     = true
      + source_security_group_id = (known after apply)
      + to_port                  = 53
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.node["ingress_cluster_443"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Cluster API to node groups"
      + from_port                = 443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_cluster_kubelet"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Cluster API to node kubelets"
      + from_port                = 10250
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 10250
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_karpenter_webhook_tcp"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Control plane invoke Karpenter webhook"
      + from_port                = 8443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 8443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_self_coredns_tcp"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Node to node CoreDNS"
      + from_port                = 53
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = true
      + source_security_group_id = (known after apply)
      + to_port                  = 53
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_self_coredns_udp"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Node to node CoreDNS"
      + from_port                = 53
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "udp"
      + security_group_id        = (known after apply)
      + self                     = true
      + source_security_group_id = (known after apply)
      + to_port                  = 53
      + type                     = "ingress"
    }

  # module.eks.kubernetes_config_map_v1_data.aws_auth[0] will be created
  + resource "kubernetes_config_map_v1_data" "aws_auth" {
      + data  = (known after apply)
      + force = true
      + id    = (known after apply)

      + metadata {
          + name      = "aws-auth"
          + namespace = "kube-system"
        }
    }

  # module.external_dns_irsa_role.data.aws_iam_policy_document.this[0] will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "this" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions = [
              + "sts:AssumeRoleWithWebIdentity",
            ]
          + effect  = "Allow"

          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "sts.amazonaws.com",
                ]
              + variable = (known after apply)
            }
          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "system:serviceaccount:kube-system:external-dns",
                ]
              + variable = (known after apply)
            }

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "Federated"
            }
        }
    }

  # module.external_dns_irsa_role.aws_iam_policy.external_dns[0] will be created
  + resource "aws_iam_policy" "external_dns" {
      + arn         = (known after apply)
      + description = "External DNS policy to allow management of Route53 hosted zone records"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "AmazonEKS_External_DNS_Policy-"
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = "route53:ChangeResourceRecordSets"
                      + Effect   = "Allow"
                      + Resource = "arn:aws:route53:::hostedzone/*"
                      + Sid      = ""
                    },
                  + {
                      + Action   = [
                          + "route53:ListResourceRecordSets",
                          + "route53:ListHostedZones",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags_all    = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
    }

  # module.external_dns_irsa_role.aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = (known after apply)
      + create_date           = (known after apply)
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "central-external-dns"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.external_dns_irsa_role.aws_iam_role_policy_attachment.external_dns[0] will be created
  + resource "aws_iam_role_policy_attachment" "external_dns" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "central-external-dns"
    }

  # module.external_secrets_irsa_role.data.aws_iam_policy_document.this[0] will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "this" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions = [
              + "sts:AssumeRoleWithWebIdentity",
            ]
          + effect  = "Allow"

          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "sts.amazonaws.com",
                ]
              + variable = (known after apply)
            }
          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "system:serviceaccount:external-secrets:kubernetes-external-secrets",
                ]
              + variable = (known after apply)
            }

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "Federated"
            }
        }
    }

  # module.external_secrets_irsa_role.aws_iam_policy.external_secrets[0] will be created
  + resource "aws_iam_policy" "external_secrets" {
      + arn         = (known after apply)
      + description = "Provides permissions to for External Secrets to retrieve secrets from AWS SSM and AWS Secrets Manager"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "AmazonEKS_External_Secrets_Policy-"
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = "ssm:GetParameter"
                      + Effect   = "Allow"
                      + Resource = "arn:aws:ssm:*:*:parameter/foo"
                      + Sid      = ""
                    },
                  + {
                      + Action   = [
                          + "secretsmanager:ListSecretVersionIds",
                          + "secretsmanager:GetSecretValue",
                          + "secretsmanager:GetResourcePolicy",
                          + "secretsmanager:DescribeSecret",
                        ]
                      + Effect   = "Allow"
                      + Resource = "arn:aws:secretsmanager:*:*:secret:bar"
                      + Sid      = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags_all    = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
    }

  # module.external_secrets_irsa_role.aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = (known after apply)
      + create_date           = (known after apply)
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "central-external-secrets"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.external_secrets_irsa_role.aws_iam_role_policy_attachment.external_secrets[0] will be created
  + resource "aws_iam_role_policy_attachment" "external_secrets" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "central-external-secrets"
    }

  # module.iam_assumable_role_atlantis_s3.data.aws_iam_policy_document.assume_role_with_oidc[0] will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "assume_role_with_oidc" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions       = (known after apply)
          + effect        = (known after apply)
          + not_actions   = (known after apply)
          + not_resources = (known after apply)
          + resources     = (known after apply)
          + sid           = (known after apply)

          + condition {
              + test     = (known after apply)
              + values   = (known after apply)
              + variable = (known after apply)
            }

          + not_principals {
              + identifiers = (known after apply)
              + type        = (known after apply)
            }

          + principals {
              + identifiers = (known after apply)
              + type        = (known after apply)
            }
        }
    }

  # module.iam_assumable_role_atlantis_s3.aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = (known after apply)
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "central-atlantis"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.iam_assumable_role_atlantis_s3.aws_iam_role_policy_attachment.custom[0] will be created
  + resource "aws_iam_role_policy_attachment" "custom" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "central-atlantis"
    }

  # module.iam_assumable_role_github_actions_ecr.data.aws_iam_policy_document.assume_role_with_oidc[0] will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "assume_role_with_oidc" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions       = (known after apply)
          + effect        = (known after apply)
          + not_actions   = (known after apply)
          + not_resources = (known after apply)
          + resources     = (known after apply)
          + sid           = (known after apply)

          + condition {
              + test     = (known after apply)
              + values   = (known after apply)
              + variable = (known after apply)
            }

          + not_principals {
              + identifiers = (known after apply)
              + type        = (known after apply)
            }

          + principals {
              + identifiers = (known after apply)
              + type        = (known after apply)
            }
        }
    }

  # module.iam_assumable_role_github_actions_ecr.aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = (known after apply)
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "central-gha-runner"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.iam_assumable_role_github_actions_ecr.aws_iam_role_policy_attachment.custom[0] will be created
  + resource "aws_iam_role_policy_attachment" "custom" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "central-gha-runner"
    }

  # module.karpenter_irsa.data.aws_iam_policy_document.karpenter_controller[0] will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "karpenter_controller" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions   = [
              + "ec2:CreateFleet",
              + "ec2:CreateLaunchTemplate",
              + "ec2:CreateTags",
              + "ec2:DescribeAvailabilityZones",
              + "ec2:DescribeImages",
              + "ec2:DescribeInstanceTypeOfferings",
              + "ec2:DescribeInstanceTypes",
              + "ec2:DescribeInstances",
              + "ec2:DescribeLaunchTemplates",
              + "ec2:DescribeSecurityGroups",
              + "ec2:DescribeSpotPriceHistory",
              + "ec2:DescribeSubnets",
              + "pricing:GetProducts",
            ]
          + resources = [
              + "*",
            ]
        }
      + statement {
          + actions   = [
              + "ec2:DeleteLaunchTemplate",
              + "ec2:TerminateInstances",
            ]
          + resources = [
              + "*",
            ]

          + condition {
              + test     = "StringEquals"
              + values   = [
                  + (known after apply),
                ]
              + variable = "ec2:ResourceTag/karpenter.sh/discovery"
            }
        }
      + statement {
          + actions   = [
              + "ec2:RunInstances",
            ]
          + resources = [
              + "arn:aws:ec2:*:765355018960:launch-template/*",
              + "arn:aws:ec2:*:765355018960:security-group/*",
            ]

          + condition {
              + test     = "StringEquals"
              + values   = [
                  + (known after apply),
                ]
              + variable = "ec2:ResourceTag/karpenter.sh/discovery"
            }
        }
      + statement {
          + actions   = [
              + "ec2:RunInstances",
            ]
          + resources = [
              + "arn:aws:ec2:*:765355018960:instance/*",
              + "arn:aws:ec2:*:765355018960:network-interface/*",
              + "arn:aws:ec2:*:765355018960:spot-instances-request/*",
              + "arn:aws:ec2:*:765355018960:subnet/*",
              + "arn:aws:ec2:*:765355018960:volume/*",
              + "arn:aws:ec2:*::image/*",
            ]
        }
      + statement {
          + actions   = [
              + "ssm:GetParameter",
            ]
          + resources = [
              + "arn:aws:ssm:*:*:parameter/aws/service/*",
            ]
        }
      + statement {
          + actions   = [
              + "iam:PassRole",
            ]
          + resources = [
              + (known after apply),
            ]
        }
    }

  # module.karpenter_irsa.data.aws_iam_policy_document.this[0] will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "this" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions = [
              + "sts:AssumeRoleWithWebIdentity",
            ]
          + effect  = "Allow"

          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "sts.amazonaws.com",
                ]
              + variable = (known after apply)
            }
          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "system:serviceaccount:karpenter:karpenter",
                ]
              + variable = (known after apply)
            }

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "Federated"
            }
        }
    }

  # module.karpenter_irsa.aws_iam_policy.karpenter_controller[0] will be created
  + resource "aws_iam_policy" "karpenter_controller" {
      + arn         = (known after apply)
      + description = "Provides permissions to handle node termination events via the Node Termination Handler"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "AmazonEKS_Karpenter_Controller_Policy-"
      + path        = "/"
      + policy      = (known after apply)
      + policy_id   = (known after apply)
      + tags_all    = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
    }

  # module.karpenter_irsa.aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = (known after apply)
      + create_date           = (known after apply)
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "central-karpenter-controller"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.karpenter_irsa.aws_iam_role_policy_attachment.karpenter_controller[0] will be created
  + resource "aws_iam_role_policy_attachment" "karpenter_controller" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "central-karpenter-controller"
    }

  # module.load_balancer_controller_irsa_role.data.aws_iam_policy_document.this[0] will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "this" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions = [
              + "sts:AssumeRoleWithWebIdentity",
            ]
          + effect  = "Allow"

          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "sts.amazonaws.com",
                ]
              + variable = (known after apply)
            }
          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "system:serviceaccount:kube-system:aws-load-balancer-controller",
                ]
              + variable = (known after apply)
            }

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "Federated"
            }
        }
    }

  # module.load_balancer_controller_irsa_role.aws_iam_policy.load_balancer_controller[0] will be created
  + resource "aws_iam_policy" "load_balancer_controller" {
      + arn         = (known after apply)
      + description = "Provides permissions for AWS Load Balancer Controller addon"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "AmazonEKS_AWS_Load_Balancer_Controller-"
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "iam:CreateServiceLinkedRole"
                      + Condition = {
                          + StringEquals = {
                              + "iam:AWSServiceName" = "elasticloadbalancing.amazonaws.com"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "*"
                      + Sid       = ""
                    },
                  + {
                      + Action   = [
                          + "elasticloadbalancing:DescribeTargetHealth",
                          + "elasticloadbalancing:DescribeTargetGroups",
                          + "elasticloadbalancing:DescribeTargetGroupAttributes",
                          + "elasticloadbalancing:DescribeTags",
                          + "elasticloadbalancing:DescribeSSLPolicies",
                          + "elasticloadbalancing:DescribeRules",
                          + "elasticloadbalancing:DescribeLoadBalancers",
                          + "elasticloadbalancing:DescribeLoadBalancerAttributes",
                          + "elasticloadbalancing:DescribeListeners",
                          + "elasticloadbalancing:DescribeListenerCertificates",
                          + "ec2:GetCoipPoolUsage",
                          + "ec2:DescribeVpcs",
                          + "ec2:DescribeVpcPeeringConnections",
                          + "ec2:DescribeTags",
                          + "ec2:DescribeSubnets",
                          + "ec2:DescribeSecurityGroups",
                          + "ec2:DescribeNetworkInterfaces",
                          + "ec2:DescribeInternetGateways",
                          + "ec2:DescribeInstances",
                          + "ec2:DescribeCoipPools",
                          + "ec2:DescribeAvailabilityZones",
                          + "ec2:DescribeAddresses",
                          + "ec2:DescribeAccountAttributes",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = ""
                    },
                  + {
                      + Action   = [
                          + "wafv2:GetWebACLForResource",
                          + "wafv2:GetWebACL",
                          + "wafv2:DisassociateWebACL",
                          + "wafv2:AssociateWebACL",
                          + "waf-regional:GetWebACLForResource",
                          + "waf-regional:GetWebACL",
                          + "waf-regional:DisassociateWebACL",
                          + "waf-regional:AssociateWebACL",
                          + "shield:GetSubscriptionState",
                          + "shield:DescribeProtection",
                          + "shield:DeleteProtection",
                          + "shield:CreateProtection",
                          + "iam:ListServerCertificates",
                          + "iam:GetServerCertificate",
                          + "cognito-idp:DescribeUserPoolClient",
                          + "acm:ListCertificates",
                          + "acm:DescribeCertificate",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = ""
                    },
                  + {
                      + Action   = [
                          + "ec2:RevokeSecurityGroupIngress",
                          + "ec2:CreateSecurityGroup",
                          + "ec2:AuthorizeSecurityGroupIngress",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = ""
                    },
                  + {
                      + Action    = "ec2:CreateTags"
                      + Condition = {
                          + Null         = {
                              + "aws:RequestTag/elbv2.k8s.aws/cluster" = "false"
                            }
                          + StringEquals = {
                              + "ec2:CreateAction" = "CreateSecurityGroup"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "arn:aws:ec2:*:*:security-group/*"
                      + Sid       = ""
                    },
                  + {
                      + Action    = [
                          + "ec2:DeleteTags",
                          + "ec2:CreateTags",
                        ]
                      + Condition = {
                          + Null = {
                              + "aws:RequestTag/elbv2.k8s.aws/cluster"  = "true"
                              + "aws:ResourceTag/elbv2.k8s.aws/cluster" = "false"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "arn:aws:ec2:*:*:security-group/*"
                      + Sid       = ""
                    },
                  + {
                      + Action    = [
                          + "ec2:RevokeSecurityGroupIngress",
                          + "ec2:DeleteSecurityGroup",
                          + "ec2:AuthorizeSecurityGroupIngress",
                        ]
                      + Condition = {
                          + Null = {
                              + "aws:ResourceTag/elbv2.k8s.aws/cluster" = "false"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "*"
                      + Sid       = ""
                    },
                  + {
                      + Action    = [
                          + "elasticloadbalancing:CreateTargetGroup",
                          + "elasticloadbalancing:CreateLoadBalancer",
                        ]
                      + Condition = {
                          + Null = {
                              + "aws:RequestTag/elbv2.k8s.aws/cluster" = "false"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "*"
                      + Sid       = ""
                    },
                  + {
                      + Action   = [
                          + "elasticloadbalancing:DeleteRule",
                          + "elasticloadbalancing:DeleteListener",
                          + "elasticloadbalancing:CreateRule",
                          + "elasticloadbalancing:CreateListener",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = ""
                    },
                  + {
                      + Action    = [
                          + "elasticloadbalancing:RemoveTags",
                          + "elasticloadbalancing:AddTags",
                        ]
                      + Condition = {
                          + Null = {
                              + "aws:RequestTag/elbv2.k8s.aws/cluster"  = "true"
                              + "aws:ResourceTag/elbv2.k8s.aws/cluster" = "false"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = [
                          + "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                          + "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                          + "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*",
                        ]
                      + Sid       = ""
                    },
                  + {
                      + Action   = [
                          + "elasticloadbalancing:RemoveTags",
                          + "elasticloadbalancing:AddTags",
                        ]
                      + Effect   = "Allow"
                      + Resource = [
                          + "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
                          + "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
                          + "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
                          + "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*",
                        ]
                      + Sid      = ""
                    },
                  + {
                      + Action    = [
                          + "elasticloadbalancing:SetSubnets",
                          + "elasticloadbalancing:SetSecurityGroups",
                          + "elasticloadbalancing:SetIpAddressType",
                          + "elasticloadbalancing:ModifyTargetGroupAttributes",
                          + "elasticloadbalancing:ModifyTargetGroup",
                          + "elasticloadbalancing:ModifyLoadBalancerAttributes",
                          + "elasticloadbalancing:DeleteTargetGroup",
                          + "elasticloadbalancing:DeleteLoadBalancer",
                        ]
                      + Condition = {
                          + Null = {
                              + "aws:ResourceTag/elbv2.k8s.aws/cluster" = "false"
                            }
                        }
                      + Effect    = "Allow"
                      + Resource  = "*"
                      + Sid       = ""
                    },
                  + {
                      + Action   = [
                          + "elasticloadbalancing:RegisterTargets",
                          + "elasticloadbalancing:DeregisterTargets",
                        ]
                      + Effect   = "Allow"
                      + Resource = "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
                      + Sid      = ""
                    },
                  + {
                      + Action   = [
                          + "elasticloadbalancing:SetWebAcl",
                          + "elasticloadbalancing:RemoveListenerCertificates",
                          + "elasticloadbalancing:ModifyRule",
                          + "elasticloadbalancing:ModifyListener",
                          + "elasticloadbalancing:AddListenerCertificates",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags_all    = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
    }

  # module.load_balancer_controller_irsa_role.aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = (known after apply)
      + create_date           = (known after apply)
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "central-load-balancer-controller"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.load_balancer_controller_irsa_role.aws_iam_role_policy_attachment.load_balancer_controller[0] will be created
  + resource "aws_iam_role_policy_attachment" "load_balancer_controller" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "central-load-balancer-controller"
    }

  # module.node_termination_handler_irsa_role.data.aws_iam_policy_document.this[0] will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "this" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions = [
              + "sts:AssumeRoleWithWebIdentity",
            ]
          + effect  = "Allow"

          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "sts.amazonaws.com",
                ]
              + variable = (known after apply)
            }
          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "system:serviceaccount:kube-system:aws-node",
                ]
              + variable = (known after apply)
            }

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "Federated"
            }
        }
    }

  # module.node_termination_handler_irsa_role.aws_iam_policy.node_termination_handler[0] will be created
  + resource "aws_iam_policy" "node_termination_handler" {
      + arn         = (known after apply)
      + description = "Provides permissions to handle node termination events via the Node Termination Handler"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "AmazonEKS_Node_Termination_Handler_Policy-"
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "ec2:DescribeInstances",
                          + "autoscaling:DescribeTags",
                          + "autoscaling:DescribeAutoScalingInstances",
                          + "autoscaling:CompleteLifecycleAction",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = ""
                    },
                  + {
                      + Action   = [
                          + "sqs:ReceiveMessage",
                          + "sqs:DeleteMessage",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags_all    = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
    }

  # module.node_termination_handler_irsa_role.aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = (known after apply)
      + create_date           = (known after apply)
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "central-node-termination-handler"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.node_termination_handler_irsa_role.aws_iam_role_policy_attachment.node_termination_handler[0] will be created
  + resource "aws_iam_role_policy_attachment" "node_termination_handler" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "central-node-termination-handler"
    }

  # module.vpc_cni_irsa.data.aws_iam_policy_document.this[0] will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "this" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions = [
              + "sts:AssumeRoleWithWebIdentity",
            ]
          + effect  = "Allow"

          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "sts.amazonaws.com",
                ]
              + variable = (known after apply)
            }
          + condition {
              + test     = "StringEquals"
              + values   = [
                  + "system:serviceaccount:kube-system:aws-node",
                ]
              + variable = (known after apply)
            }

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "Federated"
            }
        }
    }

  # module.vpc_cni_irsa.aws_iam_policy.vpc_cni[0] will be created
  + resource "aws_iam_policy" "vpc_cni" {
      + arn         = (known after apply)
      + description = "Provides the Amazon VPC CNI Plugin (amazon-vpc-cni-k8s) the permissions it requires to modify the IPv4/IPv6 address configuration on your EKS worker nodes"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "AmazonEKS_CNI_Policy-"
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "ec2:DescribeTags",
                          + "ec2:DescribeNetworkInterfaces",
                          + "ec2:DescribeInstances",
                          + "ec2:DescribeInstanceTypes",
                          + "ec2:AssignIpv6Addresses",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = "IPV6"
                    },
                  + {
                      + Action   = "ec2:CreateTags"
                      + Effect   = "Allow"
                      + Resource = "arn:aws:ec2:*:*:network-interface/*"
                      + Sid      = "CreateTags"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags_all    = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
    }

  # module.vpc_cni_irsa.aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = (known after apply)
      + create_date           = (known after apply)
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "central-vpc-cni"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/eks"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.vpc_cni_irsa.aws_iam_role_policy_attachment.vpc_cni[0] will be created
  + resource "aws_iam_role_policy_attachment" "vpc_cni" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "central-vpc-cni"
    }

  # module.eks.module.eks_managed_node_group["karpenter"].aws_eks_node_group.this[0] will be created
  + resource "aws_eks_node_group" "this" {
      + ami_type               = (known after apply)
      + arn                    = (known after apply)
      + capacity_type          = (known after apply)
      + cluster_name           = "central"
      + disk_size              = (known after apply)
      + id                     = (known after apply)
      + instance_types         = [
          + "t3.medium",
        ]
      + node_group_name        = (known after apply)
      + node_group_name_prefix = "karpenter-"
      + node_role_arn          = (known after apply)
      + release_version        = (known after apply)
      + resources              = (known after apply)
      + status                 = (known after apply)
      + subnet_ids             = [
          + "subnet-044e58d35125680a8",
          + "subnet-0d6c4fdda4b653528",
          + "subnet-0ea7a702a7c6eba80",
        ]
      + tags                   = {
          + "Name"                   = "karpenter"
          + "karpenter.sh/discovery" = "central"
        }
      + tags_all               = {
          + "ManagedByTerraform"     = "true"
          + "Name"                   = "karpenter"
          + "Owner"                  = "declarative-eks-tutorial"
          + "Stage"                  = "central"
          + "Workspace"              = "terraform/central/eks"
          + "karpenter.sh/discovery" = "central"
        }
      + version                = "1.23"

      + launch_template {
          + id      = (known after apply)
          + name    = (known after apply)
          + version = (known after apply)
        }

      + scaling_config {
          + desired_size = 1
          + max_size     = 2
          + min_size     = 1
        }

      + timeouts {}

      + update_config {
          + max_unavailable            = (known after apply)
          + max_unavailable_percentage = (known after apply)
        }
    }

  # module.eks.module.eks_managed_node_group["karpenter"].aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ec2.amazonaws.com"
                        }
                      + Sid       = "EKSNodeAssumeRole"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + description           = "EKS managed node group IAM role"
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = (known after apply)
      + name_prefix           = "karpenter-eks-node-group-"
      + path                  = "/"
      + tags                  = {
          + "karpenter.sh/discovery" = "central"
        }
      + tags_all              = {
          + "ManagedByTerraform"     = "true"
          + "Owner"                  = "declarative-eks-tutorial"
          + "Stage"                  = "central"
          + "Workspace"              = "terraform/central/eks"
          + "karpenter.sh/discovery" = "central"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.eks.module.eks_managed_node_group["karpenter"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
      + role       = (known after apply)
    }

  # module.eks.module.eks_managed_node_group["karpenter"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
      + role       = (known after apply)
    }

  # module.eks.module.eks_managed_node_group["karpenter"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
      + role       = (known after apply)
    }

  # module.eks.module.eks_managed_node_group["karpenter"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      + role       = (known after apply)
    }

  # module.eks.module.eks_managed_node_group["karpenter"].aws_launch_template.this[0] will be created
  + resource "aws_launch_template" "this" {
      + arn                    = (known after apply)
      + default_version        = (known after apply)
      + description            = "Custom launch template for karpenter EKS managed node group"
      + id                     = (known after apply)
      + latest_version         = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "karpenter-"
      + tags                   = {
          + "karpenter.sh/discovery" = "central"
        }
      + tags_all               = {
          + "ManagedByTerraform"     = "true"
          + "Owner"                  = "declarative-eks-tutorial"
          + "Stage"                  = "central"
          + "Workspace"              = "terraform/central/eks"
          + "karpenter.sh/discovery" = "central"
        }
      + update_default_version = true
      + vpc_security_group_ids = (known after apply)

      + metadata_options {
          + http_endpoint               = "enabled"
          + http_protocol_ipv6          = "disabled"
          + http_put_response_hop_limit = 2
          + http_tokens                 = "required"
          + instance_metadata_tags      = "disabled"
        }

      + monitoring {
          + enabled = true
        }

      + tag_specifications {
          + resource_type = "instance"
          + tags          = {
              + "Name"                   = "karpenter"
              + "karpenter.sh/discovery" = "central"
            }
        }
      + tag_specifications {
          + resource_type = "network-interface"
          + tags          = {
              + "Name"                   = "karpenter"
              + "karpenter.sh/discovery" = "central"
            }
        }
      + tag_specifications {
          + resource_type = "volume"
          + tags          = {
              + "Name"                   = "karpenter"
              + "karpenter.sh/discovery" = "central"
            }
        }
    }

  # module.eks.module.eks_managed_node_group["karpenter"].aws_security_group.this[0] will be created
  + resource "aws_security_group" "this" {
      + arn                    = (known after apply)
      + description            = "EKS managed node group security group"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "karpenter-eks-node-group-"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name"                   = "karpenter-eks-node-group"
          + "karpenter.sh/discovery" = "central"
        }
      + tags_all               = {
          + "ManagedByTerraform"     = "true"
          + "Name"                   = "karpenter-eks-node-group"
          + "Owner"                  = "declarative-eks-tutorial"
          + "Stage"                  = "central"
          + "Workspace"              = "terraform/central/eks"
          + "karpenter.sh/discovery" = "central"
        }
      + vpc_id                 = "vpc-020aaebb726af41a4"
    }

Plan: 65 to add, 0 to change, 0 to destroy.

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

module.external_dns_irsa_role.aws_iam_policy.external_dns[0]: Creating...
module.vpc_cni_irsa.aws_iam_policy.vpc_cni[0]: Creating...
aws_iam_policy.app_atlantis_s3: Creating...
aws_iam_policy.github_actions_ecr: Creating...
module.ebs_csi_driver_irsa_role.aws_iam_policy.ebs_csi[0]: Creating...
module.eks.aws_cloudwatch_log_group.this[0]: Creating...
module.eks.module.eks_managed_node_group["karpenter"].aws_security_group.this[0]: Creating...
module.eks.aws_security_group.cluster[0]: Creating...
module.eks.aws_security_group.node[0]: Creating...
module.eks.module.eks_managed_node_group["karpenter"].aws_iam_role.this[0]: Creating...
module.eks.aws_cloudwatch_log_group.this[0]: Creation complete after 0s [id=/aws/eks/central/cluster]
module.load_balancer_controller_irsa_role.aws_iam_policy.load_balancer_controller[0]: Creating...
module.eks.module.eks_managed_node_group["karpenter"].aws_security_group.this[0]: Creation complete after 1s [id=sg-089b4f71387a5b8e9]
module.eks.aws_security_group.node[0]: Creation complete after 1s [id=sg-028fbca8703c6ee1f]
module.external_secrets_irsa_role.aws_iam_policy.external_secrets[0]: Creating...
module.node_termination_handler_irsa_role.aws_iam_policy.node_termination_handler[0]: Creating...
module.eks.aws_security_group.cluster[0]: Creation complete after 1s [id=sg-03340da8a445d4175]
module.eks.aws_iam_role.this[0]: Creating...
aws_iam_policy.app_atlantis_s3: Creation complete after 1s [id=arn:aws:iam::765355018960:policy/central-atlantis20220926120213044800000004]
aws_security_group_rule.workers_access_internet_egress: Creating...
module.external_dns_irsa_role.aws_iam_policy.external_dns[0]: Creation complete after 1s [id=arn:aws:iam::765355018960:policy/AmazonEKS_External_DNS_Policy-20220926120213043000000002]
aws_security_group_rule.workers_access_self_ingress: Creating...
module.vpc_cni_irsa.aws_iam_policy.vpc_cni[0]: Creation complete after 2s [id=arn:aws:iam::765355018960:policy/AmazonEKS_CNI_Policy-20220926120213046000000007]
module.eks.aws_security_group_rule.cluster["egress_nodes_kubelet"]: Creating...
module.ebs_csi_driver_irsa_role.aws_iam_policy.ebs_csi[0]: Creation complete after 2s [id=arn:aws:iam::765355018960:policy/AmazonEKS_EBS_CSI_Policy-20220926120213047300000009]
module.eks.aws_security_group_rule.cluster["egress_nodes_443"]: Creating...
aws_iam_policy.github_actions_ecr: Creation complete after 2s [id=arn:aws:iam::765355018960:policy/central-gha-runner20220926120213044700000003]
module.eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Creating...
aws_security_group_rule.workers_access_internet_egress: Creation complete after 1s [id=sgrule-2807054510]
module.eks.aws_security_group_rule.node["ingress_karpenter_webhook_tcp"]: Creating...
module.eks.aws_security_group_rule.cluster["egress_nodes_kubelet"]: Creation complete after 0s [id=sgrule-3558683558]
module.eks.aws_security_group_rule.node["egress_self_coredns_udp"]: Creating...
module.load_balancer_controller_irsa_role.aws_iam_policy.load_balancer_controller[0]: Creation complete after 2s [id=arn:aws:iam::765355018960:policy/AmazonEKS_AWS_Load_Balancer_Controller-2022092612021319650000000a]
module.eks.aws_security_group_rule.node["egress_self_coredns_tcp"]: Creating...
module.external_secrets_irsa_role.aws_iam_policy.external_secrets[0]: Creation complete after 1s [id=arn:aws:iam::765355018960:policy/AmazonEKS_External_Secrets_Policy-2022092612021435620000000b]
module.eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Creating...
module.node_termination_handler_irsa_role.aws_iam_policy.node_termination_handler[0]: Creation complete after 1s [id=arn:aws:iam::765355018960:policy/AmazonEKS_Node_Termination_Handler_Policy-2022092612021435770000000c]
module.eks.aws_security_group_rule.node["egress_cluster_443"]: Creating...
aws_security_group_rule.workers_access_self_ingress: Creation complete after 1s [id=sgrule-1687311081]
module.eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Creating...
module.eks.aws_security_group_rule.cluster["egress_nodes_443"]: Creation complete after 0s [id=sgrule-3074901958]
module.eks.aws_security_group_rule.node["egress_ntp_udp"]: Creating...
module.eks.module.eks_managed_node_group["karpenter"].aws_iam_role.this[0]: Creation complete after 2s [id=karpenter-eks-node-group-20220926120213046700000008]
module.eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Creating...
module.eks.aws_security_group_rule.node["ingress_karpenter_webhook_tcp"]: Creation complete after 1s [id=sgrule-1131619432]
module.eks.aws_security_group_rule.node["egress_https"]: Creating...
module.eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Creation complete after 1s [id=sgrule-3842453839]
module.eks.aws_security_group_rule.node["egress_ntp_tcp"]: Creating...
module.eks.aws_security_group_rule.node["egress_self_coredns_udp"]: Creation complete after 1s [id=sgrule-1128953061]
module.eks.aws_security_group_rule.node["ingress_cluster_443"]: Creating...
module.eks.aws_iam_role.this[0]: Creation complete after 2s [id=central-cluster-2022092612021445010000000d]
module.eks.module.eks_managed_node_group["karpenter"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Creating...
module.eks.aws_security_group_rule.node["egress_self_coredns_tcp"]: Creation complete after 2s [id=sgrule-3442341507]
module.eks.module.eks_managed_node_group["karpenter"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Creating...
module.eks.module.eks_managed_node_group["karpenter"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Creation complete after 1s [id=karpenter-eks-node-group-20220926120213046700000008-2022092612021662180000000e]
module.eks.module.eks_managed_node_group["karpenter"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]: Creating...
module.eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Creation complete after 2s [id=sgrule-1200901390]
module.eks.module.eks_managed_node_group["karpenter"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Creating...
module.eks.module.eks_managed_node_group["karpenter"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Creation complete after 0s [id=karpenter-eks-node-group-20220926120213046700000008-2022092612021698020000000f]
module.eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"]: Creating...
module.eks.module.eks_managed_node_group["karpenter"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]: Creation complete after 0s [id=karpenter-eks-node-group-20220926120213046700000008-20220926120217109700000010]
module.eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]: Creating...
module.eks.aws_security_group_rule.node["egress_cluster_443"]: Creation complete after 3s [id=sgrule-2751249537]
module.eks.module.eks_managed_node_group["karpenter"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Creation complete after 1s [id=karpenter-eks-node-group-20220926120213046700000008-20220926120217363600000011]
module.eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"]: Creation complete after 1s [id=central-cluster-2022092612021445010000000d-20220926120217481200000012]
module.eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]: Creation complete after 1s [id=central-cluster-2022092612021445010000000d-20220926120217590400000013]
module.eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Creation complete after 3s [id=sgrule-2148265637]
module.eks.aws_security_group_rule.node["egress_ntp_udp"]: Creation complete after 3s [id=sgrule-2808439282]
module.eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Creation complete after 4s [id=sgrule-3821792993]
module.eks.aws_security_group_rule.node["egress_https"]: Creation complete after 3s [id=sgrule-103119329]
module.eks.aws_security_group_rule.node["egress_ntp_tcp"]: Creation complete after 4s [id=sgrule-3657123071]
module.eks.aws_security_group_rule.node["ingress_cluster_443"]: Creation complete after 4s [id=sgrule-1939968068]
module.eks.aws_eks_cluster.this[0]: Creating...
module.eks.aws_eks_cluster.this[0]: Still creating... [10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [9m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [9m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [9m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [9m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [9m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [9m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [10m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [10m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [10m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Creation complete after 10m24s [id=central]
data.aws_eks_cluster_auth.eks_auth: Reading...
module.eks.data.tls_certificate.this[0]: Reading...
module.iam_assumable_role_atlantis_s3.data.aws_iam_policy_document.assume_role_with_oidc[0]: Reading...
module.iam_assumable_role_github_actions_ecr.data.aws_iam_policy_document.assume_role_with_oidc[0]: Reading...
data.aws_eks_cluster_auth.eks_auth: Read complete after 0s [id=central]
module.iam_assumable_role_atlantis_s3.data.aws_iam_policy_document.assume_role_with_oidc[0]: Read complete after 0s [id=32419666]
aws_security_group_rule.worker_access_from_cluster: Creating...
module.iam_assumable_role_github_actions_ecr.data.aws_iam_policy_document.assume_role_with_oidc[0]: Read complete after 0s [id=32419666]
module.eks.data.tls_certificate.this[0]: Read complete after 0s [id=e60b99f22d560af59fd9077af16f33b74a2d6b2e]
module.iam_assumable_role_atlantis_s3.aws_iam_role.this[0]: Creating...
module.eks.aws_iam_openid_connect_provider.oidc_provider[0]: Creating...
module.iam_assumable_role_github_actions_ecr.aws_iam_role.this[0]: Creating...
module.eks.module.eks_managed_node_group["karpenter"].aws_launch_template.this[0]: Creating...
module.eks.module.eks_managed_node_group["karpenter"].aws_launch_template.this[0]: Creation complete after 0s [id=lt-0d5bf1fc4a19a1e26]
module.eks.module.eks_managed_node_group["karpenter"].aws_eks_node_group.this[0]: Creating...
aws_security_group_rule.worker_access_from_cluster: Creation complete after 0s [id=sgrule-3492227905]
module.eks.aws_iam_openid_connect_provider.oidc_provider[0]: Creation complete after 1s [id=arn:aws:iam::765355018960:oidc-provider/oidc.eks.ap-northeast-2.amazonaws.com/id/299AEF486E4C5761F3886EA00B13C2A0]
module.external_secrets_irsa_role.data.aws_iam_policy_document.this[0]: Reading...
module.node_termination_handler_irsa_role.data.aws_iam_policy_document.this[0]: Reading...
module.external_dns_irsa_role.data.aws_iam_policy_document.this[0]: Reading...
module.vpc_cni_irsa.data.aws_iam_policy_document.this[0]: Reading...
module.load_balancer_controller_irsa_role.data.aws_iam_policy_document.this[0]: Reading...
module.karpenter_irsa.data.aws_iam_policy_document.this[0]: Reading...
module.ebs_csi_driver_irsa_role.data.aws_iam_policy_document.this[0]: Reading...
module.load_balancer_controller_irsa_role.data.aws_iam_policy_document.this[0]: Read complete after 0s [id=2146090516]
module.external_dns_irsa_role.data.aws_iam_policy_document.this[0]: Read complete after 0s [id=1429386888]
module.external_secrets_irsa_role.data.aws_iam_policy_document.this[0]: Read complete after 0s [id=149974435]
module.vpc_cni_irsa.data.aws_iam_policy_document.this[0]: Read complete after 0s [id=1937677545]
module.karpenter_irsa.data.aws_iam_policy_document.this[0]: Read complete after 0s [id=1573079704]
module.node_termination_handler_irsa_role.data.aws_iam_policy_document.this[0]: Read complete after 0s [id=1937677545]
module.ebs_csi_driver_irsa_role.data.aws_iam_policy_document.this[0]: Read complete after 0s [id=4281661667]
module.external_dns_irsa_role.aws_iam_role.this[0]: Creating...
module.load_balancer_controller_irsa_role.aws_iam_role.this[0]: Creating...
module.external_secrets_irsa_role.aws_iam_role.this[0]: Creating...
module.karpenter_irsa.aws_iam_role.this[0]: Creating...
module.vpc_cni_irsa.aws_iam_role.this[0]: Creating...
module.ebs_csi_driver_irsa_role.aws_iam_role.this[0]: Creating...
module.node_termination_handler_irsa_role.aws_iam_role.this[0]: Creating...
module.iam_assumable_role_atlantis_s3.aws_iam_role.this[0]: Creation complete after 2s [id=central-atlantis]
module.iam_assumable_role_github_actions_ecr.aws_iam_role.this[0]: Creation complete after 2s [id=central-gha-runner]
module.iam_assumable_role_atlantis_s3.aws_iam_role_policy_attachment.custom[0]: Creating...
module.iam_assumable_role_github_actions_ecr.aws_iam_role_policy_attachment.custom[0]: Creating...
module.iam_assumable_role_atlantis_s3.aws_iam_role_policy_attachment.custom[0]: Creation complete after 1s [id=central-atlantis-20220926121246539500000018]
module.iam_assumable_role_github_actions_ecr.aws_iam_role_policy_attachment.custom[0]: Creation complete after 1s [id=central-gha-runner-20220926121246543300000019]
module.load_balancer_controller_irsa_role.aws_iam_role.this[0]: Creation complete after 2s [id=central-load-balancer-controller]
module.load_balancer_controller_irsa_role.aws_iam_role_policy_attachment.load_balancer_controller[0]: Creating...
module.external_dns_irsa_role.aws_iam_role.this[0]: Creation complete after 2s [id=central-external-dns]
module.external_secrets_irsa_role.aws_iam_role.this[0]: Creation complete after 2s [id=central-external-secrets]
module.external_dns_irsa_role.aws_iam_role_policy_attachment.external_dns[0]: Creating...
module.external_secrets_irsa_role.aws_iam_role_policy_attachment.external_secrets[0]: Creating...
module.karpenter_irsa.aws_iam_role.this[0]: Creation complete after 2s [id=central-karpenter-controller]
module.vpc_cni_irsa.aws_iam_role.this[0]: Creation complete after 2s [id=central-vpc-cni]
module.vpc_cni_irsa.aws_iam_role_policy_attachment.vpc_cni[0]: Creating...
module.ebs_csi_driver_irsa_role.aws_iam_role.this[0]: Creation complete after 2s [id=central-ebs-csi-driver]
module.ebs_csi_driver_irsa_role.aws_iam_role_policy_attachment.ebs_csi[0]: Creating...
module.node_termination_handler_irsa_role.aws_iam_role.this[0]: Creation complete after 2s [id=central-node-termination-handler]
module.node_termination_handler_irsa_role.aws_iam_role_policy_attachment.node_termination_handler[0]: Creating...
module.load_balancer_controller_irsa_role.aws_iam_role_policy_attachment.load_balancer_controller[0]: Creation complete after 0s [id=central-load-balancer-controller-2022092612124715240000001a]
module.external_dns_irsa_role.aws_iam_role_policy_attachment.external_dns[0]: Creation complete after 0s [id=central-external-dns-2022092612124716870000001b]
module.external_secrets_irsa_role.aws_iam_role_policy_attachment.external_secrets[0]: Creation complete after 0s [id=central-external-secrets-2022092612124718300000001c]
module.vpc_cni_irsa.aws_iam_role_policy_attachment.vpc_cni[0]: Creation complete after 0s [id=central-vpc-cni-2022092612124722850000001d]
module.ebs_csi_driver_irsa_role.aws_iam_role_policy_attachment.ebs_csi[0]: Creation complete after 1s [id=central-ebs-csi-driver-2022092612124740370000001e]
module.node_termination_handler_irsa_role.aws_iam_role_policy_attachment.node_termination_handler[0]: Creation complete after 1s [id=central-node-termination-handler-2022092612124743060000001f]
module.eks.module.eks_managed_node_group["karpenter"].aws_eks_node_group.this[0]: Still creating... [10s elapsed]
module.eks.module.eks_managed_node_group["karpenter"].aws_eks_node_group.this[0]: Still creating... [20s elapsed]
module.eks.module.eks_managed_node_group["karpenter"].aws_eks_node_group.this[0]: Still creating... [30s elapsed]
module.eks.module.eks_managed_node_group["karpenter"].aws_eks_node_group.this[0]: Still creating... [40s elapsed]
module.eks.module.eks_managed_node_group["karpenter"].aws_eks_node_group.this[0]: Still creating... [50s elapsed]
module.eks.module.eks_managed_node_group["karpenter"].aws_eks_node_group.this[0]: Still creating... [1m0s elapsed]
module.eks.module.eks_managed_node_group["karpenter"].aws_eks_node_group.this[0]: Still creating... [1m10s elapsed]
module.eks.module.eks_managed_node_group["karpenter"].aws_eks_node_group.this[0]: Still creating... [1m20s elapsed]
module.eks.module.eks_managed_node_group["karpenter"].aws_eks_node_group.this[0]: Still creating... [1m30s elapsed]
module.eks.module.eks_managed_node_group["karpenter"].aws_eks_node_group.this[0]: Still creating... [1m40s elapsed]
module.eks.module.eks_managed_node_group["karpenter"].aws_eks_node_group.this[0]: Still creating... [1m50s elapsed]
module.eks.module.eks_managed_node_group["karpenter"].aws_eks_node_group.this[0]: Creation complete after 1m59s [id=central:karpenter-20220926121244109600000016]
module.eks.aws_eks_addon.this["vpc-cni"]: Creating...
module.eks.aws_eks_addon.this["coredns"]: Creating...
module.eks.aws_eks_addon.this["kube-proxy"]: Creating...
aws_iam_instance_profile.karpenter: Creating...
module.karpenter_irsa.data.aws_iam_policy_document.karpenter_controller[0]: Reading...
module.karpenter_irsa.data.aws_iam_policy_document.karpenter_controller[0]: Read complete after 0s [id=1628787099]
module.karpenter_irsa.aws_iam_policy.karpenter_controller[0]: Creating...
module.eks.kubernetes_config_map_v1_data.aws_auth[0]: Creating...
module.eks.kubernetes_config_map_v1_data.aws_auth[0]: Creation complete after 1s [id=kube-system/aws-auth]
module.karpenter_irsa.aws_iam_policy.karpenter_controller[0]: Creation complete after 2s [id=arn:aws:iam::765355018960:policy/AmazonEKS_Karpenter_Controller_Policy-20220926121443427700000023]
module.karpenter_irsa.aws_iam_role_policy_attachment.karpenter_controller[0]: Creating...
aws_iam_instance_profile.karpenter: Creation complete after 2s [id=KarpenterNodeInstanceProfile-central]
module.karpenter_irsa.aws_iam_role_policy_attachment.karpenter_controller[0]: Creation complete after 1s [id=central-karpenter-controller-20220926121445454500000024]
module.eks.aws_eks_addon.this["kube-proxy"]: Creation complete after 3s [id=central:kube-proxy]
module.eks.aws_eks_addon.this["coredns"]: Creation complete after 8s [id=central:coredns]
module.eks.aws_eks_addon.this["vpc-cni"]: Still creating... [10s elapsed]
module.eks.aws_eks_addon.this["vpc-cni"]: Still creating... [20s elapsed]
module.eks.aws_eks_addon.this["vpc-cni"]: Still creating... [30s elapsed]
module.eks.aws_eks_addon.this["vpc-cni"]: Creation complete after 35s [id=central:vpc-cni]

Apply complete! Resources: 65 added, 0 changed, 0 destroyed.
```