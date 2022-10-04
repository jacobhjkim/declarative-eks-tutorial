```shell
$ terraform apply
data.aws_secretsmanager_secret.central_provisioner: Reading...
data.aws_secretsmanager_secret.central_provisioner: Read complete after 1s [id=arn:aws:secretsmanager:ap-northeast-2:765355018960:secret:central-provisioner-credentials-fqF9g7]
data.aws_secretsmanager_secret_version.central_provisioner: Reading...
data.aws_secretsmanager_secret_version.central_provisioner: Read complete after 0s [id=arn:aws:secretsmanager:ap-northeast-2:765355018960:secret:central-provisioner-credentials-fqF9g7|AWSCURRENT]
module.iam_assumable_role_vault_cluster.data.aws_caller_identity.current: Reading...
module.iam_assumable_role_vault_cluster.data.aws_partition.current: Reading...
data.aws_eks_cluster.cluster: Reading...
module.iam_assumable_role_vault_cluster.data.aws_partition.current: Read complete after 0s [id=aws]
data.aws_iam_policy_document.app_vault_cluster: Reading...
data.aws_iam_policy_document.app_vault_cluster: Read complete after 0s [id=3971309099]
module.iam_assumable_role_vault_cluster.data.aws_caller_identity.current: Read complete after 0s [id=765355018960]
data.aws_eks_cluster.cluster: Read complete after 0s [id=central]
module.iam_assumable_role_vault_cluster.data.aws_iam_policy_document.assume_role_with_oidc[0]: Reading...
module.iam_assumable_role_vault_cluster.data.aws_iam_policy_document.assume_role_with_oidc[0]: Read complete after 0s [id=32419666]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_dynamodb_table.vault_backend_prod will be created
  + resource "aws_dynamodb_table" "vault_backend_prod" {
      + arn              = (known after apply)
      + billing_mode     = "PAY_PER_REQUEST"
      + hash_key         = "Path"
      + id               = (known after apply)
      + name             = "vault-backend"
      + range_key        = "Key"
      + read_capacity    = (known after apply)
      + stream_arn       = (known after apply)
      + stream_label     = (known after apply)
      + stream_view_type = (known after apply)
      + tags_all         = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/vault-backend"
        }
      + write_capacity   = (known after apply)

      + attribute {
          + name = "Key"
          + type = "S"
        }
      + attribute {
          + name = "Path"
          + type = "S"
        }

      + point_in_time_recovery {
          + enabled = (known after apply)
        }

      + server_side_encryption {
          + enabled     = (known after apply)
          + kms_key_arn = (known after apply)
        }

      + ttl {
          + attribute_name = (known after apply)
          + enabled        = (known after apply)
        }
    }

  # aws_iam_policy.app_vault_cluster will be created
  + resource "aws_iam_policy" "app_vault_cluster" {
      + arn         = (known after apply)
      + description = "Vault cluster pod policy for cluster central"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "central-vault-cluster"
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "kms:*",
                          + "iam:GetUser",
                          + "dynamodb:UpdateItem",
                          + "dynamodb:Scan",
                          + "dynamodb:Query",
                          + "dynamodb:PutItem",
                          + "dynamodb:ListTagsOfResource",
                          + "dynamodb:ListTables",
                          + "dynamodb:GetRecords",
                          + "dynamodb:GetItem",
                          + "dynamodb:DescribeTimeToLive",
                          + "dynamodb:DescribeTable",
                          + "dynamodb:DescribeReservedCapacityOfferings",
                          + "dynamodb:DescribeReservedCapacity",
                          + "dynamodb:DescribeLimits",
                          + "dynamodb:DeleteItem",
                          + "dynamodb:CreateTable",
                          + "dynamodb:BatchWriteItem",
                          + "dynamodb:BatchGetItem",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = "VaultClusterPod"
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
          + "Workspace"          = "terraform/central/vault-backend"
        }
    }

  # aws_kms_alias.vault_unseal_alias will be created
  + resource "aws_kms_alias" "vault_unseal_alias" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + name           = "alias/vault-auto-unseal"
      + name_prefix    = (known after apply)
      + target_key_arn = (known after apply)
      + target_key_id  = (known after apply)
    }

  # aws_kms_key.vault_unseal will be created
  + resource "aws_kms_key" "vault_unseal" {
      + arn                                = (known after apply)
      + bypass_policy_lockout_safety_check = false
      + customer_master_key_spec           = "SYMMETRIC_DEFAULT"
      + deletion_window_in_days            = 30
      + description                        = "Vault Auto Unseal Encrypt Key"
      + enable_key_rotation                = false
      + id                                 = (known after apply)
      + is_enabled                         = true
      + key_id                             = (known after apply)
      + key_usage                          = "ENCRYPT_DECRYPT"
      + multi_region                       = (known after apply)
      + policy                             = (known after apply)
      + tags_all                           = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/vault-backend"
        }
    }

  # module.iam_assumable_role_vault_cluster.aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRoleWithWebIdentity"
                      + Effect    = "Allow"
                      + Principal = {
                          + Federated = "arn:aws:iam::765355018960:oidc-provider/oidc.eks.ap-northeast-2.amazonaws.com/id/299AEF486E4C5761F3886EA00B13C2A0"
                        }
                      + Sid       = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "central-vault-cluster"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/vault-backend"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.iam_assumable_role_vault_cluster.aws_iam_role_policy_attachment.custom[0] will be created
  + resource "aws_iam_role_policy_attachment" "custom" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "central-vault-cluster"
    }

Plan: 6 to add, 0 to change, 0 to destroy.

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

aws_iam_policy.app_vault_cluster: Creating...
aws_kms_key.vault_unseal: Creating...
module.iam_assumable_role_vault_cluster.aws_iam_role.this[0]: Creating...
aws_dynamodb_table.vault_backend_prod: Creating...
aws_iam_policy.app_vault_cluster: Creation complete after 1s [id=arn:aws:iam::765355018960:policy/central-vault-cluster20220926122639535700000001]
module.iam_assumable_role_vault_cluster.aws_iam_role.this[0]: Creation complete after 2s [id=central-vault-cluster]
module.iam_assumable_role_vault_cluster.aws_iam_role_policy_attachment.custom[0]: Creating...
module.iam_assumable_role_vault_cluster.aws_iam_role_policy_attachment.custom[0]: Creation complete after 0s [id=central-vault-cluster-20220926122641962100000002]
aws_kms_key.vault_unseal: Creation complete after 4s [id=753188e2-8c73-458a-8ed9-c13c8298d75c]
aws_kms_alias.vault_unseal_alias: Creating...
aws_kms_alias.vault_unseal_alias: Creation complete after 0s [id=alias/vault-auto-unseal]
aws_dynamodb_table.vault_backend_prod: Creation complete after 6s [id=vault-backend]

Apply complete! Resources: 6 added, 0 changed, 0 destroyed.
```