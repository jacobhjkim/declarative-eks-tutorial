```shell
$ terraform init

Initializing the backend...

Initializing provider plugins...
- terraform.io/builtin/terraform is built in to Terraform
- Reusing previous version of hashicorp/aws from the dependency lock file
- Using previously-installed hashicorp/aws v4.31.0

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
```

```shell
$ terraform apply

data.terraform_remote_state.terraform_backend: Reading...
data.terraform_remote_state.terraform_backend: Read complete after 0s
data.aws_iam_policy.aws_managed_admin_policy: Reading...
data.aws_iam_policy_document.central_user_policy: Reading...
data.aws_iam_policy_document.central_user_policy: Read complete after 0s [id=2781255193]
data.aws_iam_policy.aws_managed_admin_policy: Read complete after 6s [id=arn:aws:iam::aws:policy/AdministratorAccess]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create
 <= read (data resources)

Terraform will perform the following actions:

  # data.aws_iam_policy_document.central_role_trust_policy will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "central_role_trust_policy" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions = [
              + "sts:AssumeRole",
            ]
          + effect  = "Allow"

          + principals {
              + identifiers = [
                  + "arn:aws:iam::765355018960:user/hyunjun-kim",
                  + (known after apply),
                ]
              + type        = "AWS"
            }
        }
    }

  # aws_iam_access_key.central will be created
  + resource "aws_iam_access_key" "central" {
      + create_date                    = (known after apply)
      + encrypted_secret               = (known after apply)
      + encrypted_ses_smtp_password_v4 = (known after apply)
      + id                             = (known after apply)
      + key_fingerprint                = (known after apply)
      + secret                         = (sensitive value)
      + ses_smtp_password_v4           = (sensitive value)
      + status                         = "Active"
      + user                           = "central-provisioner"
    }

  # aws_iam_role.central_role will be created
  + resource "aws_iam_role" "central_role" {
      + arn                   = (known after apply)
      + assume_role_policy    = (known after apply)
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "central-provisioner"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/iam"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # aws_iam_role_policy_attachment.central will be created
  + resource "aws_iam_role_policy_attachment" "central" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
      + role       = "central-provisioner"
    }

  # aws_iam_user.central_user will be created
  + resource "aws_iam_user" "central_user" {
      + arn           = (known after apply)
      + force_destroy = false
      + id            = (known after apply)
      + name          = "central-provisioner"
      + path          = "/"
      + tags_all      = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/iam"
        }
      + unique_id     = (known after apply)
    }

  # aws_iam_user_policy.central will be created
  + resource "aws_iam_user_policy" "central" {
      + id     = (known after apply)
      + name   = "central-provisioner-policy"
      + policy = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "s3:ListBucket",
                          + "s3:GetBucketVersioning",
                        ]
                      + Effect   = "Allow"
                      + Resource = "arn:aws:s3:::declarative-eks-tutorial-tfstates"
                      + Sid      = ""
                    },
                  + {
                      + Action   = [
                          + "s3:PutObject",
                          + "s3:GetObject",
                        ]
                      + Effect   = "Allow"
                      + Resource = "arn:aws:s3:::declarative-eks-tutorial-tfstates/*"
                      + Sid      = ""
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
      + user   = "central-provisioner"
    }

  # aws_secretsmanager_secret.central_secret will be created
  + resource "aws_secretsmanager_secret" "central_secret" {
      + arn                            = (known after apply)
      + force_overwrite_replica_secret = false
      + id                             = (known after apply)
      + name                           = "central-provisioner-credentials"
      + name_prefix                    = (known after apply)
      + policy                         = (known after apply)
      + recovery_window_in_days        = 30
      + rotation_enabled               = (known after apply)
      + rotation_lambda_arn            = (known after apply)
      + tags_all                       = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/iam"
        }

      + replica {
          + kms_key_id         = (known after apply)
          + last_accessed_date = (known after apply)
          + region             = (known after apply)
          + status             = (known after apply)
          + status_message     = (known after apply)
        }

      + rotation_rules {
          + automatically_after_days = (known after apply)
        }
    }

  # aws_secretsmanager_secret_version.central_secret will be created
  + resource "aws_secretsmanager_secret_version" "central_secret" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + secret_id      = (known after apply)
      + secret_string  = (sensitive value)
      + version_id     = (known after apply)
      + version_stages = (known after apply)
    }

Plan: 7 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + provisioner_iam_role_arn = (known after apply)

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

aws_iam_user.central_user: Creating...
aws_secretsmanager_secret.central_secret: Creating...
aws_iam_user.central_user: Creation complete after 2s [id=central-provisioner]
data.aws_iam_policy_document.central_role_trust_policy: Reading...
aws_iam_access_key.central: Creating...
aws_iam_user_policy.central: Creating...
data.aws_iam_policy_document.central_role_trust_policy: Read complete after 0s [id=3806599493]
aws_iam_role.central_role: Creating...
aws_iam_access_key.central: Creation complete after 0s [id=AKIA3EMVWZLIHCNSI3GC]
aws_iam_user_policy.central: Creation complete after 0s [id=central-provisioner:central-provisioner-policy]
aws_secretsmanager_secret.central_secret: Still creating... [10s elapsed]
aws_iam_role.central_role: Still creating... [10s elapsed]
aws_iam_role.central_role: Creation complete after 12s [id=central-provisioner]
aws_iam_role_policy_attachment.central: Creating...
aws_iam_role_policy_attachment.central: Creation complete after 0s [id=central-provisioner-20220922142349805900000001]
aws_secretsmanager_secret.central_secret: Still creating... [20s elapsed]
aws_secretsmanager_secret.central_secret: Still creating... [30s elapsed]
aws_secretsmanager_secret.central_secret: Still creating... [40s elapsed]
aws_secretsmanager_secret.central_secret: Still creating... [50s elapsed]
aws_secretsmanager_secret.central_secret: Still creating... [1m0s elapsed]
aws_secretsmanager_secret.central_secret: Still creating... [1m10s elapsed]
aws_secretsmanager_secret.central_secret: Still creating... [1m20s elapsed]
aws_secretsmanager_secret.central_secret: Still creating... [1m30s elapsed]
aws_secretsmanager_secret.central_secret: Still creating... [1m40s elapsed]
aws_secretsmanager_secret.central_secret: Still creating... [1m50s elapsed]
╷
│ Error: error creating Secrets Manager Secret: InvalidRequestException: You can't create this secret because a secret with this name is already scheduled for deletion.
│
│   with aws_secretsmanager_secret.central_secret,
│   on main.tf line 99, in resource "aws_secretsmanager_secret" "central_secret":
│   99: resource "aws_secretsmanager_secret" "central_secret" {
│
╵

❯ aws secretsmanager delete-secret --secret-id central-provisioner-credentials --force-delete-without-recovery --region ap-northeast-2

❯ aws secretsmanager delete-secret --secret-id central-provisioner-credentials --force-delete-without-recovery --region ap-northeast-2


❯

❯ terraform apply
data.terraform_remote_state.terraform_backend: Reading...
data.terraform_remote_state.terraform_backend: Read complete after 0s
data.aws_iam_policy.aws_managed_admin_policy: Reading...
aws_iam_user.central_user: Refreshing state... [id=central-provisioner]
data.aws_iam_policy_document.central_user_policy: Reading...
data.aws_iam_policy_document.central_user_policy: Read complete after 0s [id=2781255193]
aws_iam_access_key.central: Refreshing state... [id=AKIA3EMVWZLIHCNSI3GC]
aws_iam_user_policy.central: Refreshing state... [id=central-provisioner:central-provisioner-policy]
data.aws_iam_policy_document.central_role_trust_policy: Reading...
data.aws_iam_policy_document.central_role_trust_policy: Read complete after 0s [id=3806599493]
aws_iam_role.central_role: Refreshing state... [id=central-provisioner]
data.aws_iam_policy.aws_managed_admin_policy: Read complete after 1s [id=arn:aws:iam::aws:policy/AdministratorAccess]
aws_iam_role_policy_attachment.central: Refreshing state... [id=central-provisioner-20220922142349805900000001]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_secretsmanager_secret.central_secret will be created
  + resource "aws_secretsmanager_secret" "central_secret" {
      + arn                            = (known after apply)
      + force_overwrite_replica_secret = false
      + id                             = (known after apply)
      + name                           = "central-provisioner-credentials"
      + name_prefix                    = (known after apply)
      + policy                         = (known after apply)
      + recovery_window_in_days        = 30
      + rotation_enabled               = (known after apply)
      + rotation_lambda_arn            = (known after apply)
      + tags_all                       = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/iam"
        }

      + replica {
          + kms_key_id         = (known after apply)
          + last_accessed_date = (known after apply)
          + region             = (known after apply)
          + status             = (known after apply)
          + status_message     = (known after apply)
        }

      + rotation_rules {
          + automatically_after_days = (known after apply)
        }
    }

  # aws_secretsmanager_secret_version.central_secret will be created
  + resource "aws_secretsmanager_secret_version" "central_secret" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + secret_id      = (known after apply)
      + secret_string  = (sensitive value)
      + version_id     = (known after apply)
      + version_stages = (known after apply)
    }

Plan: 2 to add, 0 to change, 0 to destroy.

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

aws_secretsmanager_secret.central_secret: Creating...
aws_secretsmanager_secret.central_secret: Creation complete after 0s [id=arn:aws:secretsmanager:ap-northeast-2:765355018960:secret:central-provisioner-credentials-fqF9g7]
aws_secretsmanager_secret_version.central_secret: Creating...
aws_secretsmanager_secret_version.central_secret: Creation complete after 1s [id=arn:aws:secretsmanager:ap-northeast-2:765355018960:secret:central-provisioner-credentials-fqF9g7|6A385769-F7D2-4253-89BA-1D5CE542E3A7]

Apply complete! Resources: 2 added, 0 changed, 0 destroyed.

Outputs:

provisioner_iam_role_arn = "arn:aws:iam::765355018960:role/central-provisioner"
```
