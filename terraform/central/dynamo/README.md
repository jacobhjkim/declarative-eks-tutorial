```shell
$ terraform apply

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_dynamodb_table.backend_lock will be created
  + resource "aws_dynamodb_table" "backend_lock" {
      + arn              = (known after apply)
      + billing_mode     = "PAY_PER_REQUEST"
      + hash_key         = "LockID"
      + id               = (known after apply)
      + name             = "tutorial-terraform-backend-locks"
      + read_capacity    = (known after apply)
      + stream_arn       = (known after apply)
      + stream_label     = (known after apply)
      + stream_view_type = (known after apply)
      + tags_all         = {
          + "ManagedByTerraform" = "true"
          + "Owner"              = "declarative-eks-tutorial"
          + "Stage"              = "central"
          + "Workspace"          = "terraform/central/dynamo"
        }
      + write_capacity   = (known after apply)

      + attribute {
          + name = "LockID"
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

Plan: 1 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + lock_table_arn = (known after apply)

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

aws_dynamodb_table.backend_lock: Creating...
aws_dynamodb_table.backend_lock: Creation complete after 7s [id=tutorial-terraform-backend-locks]

Apply complete! Resources: 1 added, 0 changed, 0 destroyed.

Outputs:

lock_table_arn = "arn:aws:dynamodb:ap-northeast-2:765355018960:table/tutorial-terraform-backend-locks"
```

```shell
Initializing the backend...
╷
│ Error: Variables not allowed
│
│   on versions.tf line 5, in terraform:
│    5:     region = local.region
│
│ Variables may not be used here.
╵

╷
│ Error: Variables not allowed
│
│   on versions.tf line 6, in terraform:
│    6:     bucket = local.tfstates_bucket
│
│ Variables may not be used here.
╵
```