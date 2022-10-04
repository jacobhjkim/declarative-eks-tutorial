provider "aws" {
  region = local.region

  default_tags {
    tags = {
      Stage              = "central"
      Owner              = "declarative-eks-tutorial"
      Workspace          = "terraform/central/dynamo"
      ManagedByTerraform = "true"
    }
  }
}

resource "aws_dynamodb_table" "backend_lock" {
  name         = "tutorial-terraform-backend-locks"
  hash_key     = "LockID"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "LockID"
    type = "S"
  }
}
