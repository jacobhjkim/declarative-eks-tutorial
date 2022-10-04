################################################################################
# AWS Provider
################################################################################
provider "aws" {
  region = local.region

  default_tags {
    tags = {
      Stage              = "central"
      Owner              = "declarative-eks-tutorial"
      Workspace          = "terraform/central/iam"
      ManagedByTerraform = "true"
    }
  }
}

data "terraform_remote_state" "terraform_backend" {
  backend = "s3"
  config = {
    region = local.region
    bucket = local.tfstates_bucket
    key    = "central/dynamo.tfstate"
  }
}
################################################################################
# Central Terraform Provisioner IAM
################################################################################
resource "aws_iam_user" "central_user" {
  name = local.name
}

data "aws_iam_policy_document" "central_role_trust_policy" {
  statement {
    effect = "Allow"
    principals {
      identifiers = [aws_iam_user.central_user.arn, local.initial_provisioner_arn]
      type        = "AWS"
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "central_role" {
  name               = local.name
  assume_role_policy = data.aws_iam_policy_document.central_role_trust_policy.json
}

data "aws_iam_policy" "aws_managed_admin_policy" {
  arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role_policy_attachment" "central" {
  role       = aws_iam_role.central_role.name
  policy_arn = data.aws_iam_policy.aws_managed_admin_policy.arn
}

data "aws_iam_policy_document" "central_user_policy" {
  statement {
    effect = "Allow"
    actions = [
      "s3:ListBucket",
      "s3:GetBucketVersioning",
    ]
    resources = ["arn:aws:s3:::${local.tfstates_bucket}"]
  }
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = ["arn:aws:s3:::${local.tfstates_bucket}/*"]
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

################################################################################
# AWS Secret Manager
################################################################################
resource "aws_iam_user_policy" "central" {
  name   = format("%s-policy", local.name)
  user   = aws_iam_user.central_user.name
  policy = data.aws_iam_policy_document.central_user_policy.json
}

resource "aws_iam_access_key" "central" {
  user = aws_iam_user.central_user.name
}

resource "aws_secretsmanager_secret" "central_secret" {
  name = format("%s-credentials", local.name)
}

resource "aws_secretsmanager_secret_version" "central_secret" {
  secret_id = aws_secretsmanager_secret.central_secret.id
  secret_string = jsonencode({
    accessKey = aws_iam_access_key.central.id
    secretKey = aws_iam_access_key.central.secret
  })
}
