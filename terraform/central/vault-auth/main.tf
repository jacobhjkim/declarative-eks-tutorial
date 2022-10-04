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
    session_name = "${local.region}-vault-auth"
  }

  default_tags {
    tags = {
      Stage              = local.cluster_name
      Owner              = "declarative-eks-tutorial"
      Workspace          = "terraform/${local.cluster_name}/vault-auth"
      ManagedByTerraform = "true"
    }
  }
}

################################################################################
# Vault Provider
################################################################################
provider "vault" {
  address = local.vault_addr
}

################################################################################
# Terraform Provisioner Vault Auth
################################################################################
resource "aws_iam_user" "vault_user" {
  provider = aws.central

  name = "vault"
}

data "aws_iam_policy_document" "vault_user_role_trust_policy" {
  provider = aws.central

  version = "2012-10-17"
  statement {
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.vault_user.arn]
    }
    actions = [
      "sts:AssumeRole",
    ]
  }
}

resource "aws_iam_role" "vault_user_role" {
  provider = aws.central

  name               = "vault-terraform-provisioner"
  assume_role_policy = data.aws_iam_policy_document.vault_user_role_trust_policy.json
}

resource "aws_iam_role_policy_attachment" "vault_user_role_policy_attachment" {
  provider = aws.central

  role       = aws_iam_role.vault_user_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" // TODO: change to something more specific
}


data "aws_iam_policy_document" "vault_user_policy_document" {
  provider = aws.central

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    resources = [
      aws_iam_role.vault_user_role.arn,
    ]
  }
}

resource "aws_iam_user_policy" "vault_user_policy" {
  provider = aws.central

  name   = "vault-user-policy"
  user   = aws_iam_user.vault_user.name
  policy = data.aws_iam_policy_document.vault_user_policy_document.json
}

resource "aws_iam_access_key" "central_access_key" {
  provider = aws.central

  user = aws_iam_user.vault_user.name
}

data "aws_caller_identity" "central" {
  provider = aws.central
}

resource "vault_aws_secret_backend" "central_vault_secret_backend" {
  path                      = "aws/${data.aws_caller_identity.central.account_id}"
  access_key                = aws_iam_access_key.central_access_key.id
  secret_key                = aws_iam_access_key.central_access_key.secret
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 36000
}

resource "vault_aws_secret_backend_role" "central_terraform_provisioner" {
  backend         = vault_aws_secret_backend.central_vault_secret_backend.path
  name            = "terraform-provisioner"
  credential_type = "assumed_role"
  role_arns       = [aws_iam_role.vault_user_role.arn]
}

################################################################################
# Central Kubernetes Cluster Vault Auth
################################################################################

#### Kubernetes Provider ####
data "aws_eks_cluster" "cluster" {
  provider = aws.central

  name = local.cluster_name
}

data "aws_eks_cluster_auth" "cluster" {
  provider = aws.central

  name = local.cluster_name
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.cluster.token
}

#### Kubernetes Resources ####
resource "kubernetes_namespace" "validator_namespace" {
  metadata {
    name = local.namespace
    labels = {
      "managed-by" = "terraform"
      "owner"      = "terraform-vault-auth"
    }
  }
}


resource "kubernetes_service_account" "validator_service_account" {
  metadata {
    name      = local.service_account_name
    namespace = kubernetes_namespace.validator_namespace.metadata[0].name
    labels = {
      "migaloo.io/managed-by" = "terraform"
      "migaloo.io/owner"      = "terraform-migaloo-vault-auth"
    }
  }
  automount_service_account_token = true
}


resource "kubernetes_cluster_role_binding" "validator_service_account_cluster_role_binding" {
  metadata {
    name = format("%s-role-binding", local.service_account_name)
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = local.clusterrole_name
  }
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.validator_service_account.metadata[0].name
    namespace = kubernetes_namespace.validator_namespace.metadata[0].name
  }
}

data "kubernetes_secret" "validator_sa_secret" {
  metadata {
    name      = kubernetes_service_account.validator_service_account.default_secret_name
    namespace = kubernetes_namespace.validator_namespace.metadata[0].name
  }
}

data "vault_policy_document" "external_secret_policy" {
  rule {
    path         = "secret/*"
    capabilities = ["read", "list"]
  }
}

resource "vault_policy" "secret_controller" {
  name = "k8s-${local.cluster_name}-external-secret"

  policy = data.vault_policy_document.external_secret_policy.hcl
}

resource "vault_auth_backend" "vault_backend" {
  type = "kubernetes"
  path = "k8s/${local.cluster_name}-external-secrets"
}

resource "vault_kubernetes_auth_backend_config" "vault_backend_config" {
  backend                = vault_auth_backend.vault_backend.path
  kubernetes_host        = data.aws_eks_cluster.cluster.endpoint
  issuer                 = data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer
  disable_iss_validation = true // If you are upgrading to Kubernetes v1.21+, ensure the config option disable_iss_validation is set to true.
}

locals {
  auth_backend_roles = [{
    policy_names          = [vault_policy.secret_controller.name]
    role_name             = "external-secrets"
    bound_namespaces      = ["*"]
    bound_serviceaccounts = ["*"]
    token_ttl             = 3600
  }]
}

resource "vault_kubernetes_auth_backend_role" "vault_backend_role" {
  count = length(local.auth_backend_roles)

  backend                          = vault_auth_backend.vault_backend.path
  role_name                        = local.auth_backend_roles[count.index].role_name
  bound_service_account_names      = local.auth_backend_roles[count.index].bound_serviceaccounts
  bound_service_account_namespaces = local.auth_backend_roles[count.index].bound_namespaces
  token_ttl                        = local.auth_backend_roles[count.index].token_ttl
  token_policies                   = local.auth_backend_roles[count.index].policy_names
}

################################################################################
# Vault Policies (and policy for Atlantis)
################################################################################

#### Atlantis ####
data "vault_policy_document" "atlantis_secret_access_policy" {
  rule {
    path         = "aws/${local.aws_account_id}/sts/terraform-provisioner"
    capabilities = ["read"]
  }
}

#### Vault Policy Documents ####
data "vault_policy_document" "terraform_default_policy" {
  rule {
    path         = "auth/token/renew"
    capabilities = ["update"]
  }

  rule {
    path         = "auth/token/create"
    capabilities = ["read", "list", "create", "update"]
  }

  rule {
    path         = "auth/token/lookup-self"
    capabilities = ["read"]
  }

  rule {
    path         = "auth/token/lookup-accessor"
    capabilities = ["update"]
  }

  rule {
    path         = "auth/token/revoke-accessor"
    capabilities = ["update"]
  }
}

data "vault_policy_document" "terraform_kv_read_policy" {
  rule {
    path         = "secret/*"
    capabilities = ["read", "list"]
  }
}

data "vault_policy_document" "terraform_kv_write_policy" {
  rule {
    path         = "secret/*"
    capabilities = ["create", "read", "update", "delete", "list"]
  }

  rule {
    path         = "cluster/*"
    capabilities = ["create", "read", "update", "delete", "list"]
  }
}

data "vault_policy_document" "terraform_auth_method_policy" {
  rule {
    path         = "sys/auth"
    capabilities = ["read"]
  }

  rule {
    path         = "sys/auth/k8s/*"
    capabilities = ["read", "list", "create", "update", "delete", "sudo"]
  }

  rule {
    path         = "auth/k8s/*"
    capabilities = ["read", "list", "create", "update", "delete", "sudo"]
  }

  rule {
    path         = "sys/policies/acl/*"
    capabilities = ["read", "create", "update", "delete", "sudo"]
  }
}

##### Policies #####
resource "vault_policy" "cicd_terraform_read" {
  name = "cicd/terraform-read"

  policy = join("\n",
    [
      data.vault_policy_document.terraform_kv_read_policy.hcl,
      data.vault_policy_document.atlantis_secret_access_policy.hcl,
      data.vault_policy_document.terraform_default_policy.hcl,
    ]
  )
}

resource "vault_policy" "cicd_terraform_write" {
  name = "cicd/terraform-write"

  policy = join("\n",
    [
      data.vault_policy_document.terraform_kv_write_policy.hcl,
      data.vault_policy_document.atlantis_secret_access_policy.hcl,
      data.vault_policy_document.terraform_default_policy.hcl,
    ]
  )
}

resource "vault_policy" "cicd_terraform_auth_method" {
  name = "cicd/terraform-auth-method"

  policy = join("\n",
    [
      data.vault_policy_document.terraform_auth_method_policy.hcl,
      data.vault_policy_document.terraform_kv_write_policy.hcl,
      data.vault_policy_document.atlantis_secret_access_policy.hcl,
      data.vault_policy_document.terraform_default_policy.hcl,
    ]
  )
}

resource "vault_policy" "terraform_admin" {
  name = "cicd/terraform-admin"

  policy = <<EOT
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
EOT
}

resource "vault_token_auth_backend_role" "terraform_read" {
  role_name        = "terraform-read"
  allowed_policies = [vault_policy.cicd_terraform_read.name]
  token_period     = tostring(60 * 60 * 24 * 30) // 30 days
  renewable        = true
  orphan           = true
}

resource "vault_token_auth_backend_role" "terraform_write" {
  role_name        = "terraform-write"
  allowed_policies = [vault_policy.cicd_terraform_write.name]
  token_period     = tostring(60 * 60 * 24 * 30) // 30 days
  renewable        = true
  orphan           = true
}

resource "vault_token_auth_backend_role" "terraform_extsecret" {
  role_name        = "terraform-auth-method"
  allowed_policies = [vault_policy.cicd_terraform_auth_method.name]
  token_period     = tostring(60 * 60 * 24 * 30) // 30 days
  renewable        = true
  orphan           = true
}

resource "vault_token_auth_backend_role" "terraform_admin" {
  role_name        = "terraform-admin"
  allowed_policies = [vault_policy.terraform_admin.name]
  token_period     = tostring(60 * 60 * 24 * 30) // 30 days
  renewable        = true
  orphan           = true
}
