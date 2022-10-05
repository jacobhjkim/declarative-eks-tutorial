provider "vault" {
  address = local.vault_address
}

data "vault_aws_access_credentials" "aws_credentials" {
  backend = "aws/${local.aws_account_id}"
  role    = "terraform-provisioner"
  type    = "sts"
}

provider "aws" {
  region     = local.cluster_region
  access_key = data.vault_aws_access_credentials.aws_credentials.access_key
  secret_key = data.vault_aws_access_credentials.aws_credentials.secret_key
  token      = data.vault_aws_access_credentials.aws_credentials.security_token
}

################################################################################
# ArgoCD
################################################################################
data "aws_eks_cluster" "eks" {
  name = local.cluster_name
}

data "aws_eks_cluster_auth" "eks_auth" {
  name = local.cluster_name
}

locals {
  cluster_endpoint = data.aws_eks_cluster.eks.endpoint
  cluster_ca_cert  = data.aws_eks_cluster.eks.certificate_authority.0.data
  issuer           = data.aws_eks_cluster.eks.identity.0.oidc.0.issuer
  token            = data.aws_eks_cluster_auth.eks_auth.token
}

provider "kubernetes" {
  host                   = local.cluster_endpoint
  cluster_ca_certificate = base64decode(local.cluster_ca_cert)
  token                  = local.token
}

resource "kubernetes_namespace" "manager_ns" {
  metadata {
    name   = "argocd-manager"
    labels = local.kubernetes_labels
  }
}

resource "kubernetes_service_account" "manager_sa" {
  metadata {
    name      = local.argocd_manager_name
    namespace = kubernetes_namespace.manager_ns.metadata[0].name
    labels    = local.kubernetes_labels
  }
  automount_service_account_token = true
}

resource "kubernetes_cluster_role_binding" "manager_crb" {
  metadata {
    name = format("%s-role-binding", local.argocd_manager_name)
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster-admin"
  }
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.manager_sa.metadata[0].name
    namespace = kubernetes_namespace.manager_ns.metadata[0].name
  }
}

data "kubernetes_secret" "manager_secret" {
  metadata {
    name      = kubernetes_service_account.manager_sa.default_secret_name
    namespace = kubernetes_namespace.manager_ns.metadata[0].name
  }
}

resource "vault_generic_secret" "argoconfig" {
  path = format("secret/cluster/%s/argocd", local.cluster_name)
  data_json = jsonencode({
    name   = local.cluster_name
    server = local.cluster_endpoint
    argoconfig = jsonencode({
      bearerToken = data.kubernetes_secret.manager_secret.data.token
      tlsClientConfig = {
        insecure = false
        caData   = local.cluster_ca_cert
      }
    })
  })
}

################################################################################
# Vault
################################################################################

#### Kubernetes Setup ####
resource "kubernetes_namespace" "validator_ns" {
  metadata {
    name   = "token-vault-auth-validator"
    labels = local.kubernetes_labels
  }
}

resource "kubernetes_service_account" "validator_sa" {
  metadata {
    name      = local.vault_auth_name
    namespace = kubernetes_namespace.validator_ns.metadata[0].name
    labels    = local.kubernetes_labels
  }
  automount_service_account_token = true
}

resource "kubernetes_cluster_role_binding" "validator_sa_crb" {
  metadata {
    name = format("%s-role-binding", local.vault_auth_name)
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = local.vault_auth_clusterrole_name
  }
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.validator_sa.metadata[0].name
    namespace = kubernetes_namespace.validator_ns.metadata[0].name
  }
}

data "kubernetes_secret" "validator_sa_secret" {
  metadata {
    name      = kubernetes_service_account.validator_sa.default_secret_name
    namespace = kubernetes_namespace.validator_ns.metadata[0].name
  }
}

#### Vault Engine ####
data "vault_policy_document" "external_secret_policy" {
  rule {
    path         = "secret/dev/*"
    capabilities = ["read", "list"]
  }
}

resource "vault_policy" "external_secrets_policy" {
  name = format("k8s-%s-external-secret-controller", local.cluster_name)

  policy = data.vault_policy_document.external_secret_policy.hcl
}

locals {
  auth_backend_roles = [
    {
      policy_names          = [vault_policy.external_secrets_policy.name]
      role_name             = "external-secrets"
      bound_namespaces      = ["*"]
      bound_serviceaccounts = ["*"]
      token_ttl             = 3600
    }
  ]
}

resource "vault_auth_backend" "vault_backend" {
  type = "kubernetes"
  path = "k8s/${local.cluster_name}-external-secrets"
}

resource "vault_kubernetes_auth_backend_config" "vault_backend_config" {
  backend                = vault_auth_backend.vault_backend.path
  kubernetes_host        = local.cluster_endpoint
  kubernetes_ca_cert     = base64decode(local.cluster_ca_cert)
  token_reviewer_jwt     = data.kubernetes_secret.validator_sa_secret.data.token
  issuer                 = local.issuer
  disable_iss_validation = true
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
