locals {
  vault_address  = "https://vault.jacobkim.io"
  aws_account_id = "765355018960" # TODO: Change to your account ID

  cluster_name   = "dev"
  cluster_region = "ap-northeast-2" # TODO: Change to your region

  kubernetes_labels = {
    "managed-by" = "terraform"
    "owner"      = "terraform-eks-addons"
  }

  argocd_manager_name         = "argocd-manager"
  vault_auth_name             = "vault-auth-validator"
  vault_auth_clusterrole_name = "system:auth-delegator"
}
