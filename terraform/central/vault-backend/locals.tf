locals {
  aws_account_id = "765355018960"   # TODO: replace with your AWS account ID
  region         = "ap-northeast-2" # TODO: replace with your AWS region

  cluster_name     = "central"
  namespace        = "token-vault-auth-validator"
  account_name     = "vault-auth-validator"
  clusterrole_name = "system:auth-delegator"
}
