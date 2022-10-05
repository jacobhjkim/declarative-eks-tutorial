locals {
  vault_address   = "https://vault.jacobkim.io"
  aws_account_id  = "765355018960"                      # TODO: Change to your account ID
  region          = "ap-northeast-2"                    # TODO: Change to your region
  tfstates_bucket = "declarative-eks-tutorial-tfstates" # TODO: Change to your bucket name
  cidr            = "10.98.0.0/16"

  cluster_name     = "dev"
  subnets          = cidrsubnets(local.cidr, 3, 3, 3, 3, 3, 3)
  private_subnets  = slice(local.subnets, 0, 3)             // Three 19bit subnets
  public_subnets   = cidrsubnets(local.subnets[3], 3, 3, 3) // Three 22bit subnets
  intra_subnets    = cidrsubnets(local.subnets[4], 3, 3, 3) // Three 22bit subnets
  database_subnets = cidrsubnets(local.subnets[5], 3, 3, 3) // Three 22bit subnets

  acl_policy_allow_all = {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}
