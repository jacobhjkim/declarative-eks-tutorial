locals {
  credentials_region = "ap-northeast-2"                    # TODO: Change to your region
  aws_account_id     = "765355018960"                      # TODO: Change to your account ID
  tfstates_bucket    = "declarative-eks-tutorial-tfstates" # TODO: Change to your bucket name
  initial_user       = "hyunjun-kim"                       # TODO: Change to your user name
  // remove initial_user_arn once we have a proper provisioner
  initial_user_arn = "arn:aws:iam::${local.aws_account_id}:user/${local.initial_user}"

  cluster_name    = "central"
  cluster_region  = "ap-northeast-2" # TODO: Change to your region
  cluster_version = "1.23"

  vpc_id              = data.terraform_remote_state.vpc_state.outputs.vpc_id
  vpc_cidrs           = data.terraform_remote_state.vpc_state.outputs.vpc_cidrs
  vpc_private_subnets = data.terraform_remote_state.vpc_state.outputs.private_subnet_ids
  vpc_public_subnets  = data.terraform_remote_state.vpc_state.outputs.public_subnet_ids
  vpc_intra_subnets   = data.terraform_remote_state.vpc_state.outputs.intra_subnet_ids
}
