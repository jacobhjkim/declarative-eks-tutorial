locals {
  region         = "ap-northeast-2" # TODO: Change to your region
  name           = "central-provisioner"
  aws_account_id = "765355018960" # TODO: Change to your AWS Account ID
  // remove initial_provisioner_arn once we have a proper provisioner
  initial_provisioner_arn = "arn:aws:iam::${local.aws_account_id}:user/hyunjun-kim" # TODO: Use your user ARN
  tfstates_bucket         = "declarative-eks-tutorial-tfstates"                     # TODO: Change to your bucket name
}
