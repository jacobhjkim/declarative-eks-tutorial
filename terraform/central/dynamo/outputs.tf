output "lock_table_arn" {
  value = aws_dynamodb_table.backend_lock.arn
}
