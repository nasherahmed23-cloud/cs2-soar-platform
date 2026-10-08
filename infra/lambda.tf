data "archive_file" "event_collector" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  output_path = "${path.module}/event_collector.zip"
}
resource "aws_lambda_function" "event_collector" {
  function_name = "innovatech-soar-event-collector"

  filename         = data.archive_file.event_collector.output_path
  source_code_hash = data.archive_file.event_collector.output_base64sha256

  runtime = "python3.12"
  handler = "event_collector.lambda_handler"

  role = aws_iam_role.lambda_execution_role.arn

  timeout     = 10
  memory_size = 128
  vpc_config {
    subnet_ids = [
      "subnet-0ef41a91a63101ba7",
      "subnet-09464db9a5f9d05c8"
    ]
    security_group_ids = [
      aws_security_group.soar_lambda_sg.id
    ]
  }
  tags = {
    Project     = "Innovatech-NCA"
    Component   = "SOAR"
    Environment = "Prototype"
  }
}
