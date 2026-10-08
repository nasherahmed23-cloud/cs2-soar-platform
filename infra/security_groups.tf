resource "aws_security_group" "soar_lambda_sg" {
  name        = "innovatech-soar-lambda-sg"
  description = "Security group for the Innovatech SOAR Lambda"
  vpc_id      = "vpc-092bfb079da6e5bda"

  egress {
    description = "Allow outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "innovatech-soar-lambda-sg"
    Project     = "Innovatech-NCA"
    Component   = "SOAR"
    Environment = "Prototype"
  }
}
resource "aws_vpc_security_group_ingress_rule" "rds_from_soar_lambda" {
  security_group_id = "sg-0a0b7ac0eac22b4be"

  referenced_security_group_id = aws_security_group.soar_lambda_sg.id

  from_port   = 3306
  to_port     = 3306
  ip_protocol = "tcp"

  description = "Allow MySQL access from SOAR Lambda"
}