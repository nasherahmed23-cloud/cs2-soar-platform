resource "aws_apigatewayv2_api" "soar_api" {
  name          = "innovatech-soar-api"
  protocol_type = "HTTP"
  tags = {
    Project     = "Innovatech-NCA"
    Component   = "SOAR"
    Environment = "Prototype"
  }
}
resource "aws_apigatewayv2_integration" "event_collector" {
  api_id = aws_apigatewayv2_api.soar_api.id

  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.event_collector.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}
resource "aws_apigatewayv2_route" "events" {
  api_id = aws_apigatewayv2_api.soar_api.id

  route_key = "POST /events"
  target    = "integrations/${aws_apigatewayv2_integration.event_collector.id}"
}
resource "aws_apigatewayv2_stage" "default" {
  api_id = aws_apigatewayv2_api.soar_api.id

  name        = "$default"
  auto_deploy = true

  tags = {
    Project     = "Innovatech-NCA"
    Component   = "SOAR"
    Environment = "Prototype"
  }
}

resource "aws_lambda_permission" "allow_api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.event_collector.function_name
  principal     = "apigateway.amazonaws.com"

  source_arn = "${aws_apigatewayv2_api.soar_api.execution_arn}/*/*"
}
resource "aws_apigatewayv2_route" "get_events" {
  api_id = aws_apigatewayv2_api.soar_api.id

  route_key = "GET /events"
  target    = "integrations/${aws_apigatewayv2_integration.event_collector.id}"
}
resource "aws_apigatewayv2_route" "get_incidents" {
  api_id = aws_apigatewayv2_api.soar_api.id

  route_key = "GET /incidents"
  target    = "integrations/${aws_apigatewayv2_integration.event_collector.id}"
}
resource "aws_apigatewayv2_route" "get_notifications" {
  api_id = aws_apigatewayv2_api.soar_api.id

  route_key = "GET /notifications"
  target    = "integrations/${aws_apigatewayv2_integration.event_collector.id}"
}

resource "aws_apigatewayv2_route" "login" {
  api_id = aws_apigatewayv2_api.soar_api.id

  route_key = "POST /login"
  target    = "integrations/${aws_apigatewayv2_integration.event_collector.id}"
}