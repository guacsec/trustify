variable "sso-domain" {
  type = string
}

variable "admin-email" {
  type = string
}

variable "console-url" {
  type = string
}

resource "aws_cognito_user_pool" "pool" {
  name = "trustify-${var.environment}"
}

resource "aws_cognito_resource_server" "trustify" {
  identifier   = "trustify"
  name         = "trustify"
  user_pool_id = aws_cognito_user_pool.pool.id

  scope {
    scope_description = "sbom"
    scope_name        = "sbom"
  }
  scope {
    scope_description = "advisory"
    scope_name        = "advisory"
  }
  scope {
    scope_description = "metadata"
    scope_name        = "metadata"
  }
  scope {
    scope_description = "importer"
    scope_name        = "importer"
  }
  scope {
    scope_description = "ai"
    scope_name        = "ai"
  }
  scope {
    scope_description = "admin"
    scope_name        = "admin"
  }
}

resource "aws_cognito_user_pool_domain" "main" {
  domain       = var.sso-domain
  user_pool_id = aws_cognito_user_pool.pool.id
}

resource "aws_cognito_user_group" "manager" {
  user_pool_id = aws_cognito_user_pool.pool.id
  name         = "manager"
}

resource "aws_cognito_user" "admin" {
  user_pool_id = aws_cognito_user_pool.pool.id
  username     = "admin"

  attributes = {
    email          = var.admin-email
    email_verified = true
  }
}

resource "aws_cognito_user_in_group" "admin-manager" {
  group_name   = aws_cognito_user_group.manager.name
  user_pool_id = aws_cognito_user_pool.pool.id
  username     = aws_cognito_user.admin.username
}

resource "aws_cognito_user_pool_client" "cli" {
  name         = "cli-${var.environment}"
  user_pool_id = aws_cognito_user_pool.pool.id

  supported_identity_providers = ["COGNITO"]

  allowed_oauth_flows_user_pool_client = true

  allowed_oauth_flows  = ["client_credentials"]
  allowed_oauth_scopes = aws_cognito_resource_server.trustify.scope_identifiers

  generate_secret = true
}

resource "kubernetes_secret" "oidc-cli" {
  metadata {
    name      = "oidc-cli"
    namespace = var.namespace
  }

  data = {
    client-id     = aws_cognito_user_pool_client.cli.id
    client-secret = aws_cognito_user_pool_client.cli.client_secret
  }

  type = "Opaque"
}

resource "aws_cognito_user_pool_client" "frontend" {
  name         = "frontend-${var.environment}"
  user_pool_id = aws_cognito_user_pool.pool.id

  supported_identity_providers = ["COGNITO"]

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["email", "openid"]

  callback_urls = [
    var.console-url,
    "${var.console-url}/",
    "${var.console-url}/openapi/oauth-receiver.html",
  ]
  logout_urls = [
    "${var.console-url}/",
    "${var.console-url}/notloggedin",
  ]
}

resource "kubernetes_secret" "oidc-frontend" {
  metadata {
    name      = "oidc-frontend"
    namespace = var.namespace
  }

  data = {
    client-id = aws_cognito_user_pool_client.frontend.id
  }

  type = "Opaque"
}

resource "kubernetes_config_map" "aws-oidc" {
  metadata {
    name      = "aws-oidc"
    namespace = var.namespace
  }

  data = {
    issuer-url = "https://cognito-idp.${data.aws_region.current.name}.amazonaws.com/${aws_cognito_user_pool.pool.id}"
  }
}
