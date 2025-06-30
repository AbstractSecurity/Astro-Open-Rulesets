rule SSH_Private_Keys {
    meta:
        description = "Detects SSH private keys in files"
        author = "Abstract Security ASTRO - Justin Borland"
        date = "2025-01-01"
        reference = "https://www.rfc-editor.org/rfc/rfc7468.html"
    strings:
        $ssh_key_begin = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $rsa_key_begin = "-----BEGIN RSA PRIVATE KEY-----"
        $dsa_key_begin = "-----BEGIN DSA PRIVATE KEY-----"
        $ecdsa_key_begin = "-----BEGIN EC PRIVATE KEY-----"
    condition:
        any of them
}

rule AWS_Secrets {
    meta:
        description = "Detects AWS credentials in files"
        author = "Abstract Security ASTRO - Justin Borland"
        date = "2025-01-01"
        reference = "https://github.com/awslabs/git-secrets"
    strings:
        $aws_access_key = /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/
        $aws_secret_key = /[A-Za-z0-9\/+=]{40}/
    condition:
        all of them
}

rule GCP_Service_Account_Keys {
    meta:
        description = "Detects GCP service account JSON key files"
        author = "Abstract Security ASTRO - Justin Borland"
        date = "2025-01-01"
        reference = "https://cloud.google.com/iam/docs/creating-managing-service-account-keys"
    strings:
        $private_key_id = "private_key_id"
        $private_key = "private_key"
        $private_client_email = "client_email"
        $auth_uri = "https://accounts.google.com/o/oauth2/auth"
    condition:
        any of ($private_*) and $auth_uri
}

rule Kubernetes_Secrets {
    meta:
        description = "Detects Kubernetes secrets in configuration files"
        author = "Abstract Security ASTRO - Justin Borland"
        date = "2025-01-01"
        reference = "https://kubernetes.io/docs/concepts/configuration/secret/"
    strings:
        $k8s_secret = "apiVersion: v1"
        $k8s_data = "data:"
        $k8s_kind_secret = "kind: Secret"
    condition:
        all of them
}

rule Env_Files_Credentials {
    meta:
        description = "Detects sensitive environment variables typically found in .env files"
        author = "Abstract Security ASTRO - Justin Borland"
        date = "2025-01-01"
        reference = "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"

    strings:
        $db_password = /DB_PASSWORD\s*=\s*["']?.{4,256}/ nocase
        $api_key     = /API_KEY\s*=\s*["']?.{4,256}/ nocase
        $secret_key  = /SECRET_KEY\s*=\s*["']?.{4,256}/ nocase
        $aws_key     = /AWS_(ACCESS|SECRET)_KEY(_ID)?\s*=\s*["']?.{4,256}/ nocase
        $token       = /(BEARER_)?TOKEN\s*=\s*["']?.{4,256}/ nocase
    condition:
        any of them
}

rule Okta_API_Tokens {
    meta:
        description = "Detects Okta API tokens in files"
        author = "Abstract Security ASTRO - Justin Borland"
        date = "2025-01-01"
        reference = "https://devforum.okta.com/t/api-token-length/5519/3"
    strings:
        $okta_api_token = /00[a-zA-Z0-9\-\_]{40}/
    condition:
        $okta_api_token
}

rule Duo_Integration_Keys {
    meta:
        description = "Detects Duo integration keys in files"
        author = "Abstract Security ASTRO - Justin Borland"
        date = "2025-01-01"
        reference = "https://duo.com/docs/adminapi"
    strings:
        $duo_integration_key = /DI[0-9A-Z]{18}/
        $duo_secret_key = /[A-Za-z0-9\/+=]{40}/
    condition:
        $duo_integration_key and $duo_secret_key
}

rule Azure_API_Keys {
    meta:
        description = "Detects Azure API keys and tokens"
        author = "Abstract Security ASTRO - Justin Borland"
        date = "2025-01-01"
        reference = "https://learn.microsoft.com/en-us/purview/sit-defn-azure-cognitive-search-api-key"
    strings:
        $azure_subscription_key = /apikey:\w+[a-fA-F0-9]{32}/
    condition:
        $azure_subscription_key
}

rule Google_API_Keys {
    meta:
        description = "Detects Google API keys in files"
        author = "Abstract Security ASTRO - Justin Borland"
        date = "2025-01-01"
        reference_0 = "https://cloud.google.com/docs/authentication/api-keys"
        reference_1 = "https://github.com/odomojuli/regextokens"
    strings:
        $google_api_key = /AIza[0-9A-Za-z\-_]{35}/
    condition:
        $google_api_key
}

rule Slack_API_Tokens {
    meta:
        description = "Detects Slack API tokens in files"
        author = "Abstract Security ASTRO - Justin Borland"
        date = "2025-01-01"
        reference = "https://api.slack.com/authentication/token-types"
    strings:
        $slack_bot_token = /xoxb-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}/
        $slack_user_token = /xoxp-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}/
        $slack_app_token = /xapp-[A-Za-z0-9\-_]{32}/
        $slack_legacy_token = /xoxs-[A-Za-z0-9\-_]{32}/
        $slack_webhook_url = /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\-_]+\/[A-Za-z0-9\-_]+\/[A-Za-z0-9\-_]+/
    condition:
        any of ($slack_bot_token, $slack_user_token, $slack_app_token, $slack_legacy_token, $slack_webhook_url)
}

rule GitHub_Tokens {
    meta:
        description = "Detects GitHub personal access tokens in files"
        author = "Abstract Security ASTRO - Justin Borland"
        date = "2025-01-01"
        reference = "https://github.blog/engineering/behind-githubs-new-authentication-token-formats"
    strings:
        $github_token = /(ghp|gho|ghu|ghs|ghr|ghv)_[A-Za-z0-9]{36}/
    condition:
        $github_token
}

rule General_Credential_Theft {
    meta:
        description = "Detects general patterns of credential theft from multiple sources"
        author = "Abstract Security ASTRO - Justin Borland"
        date = "2025-01-01"
    strings:
        $credentials_pattern1 = /password[=:][\s]*['"]?[\w\d!@#$%^&*()_+={}:;,.?<>-]+['"]?/
        $credentials_pattern2 = /username[=:][\s]*['"]?[\w\d!@#$%^&*()_+={}:;,.?<>-]+['"]?/
        $credentials_pattern3 = /token[=:][\s]*['"]?[\w\d!@#$%^&*()_+={}:;,.?<>-]+['"]?/
        $credentials_pattern4 = /key[=:][\s]*['"]?[\w\d!@#$%^&*()_+={}:;,.?<>-]+['"]?/
    condition:
        any of them
}