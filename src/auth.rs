use crate::{
    profile::Identity,
    rpc::{MAX_PENDING, Rpc},
};
use anyhow::{Result, anyhow, bail};
use base64::{
    Engine,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use serde_json::{Value, json};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;

pub struct Login {
    pub auth_url: String,
    pub login_id: String,
}
pub enum LoginOutcome {
    Ready,
    Unconfirmed,
}

pub struct Token {
    secret: String,
    pub identity: Identity,
}
impl Token {
    fn parse(secret: String, now: u64) -> Result<Self> {
        let mut parts = secret.split('.');
        let _header = parts.next();
        let payload = parts
            .next()
            .ok_or_else(|| anyhow!("helper returned an opaque token; log in again"))?;
        if parts.next().is_none() || parts.next().is_some() {
            bail!("helper returned an invalid token");
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .or_else(|_| URL_SAFE.decode(payload))
            .map_err(|_| anyhow!("helper returned invalid token claims"))?;
        let claims: Value = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow!("helper returned invalid token claims"))?;
        let exp = claims
            .get("exp")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("helper token has no expiry"))?;
        if exp <= now.saturating_add(30) {
            bail!(
                "helper token is expired or expiring; retry, then log in again if the problem persists"
            );
        }
        let auth = &claims["https://api.openai.com/auth"];
        let account_id = required_string(auth, "chatgpt_account_id")?;
        let user_id = auth
            .get("chatgpt_user_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                auth.get("user_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
            })
            .ok_or_else(|| anyhow!("helper token has no user identity"))?
            .to_owned();
        let plan_type = required_string(auth, "chatgpt_plan_type")?.to_ascii_lowercase();
        let plan_type = match plan_type.as_str() {
            "education" => "edu".to_owned(),
            "hc" => "enterprise".to_owned(),
            _ => plan_type,
        };
        if !matches!(
            plan_type.as_str(),
            "free"
                | "go"
                | "plus"
                | "pro"
                | "prolite"
                | "team"
                | "self_serve_business_prolite"
                | "self_serve_business_usage_based"
                | "business"
                | "ent26"
                | "enterprise_cbp_automation"
                | "enterprise_cbp_usage_based"
                | "enterprise"
                | "edu"
                | "edu_plus"
                | "edu_pro"
        ) {
            bail!("this ChatGPT plan is not supported by this Coduck version");
        }
        let email = claims
            .get("email")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                claims["https://api.openai.com/profile"]
                    .get("email")
                    .and_then(Value::as_str)
            })
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        Ok(Self {
            secret,
            identity: Identity {
                account_id,
                user_id,
                email,
                plan_type,
            },
        })
    }
    pub fn login_params(&self) -> Value {
        let mut params = self.refresh_result();
        params["type"] = json!("chatgptAuthTokens");
        params
    }
    pub fn refresh_result(&self) -> Value {
        json!({"accessToken":self.secret,"chatgptAccountId":self.identity.account_id,"chatgptPlanType":self.identity.plan_type})
    }
}
fn required_string(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("helper response is missing required identity or login information"))
}
pub async fn initialize(rpc: &mut Rpc) -> Result<()> {
    rpc.initialize(json!({"clientInfo":{"name":"coduck","version":env!("CARGO_PKG_VERSION")},"capabilities":{"experimentalApi":true}})).await?;
    let result = rpc
        .request("config/read", json!({"includeLayers":false}))
        .await?;
    validate_config(&result["config"])
}
fn validate_config(config: &Value) -> Result<()> {
    if config["cli_auth_credentials_store"].as_str() != Some("keyring") {
        bail!("auth helper must use the keyring credential store");
    }
    if !matches!(config["model_provider"].as_str(), None | Some("openai"))
        || config["model_providers"].get("openai").is_some()
        || !matches!(
            config["chatgpt_base_url"].as_str(),
            Some("https://chatgpt.com/backend-api/") | Some("https://chatgpt.com/backend-api")
        )
        || !matches!(
            config["openai_base_url"].as_str(),
            None | Some("https://api.openai.com/v1") | Some("https://api.openai.com/v1/")
        )
        || !matches!(
            config["forced_login_method"].as_str(),
            None | Some("chatgpt")
        )
    {
        bail!("Coduck requires the default OpenAI provider and official ChatGPT backend");
    }
    Ok(())
}
pub async fn signed_in(rpc: &mut Rpc) -> Result<bool> {
    let response = rpc
        .request("account/read", json!({"refreshToken":false}))
        .await?;
    let account = response
        .get("account")
        .ok_or_else(|| anyhow!("invalid helper account response"))?;
    Ok(!account.is_null())
}
pub async fn begin_login(rpc: &mut Rpc) -> Result<Login> {
    let response = rpc
        .request("account/login/start", json!({"type":"chatgpt"}))
        .await?;
    if response["type"].as_str() != Some("chatgpt") {
        bail!("helper did not start a managed ChatGPT login");
    }
    let login = Login {
        auth_url: required_string(&response, "authUrl")?,
        login_id: required_string(&response, "loginId")?,
    };
    if !login.auth_url.starts_with("https://auth.openai.com/") {
        bail!("helper returned an unexpected login URL");
    }
    Ok(login)
}
pub async fn wait_login(rpc: &mut Rpc, login: &Login) -> Result<LoginOutcome> {
    timeout(Duration::from_secs(600), async {
        let mut completed = false;
        for _ in 0..MAX_PENDING {
            let frame = rpc.recv().await?;
            if frame["method"].as_str() == Some("account/login/completed")
                && frame["params"]["loginId"].as_str() == Some(&login.login_id)
            {
                match frame["params"]["success"].as_bool() {
                    Some(true) => {}
                    Some(false) => return Ok(LoginOutcome::Unconfirmed),
                    None => bail!("invalid helper login completion response"),
                }
                // browser completion precedes the helper's credential reload.
                completed = true;
            } else if completed && frame["method"].as_str() == Some("account/updated") {
                if frame["params"]["authMode"].as_str() != Some("chatgpt") {
                    bail!("helper did not load the new ChatGPT login; retry coduck login");
                }
                return Ok(LoginOutcome::Ready);
            }
        }
        bail!("too many unrelated notifications while waiting for login")
    })
    .await
    .map_err(|_| anyhow!("ChatGPT login timed out; retry coduck login"))?
}
pub async fn cancel_login(rpc: &mut Rpc, login: &Login) -> Result<()> {
    rpc.request("account/login/cancel", json!({"loginId":login.login_id}))
        .await?;
    Ok(())
}
pub async fn token(rpc: &mut Rpc, refresh: bool) -> Result<Token> {
    let response = rpc
        .request(
            "getAuthStatus",
            json!({"includeToken":true,"refreshToken":refresh}),
        )
        .await?;
    if response["authMethod"].as_str() != Some("chatgpt") {
        bail!("profile needs a managed ChatGPT login; run coduck login NAME");
    }
    let secret = required_string(&response, "authToken")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut token = Token::parse(secret, now)?;
    if token.identity.email.is_none() {
        let response = rpc
            .request("account/read", json!({"refreshToken":false}))
            .await?;
        token.identity.email = response["account"]["email"].as_str().map(str::to_owned);
    }
    Ok(token)
}
pub async fn refresh(
    rpc: &mut Rpc,
    saved: &Identity,
    previous: &Token,
    params: &Value,
) -> Result<Token> {
    if params["reason"].as_str() != Some("unauthorized") {
        bail!("unsupported authentication refresh reason");
    }
    if let Some(value) = params.get("previousAccountId").filter(|v| !v.is_null())
        && value.as_str() != Some(saved.account_id.as_str())
    {
        bail!("refresh requested for a different account");
    }
    saved.ensure_same_account(&previous.identity)?;
    let next = timeout(Duration::from_secs(7), token(rpc, true))
        .await
        .map_err(|_| anyhow!("profile authentication refresh timed out"))??;
    saved.ensure_same_account(&next.identity)?;
    if next.secret == previous.secret {
        bail!(
            "helper could not refresh the token; retry, then log in again if the problem persists"
        );
    }
    Ok(next)
}
pub async fn logout(rpc: &mut Rpc) -> Result<()> {
    rpc.request("account/logout", json!({})).await?;
    if signed_in(rpc).await? {
        bail!("helper still has a local login; profile metadata was preserved");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::json;
    fn jwt(account: &str, user: &str, plan: &str, exp: u64) -> String {
        format!("e30.{}.signature", URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
            "exp":exp,"email":"sample@example.invalid",
            "https://api.openai.com/auth":{"chatgpt_account_id":account,"chatgpt_user_id":user,"chatgpt_plan_type":plan}
        })).unwrap()))
    }
    fn mock_rpc(responses: Vec<Value>) -> (Rpc, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let (client, server) = tokio::io::duplex(16384);
        let peer = tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(server);
            let mut lines = BufReader::new(read).lines();
            for response in responses {
                let request: Value =
                    serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
                let frame = json!({"id":request["id"],"result":response});
                write
                    .write_all(format!("{frame}\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        (Rpc::test_connection(client), peer)
    }
    #[tokio::test]
    async fn unsuccessful_callback_requires_saved_credential_verification() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(4096);
        let mut rpc = Rpc::test_connection(client);
        server.write_all(b"{\"method\":\"account/login/completed\",\"params\":{\"loginId\":\"login\",\"success\":false,\"error\":\"private callback detail\"}}\n").await.unwrap();
        let login = Login {
            auth_url: String::new(),
            login_id: "login".into(),
        };
        assert!(matches!(
            wait_login(&mut rpc, &login).await.unwrap(),
            LoginOutcome::Unconfirmed
        ));
    }
    #[tokio::test]
    async fn login_waits_for_account_reload_after_browser_completion() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(4096);
        let mut rpc = Rpc::test_connection(client);
        let login = Login {
            auth_url: String::new(),
            login_id: "login".into(),
        };
        let mut waiting = tokio::spawn(async move { wait_login(&mut rpc, &login).await });
        for frame in [
            json!({"method":"account/updated","params":{"authMode":"chatgpt"}}),
            json!({"method":"account/login/completed","params":{"loginId":"login","success":true}}),
        ] {
            server
                .write_all(format!("{frame}\n").as_bytes())
                .await
                .unwrap();
        }
        assert!(
            timeout(Duration::from_millis(20), &mut waiting)
                .await
                .is_err()
        );
        server
            .write_all(b"{\"method\":\"account/updated\",\"params\":{\"authMode\":\"chatgpt\"}}\n")
            .await
            .unwrap();
        waiting.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn forced_refresh_rejects_cached_and_changed_identity_tokens() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let previous = Token::parse(jwt("account", "user", "plus", now + 3600), now).unwrap();
        let (mut rpc, peer) = mock_rpc(vec![
            json!({"authMethod":"chatgpt","authToken":previous.secret}),
            json!({"authMethod":"chatgpt","authToken":jwt("other","user","plus",now+7200)}),
            json!({"authMethod":"chatgpt","authToken":jwt("account","user","pro",now+7200)}),
        ]);
        let params = json!({"reason":"unauthorized","previousAccountId":"account"});
        assert!(
            refresh(&mut rpc, &previous.identity, &previous, &params)
                .await
                .is_err()
        );
        assert!(
            refresh(&mut rpc, &previous.identity, &previous, &params)
                .await
                .is_err()
        );
        let renewed = refresh(&mut rpc, &previous.identity, &previous, &params)
            .await
            .unwrap();
        assert_eq!(renewed.identity.plan_type, "pro");
        assert!(
            refresh(
                &mut rpc,
                &previous.identity,
                &previous,
                &json!({"reason":"unauthorized","previousAccountId":"other"})
            )
            .await
            .is_err()
        );
        peer.await.unwrap();
    }
    #[tokio::test]
    async fn logout_requires_confirmed_local_credential_removal() {
        let (mut rpc, peer) = mock_rpc(vec![
            json!({}),
            json!({"account":{"type":"chatgpt"}}),
            json!({}),
            json!({"account":null}),
        ]);
        assert!(logout(&mut rpc).await.is_err());
        logout(&mut rpc).await.unwrap();
        peer.await.unwrap();
    }
    #[test]
    fn optional_claim_fallbacks_accept_legacy_user_and_profile_email() {
        let claims = json!({"exp":1000,"email":"","https://api.openai.com/profile":{"email":"fallback@example.invalid"},"https://api.openai.com/auth":{"chatgpt_account_id":"account","chatgpt_user_id":null,"user_id":"legacy-user","chatgpt_plan_type":"free"}});
        let secret = format!(
            "e30.{}.signature",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let token = Token::parse(secret, 100).unwrap();
        assert_eq!(token.identity.user_id, "legacy-user");
        assert_eq!(
            token.identity.email.as_deref(),
            Some("fallback@example.invalid")
        );
    }
    #[test]
    fn preflight_rejects_custom_endpoints_and_credential_stores() {
        let config = json!({"cli_auth_credentials_store":"keyring","chatgpt_base_url":"https://chatgpt.com/backend-api/","model_provider":null});
        validate_config(&config).unwrap();
        for (key, value) in [
            ("cli_auth_credentials_store", json!("file")),
            ("chatgpt_base_url", json!("https://example.invalid")),
            ("model_provider", json!("custom")),
            (
                "model_providers",
                json!({"openai":{"base_url":"https://example.invalid"}}),
            ),
            ("forced_login_method", json!("api")),
        ] {
            let mut changed = config.clone();
            changed[key] = value;
            assert!(validate_config(&changed).is_err());
        }
    }
    #[test]
    fn organization_plans_preserve_workspace_identity() {
        for plan in [
            "team",
            "self_serve_business_prolite",
            "self_serve_business_usage_based",
            "business",
            "ent26",
            "enterprise_cbp_automation",
            "enterprise_cbp_usage_based",
            "enterprise",
            "edu",
            "edu_plus",
            "edu_pro",
        ] {
            let token = Token::parse(jwt("workspace", "member", plan, 1000), 100).unwrap();
            let login = token.login_params();
            assert_eq!(login["chatgptAccountId"], "workspace");
            assert_eq!(login["chatgptPlanType"], plan);
            assert_eq!(token.refresh_result()["chatgptAccountId"], "workspace");
            let other = Token::parse(jwt("other-workspace", "member", plan, 1000), 100).unwrap();
            assert!(token.identity.ensure_same_account(&other.identity).is_err());
        }
    }
    #[test]
    fn normalizes_official_organization_plan_aliases() {
        for (raw, expected) in [("education", "edu"), ("hc", "enterprise"), ("EDU", "edu")] {
            let token = Token::parse(jwt("workspace", "member", raw, 1000), 100).unwrap();
            assert_eq!(token.identity.plan_type, expected);
            assert_eq!(token.login_params()["chatgptPlanType"], expected);
            assert_eq!(token.refresh_result()["chatgptPlanType"], expected);
        }
    }
    #[test]
    fn validates_identity_expiry_and_supported_plans_without_exposing_tokens() {
        let token = Token::parse(jwt("account", "user", "plus", 1000), 100).unwrap();
        assert_eq!(token.identity.account_id, "account");
        assert_eq!(token.identity.user_id, "user");
        for secret in [
            jwt("", "user", "plus", 1000),
            jwt("account", "", "plus", 1000),
            jwt("account", "user", "unknown", 1000),
            jwt("account", "user", "plus", 110),
            "opaque-secret".into(),
        ] {
            let error = Token::parse(secret.clone(), 100).err().unwrap().to_string();
            assert!(!error.contains(&secret));
        }
    }
}
