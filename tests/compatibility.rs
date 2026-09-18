use std::{fs, path::Path};

use anyhow::{Result, ensure};
use coduck::rpc::Rpc;
use serde_json::{Value, json};
use tokio::process::Command;

async fn check_version() -> Result<()> {
    let version = Command::new("codex").arg("--version").output().await?;
    let version = String::from_utf8(version.stdout)?;
    assert!(version.trim().starts_with("codex-cli 0."));
    Ok(())
}

async fn server(home: &Path, storage: &str) -> Result<Rpc> {
    let mut command = Command::new("codex");
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("CODEX_") || name.starts_with("OPENAI_") {
            command.env_remove(key);
        }
    }
    command
        .env("CODEX_HOME", home)
        .env("CODEX_INTERNAL_APP_SERVER_REMOTE_CONTROL_DISABLED", "1")
        .current_dir(home)
        .args([
            "-c",
            &format!("cli_auth_credentials_store=\"{storage}\""),
            "app-server",
            "--stdio",
        ]);
    let mut rpc = Rpc::spawn(command)?;
    rpc.initialize(json!({
        "clientInfo": {"name": "coduck-compatibility", "version": "0.1.0"},
        "capabilities": {"experimentalApi": true}
    }))
    .await?;
    Ok(rpc)
}

async fn account(rpc: &mut Rpc) -> Result<Value> {
    Ok(rpc
        .request("account/read", json!({"refreshToken": false}))
        .await?["account"]
        .clone())
}

#[tokio::test]
#[ignore = "requires installed Codex 0.154.0 or newer; uses only a disposable home and dummy credentials"]
async fn official_binary_keeps_managed_and_ephemeral_logins_separate() -> Result<()> {
    check_version().await?;
    let home = tempfile::tempdir()?;
    let original = b"{\"OPENAI_API_KEY\":\"dummy-persistent-credential\"}";
    fs::write(home.path().join("auth.json"), original)?;
    fs::write(
        home.path().join("config.toml"),
        "[analytics]\nenabled=false\n",
    )?;

    let mut managed = server(home.path(), "file").await?;
    let mut coding = server(home.path(), "ephemeral").await?;
    assert_eq!(account(&mut managed).await?["type"], "apiKey");
    assert!(account(&mut coding).await?.is_null());

    // deliberately unsigned fixture; this checks local plumbing, not successful service authentication.
    let token = concat!(
        "eyJhbGciOiJub25lIn0.",
        "eyJleHAiOjQxMDI0NDQ4MDAsImh0dHBzOi8vYXBpLm9wZW5haS5jb20vYXV0aCI6eyJjaGF0Z3B0X2FjY291bnRfaWQiOiJmaXh0dXJlIiwiY2hhdGdwdF91c2VyX2lkIjoiZml4dHVyZS11c2VyIiwiY2hhdGdwdF9wbGFuX3R5cGUiOiJwbHVzIn19.",
        "fixture"
    );
    coding
        .request(
            "account/login/start",
            json!({
                "type": "chatgptAuthTokens", "accessToken": token,
                "chatgptAccountId": "fixture", "chatgptPlanType": "plus"
            }),
        )
        .await?;
    assert_eq!(account(&mut coding).await?["type"], "chatgpt");
    assert_eq!(fs::read(home.path().join("auth.json"))?, original);

    let mut another = server(home.path(), "ephemeral").await?;
    assert!(account(&mut another).await?.is_null());
    coding.request("account/logout", Value::Null).await?;
    assert!(account(&mut coding).await?.is_null());
    assert_eq!(account(&mut managed).await?["type"], "apiKey");
    assert_eq!(fs::read(home.path().join("auth.json"))?, original);

    let restricted_home = tempfile::tempdir()?;
    fs::write(
        restricted_home.path().join("config.toml"),
        "forced_chatgpt_workspace_id = [\"required-workspace\"]\n",
    )?;
    let mut restricted = server(restricted_home.path(), "ephemeral").await?;
    assert!(
        restricted
            .request(
                "account/login/start",
                json!({
                    "type":"chatgptAuthTokens", "accessToken":token,
                    "chatgptAccountId":"fixture", "chatgptPlanType":"plus"
                })
            )
            .await
            .is_err()
    );
    assert!(account(&mut restricted).await?.is_null());
    restricted.shutdown().await?;

    another.shutdown().await?;
    coding.shutdown().await?;
    managed.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "uses two disposable macOS Keychain profiles with dummy credentials and removes them afterward"]
async fn official_keyring_profiles_survive_restart_and_independent_logout() -> Result<()> {
    check_version().await?;
    let homes = [tempfile::tempdir()?, tempfile::tempdir()?];
    let mut result: Result<()> = async {
        for (index, home) in homes.iter().enumerate() {
            let mut helper = server(home.path(), "keyring").await?;
            helper
                .request(
                    "account/login/start",
                    json!({
                        "type": "apiKey", "apiKey": format!("dummy-coduck-profile-{index}")
                    }),
                )
                .await?;
            helper.shutdown().await?;
            ensure!(
                !home.path().join("auth.json").exists(),
                "keyring must not write plaintext auth"
            );
        }
        let mut first = server(homes[0].path(), "keyring").await?;
        let mut second = server(homes[1].path(), "keyring").await?;
        for (index, helper) in [&mut first, &mut second].into_iter().enumerate() {
            let status = helper
                .request("getAuthStatus", json!({"includeToken": true}))
                .await?;
            ensure!(
                status["authToken"] == format!("dummy-coduck-profile-{index}"),
                "profile identity did not survive restart"
            );
        }
        first.request("account/logout", Value::Null).await?;
        ensure!(
            account(&mut first).await?.is_null(),
            "first profile remained signed in"
        );
        ensure!(
            account(&mut second).await?["type"] == "apiKey",
            "logout changed the other profile"
        );
        first.shutdown().await?;
        second.shutdown().await?;
        Ok(())
    }
    .await;

    // attempt both removals even if verification or one cleanup fails.
    for home in &homes {
        let cleanup = async {
            let mut helper = server(home.path(), "keyring").await?;
            helper.request("account/logout", Value::Null).await?;
            helper.shutdown().await
        }
        .await;
        result = result.and(cleanup);
    }
    result
}
