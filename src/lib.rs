pub mod structs;

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest;
use std::{
    collections::HashSet,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use structs::*;
use tokio::sync::RwLock;

impl FirebaseAuth {
    pub async fn new(project_id: String) -> Self {
        let auth = FirebaseAuth {
            config: FirebaseAuthConfig {
                project_id,
                public_keys_url: String::from(
                    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
                ),
            },
            cached_public_keys: Arc::new(RwLock::new(None)),
        };

        auth.update_public_keys()
            .await
            .expect("Initial key fetch failed");
        auth.start_key_refresh_task();
        auth
    }

    fn start_key_refresh_task(&self) {
        let cached_keys = self.cached_public_keys.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            loop {
                let next_update = {
                    let keys = cached_keys.read().await;
                    keys.as_ref().map(|state| state.expiry).unwrap_or_else(|| {
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64
                    })
                };

                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;

                let sleep_duration = if next_update > current_time {
                    ((next_update - current_time) as f64 * 0.9) as u64
                } else {
                    0
                };

                tokio::time::sleep(tokio::time::Duration::from_secs(sleep_duration)).await;

                let client = reqwest::Client::new();
                match Self::fetch_public_keys(&config, &client).await {
                    Ok((keys, expiry)) => {
                        let mut cached = cached_keys.write().await;
                        *cached = Some(SharedState { keys, expiry });
                    }
                    Err(e) => {
                        eprintln!("Failed to update public keys: {:?}", e);
                        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                    }
                }
            }
        });
    }

    async fn fetch_public_keys(
        config: &FirebaseAuthConfig,
        client: &reqwest::Client,
    ) -> FirebaseAuthResult<(PublicKeysResponse, i64)> {
        let response = client
            .get(&config.public_keys_url)
            .send()
            .await
            .map_err(|e| FirebaseAuthError::HttpError(e.to_string()))?;

        let cache_control = response
            .headers()
            .get("Cache-Control")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("max-age=3600");

        let max_age = cache_control
            .split(',')
            .find(|&s| s.trim().starts_with("max-age="))
            .and_then(|s| s.trim().strip_prefix("max-age="))
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(3600);

        let keys: PublicKeysResponse = response
            .json()
            .await
            .map_err(|e| FirebaseAuthError::HttpError(e.to_string()))?;

        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + max_age;

        Ok((keys, expiry))
    }

    async fn update_public_keys(&self) -> FirebaseAuthResult<()> {
        let client = reqwest::Client::new();
        let (keys, expiry) = Self::fetch_public_keys(&self.config, &client).await?;
        let mut cached = self.cached_public_keys.write().await;
        *cached = Some(SharedState { keys, expiry });
        Ok(())
    }

    pub async fn verify_token<T>(&self, token: &str) -> FirebaseAuthResult<T>
    where
        T: TokenVerifier + serde::de::DeserializeOwned,
    {
        let header =
            decode_header(token).map_err(|e| FirebaseAuthError::JwtError(e.to_string()))?;
        if header.alg != Algorithm::RS256 {
            return Err(FirebaseAuthError::InvalidTokenFormat);
        }

        let kid = header.kid.ok_or(FirebaseAuthError::InvalidTokenFormat)?;
        let cached_keys = self.cached_public_keys.read().await;
        let state = cached_keys
            .as_ref()
            .ok_or(FirebaseAuthError::InvalidTokenFormat)?;

        let public_key = state
            .keys
            .keys
            .get(&kid)
            .ok_or(FirebaseAuthError::InvalidSignature)?;

        let mut validation = Validation::new(Algorithm::RS256);
        let mut iss_set = HashSet::new();
        iss_set.insert(format!(
            "https://securetoken.google.com/{}",
            self.config.project_id
        ));
        validation.iss = Some(iss_set);

        let mut aud_set = HashSet::new();
        aud_set.insert(self.config.project_id.clone());
        validation.aud = Some(aud_set);

        validation.validate_exp = true;
        validation.validate_nbf = false;
        validation.set_required_spec_claims(&["sub"]);

        let token_data = decode::<T>(
            token,
            &DecodingKey::from_rsa_pem(public_key.as_bytes())
                .map_err(|e| FirebaseAuthError::JwtError(e.to_string()))?,
            &validation,
        )
        .map_err(|e| FirebaseAuthError::JwtError(e.to_string()))?;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        token_data
            .claims
            .verify(&self.config.project_id, current_time)?;

        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_public_key_fetch() {
        let auth = FirebaseAuth::new("test-project".to_string()).await;
        let client = reqwest::Client::new();

        let result = FirebaseAuth::fetch_public_keys(&auth.config, &client).await;
        assert!(result.is_ok());

        let (keys, _) = result.unwrap();
        assert!(!keys.keys.is_empty());
    }

    #[tokio::test]
    async fn test_verify_normal_token() {
        let auth = FirebaseAuth::new("test-project".to_string()).await;

        // You would need to replace this with a valid test token
        let test_token = "your.test.token";

        let result: FirebaseAuthResult<FirebaseAuthUser> = auth.verify_token(test_token).await;
        assert!(result.is_err()); // Will fail with invalid token, replace with proper test token
    }

    #[tokio::test]
    async fn test_verify_google_token() {
        let auth = FirebaseAuth::new("test-project".to_string()).await;

        // You would need to replace this with a valid test token
        let test_token = "your.google.test.token";

        let result: FirebaseAuthResult<FirebaseAuthGoogleUser> =
            auth.verify_token(test_token).await;
        assert!(result.is_err()); // Will fail with invalid token, replace with proper test token
    }
}
