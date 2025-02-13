pub mod structs;

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest;
use std::{collections::HashSet, sync::Arc};
use structs::*;
use time::{Duration, OffsetDateTime};
use tokio::sync::RwLock;

impl FirebaseTokenPayload {
    fn verify(&self, project_id: &str, current_time: OffsetDateTime) -> FirebaseAuthResult<()> {
        // Verify expiration time
        if self.exp <= current_time.unix_timestamp() {
            return Err(FirebaseAuthError::TokenExpired);
        }

        // Verify issued at time
        if self.iat >= current_time.unix_timestamp() {
            return Err(FirebaseAuthError::InvalidTokenFormat);
        }

        // Verify authentication time
        if self.auth_time >= current_time.unix_timestamp() {
            return Err(FirebaseAuthError::InvalidAuthTime);
        }

        // Verify audience
        if self.aud != project_id {
            return Err(FirebaseAuthError::InvalidAudience);
        }

        // Verify issuer
        let expected_issuer = format!("https://securetoken.google.com/{}", project_id);
        if self.iss != expected_issuer {
            return Err(FirebaseAuthError::InvalidIssuer);
        }

        // Verify subject
        if self.sub.is_empty() {
            return Err(FirebaseAuthError::InvalidSubject);
        }

        Ok(())
    }

    fn to_auth_user(&self) -> FirebaseAuthUser {
        FirebaseAuthUser {
            uid: self.sub.clone(),
            issued_at: OffsetDateTime::from_unix_timestamp(self.iat)
                .unwrap_or_else(|_| OffsetDateTime::now_utc()),
            expires_at: OffsetDateTime::from_unix_timestamp(self.exp)
                .unwrap_or_else(|_| OffsetDateTime::now_utc()),
            auth_time: OffsetDateTime::from_unix_timestamp(self.auth_time)
                .unwrap_or_else(|_| OffsetDateTime::now_utc()),
        }
    }
}

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

        // Initialize the keys
        auth.update_public_keys()
            .await
            .expect("Initial key fetch failed");

        // Start the background refresh task
        auth.start_key_refresh_task();

        auth
    }

    fn start_key_refresh_task(&self) {
        let cached_keys = self.cached_public_keys.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            loop {
                // Read current state
                let next_update = {
                    let keys = cached_keys.read().await;
                    keys.as_ref()
                        .map(|state| state.expiry)
                        .unwrap_or_else(|| OffsetDateTime::now_utc())
                };

                // Calculate sleep duration
                let now = OffsetDateTime::now_utc();
                let sleep_duration = if next_update > now {
                    // Refresh slightly before expiry (90% of the remaining time)
                    let total_duration = (next_update - now).whole_seconds();
                    Duration::seconds((total_duration as f64 * 0.9) as i64)
                } else {
                    Duration::seconds(0)
                };

                // Sleep until next refresh
                tokio::time::sleep(tokio::time::Duration::from_secs(
                    sleep_duration.whole_seconds() as u64,
                ))
                .await;

                // Create new client for each request
                let client = reqwest::Client::new();

                // Fetch new keys
                match Self::fetch_public_keys(&config, &client).await {
                    Ok((keys, expiry)) => {
                        let mut cached = cached_keys.write().await;
                        *cached = Some(SharedState { keys, expiry });
                        println!(
                            "Successfully updated public keys. Next update in {} seconds",
                            (expiry - OffsetDateTime::now_utc()).whole_seconds()
                        );
                    }
                    Err(e) => {
                        eprintln!("Failed to update public keys: {:?}", e);
                        // On error, retry after 1 minute
                        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                    }
                }
            }
        });
    }

    async fn update_public_keys(&self) -> FirebaseAuthResult<()> {
        println!("Updating public keys...");
        let client = reqwest::Client::new();
        let (keys, expiry) = Self::fetch_public_keys(&self.config, &client).await?;
        let mut cached = self.cached_public_keys.write().await;
        *cached = Some(SharedState { keys, expiry });
        println!("Public keys updated successfully with expiry: {}", expiry);
        Ok(())
    }

    async fn fetch_public_keys(
        config: &FirebaseAuthConfig,
        client: &reqwest::Client,
    ) -> FirebaseAuthResult<(PublicKeysResponse, OffsetDateTime)> {
        println!("Fetching public keys from URL: {}", config.public_keys_url);
        let response = client
            .get(&config.public_keys_url)
            .send()
            .await
            .map_err(|e| FirebaseAuthError::HttpError(e.to_string()))?;

        println!("Received response with status: {}", response.status());
        // Get cache control header
        let cache_control = response
            .headers()
            .get("Cache-Control")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("max-age=3600");
        println!("Cache-Control header value: {}", cache_control);

        // Parse max age
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

        // Calculate expiry time
        let expiry = OffsetDateTime::now_utc() + Duration::seconds(max_age);

        Ok((keys, expiry))
    }

    pub async fn verify_token(&self, token: &str) -> FirebaseAuthResult<FirebaseAuthUser> {
        // Decode header without verification
        let header =
            decode_header(token).map_err(|e| FirebaseAuthError::JwtError(e.to_string()))?;

        // Verify algorithm
        if header.alg != Algorithm::RS256 {
            return Err(FirebaseAuthError::InvalidTokenFormat);
        }

        // Get key ID
        let kid = header.kid.ok_or(FirebaseAuthError::InvalidTokenFormat)?;

        // Get public keys
        let cached_keys = self.cached_public_keys.read().await;
        let state = cached_keys
            .as_ref()
            .ok_or(FirebaseAuthError::InvalidTokenFormat)?;

        // Find matching key using the updated structure
        let public_key = state
            .keys
            .keys
            .get(&kid)
            .ok_or(FirebaseAuthError::InvalidSignature)?;

        // Set up validation parameters
        let mut validation = Validation::new(Algorithm::RS256);

        // Configure validation parameters using HashSet
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

        // Decode and verify token
        let token_data = decode::<FirebaseTokenPayload>(
            token,
            &DecodingKey::from_rsa_pem(public_key.as_bytes())
                .map_err(|e| FirebaseAuthError::JwtError(e.to_string()))?,
            &validation,
        )
        .map_err(|e| FirebaseAuthError::JwtError(e.to_string()))?;

        // Verify additional Firebase-specific claims
        token_data
            .claims
            .verify(&self.config.project_id, OffsetDateTime::now_utc())?;

        Ok(token_data.claims.to_auth_user())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_public_key_fetch() {
        println!("Starting public key fetch test");

        let auth = FirebaseAuth::new("oyetime-test".to_string()).await;
        let client = reqwest::Client::new();

        println!("Making request to fetch public keys...");
        match FirebaseAuth::fetch_public_keys(&auth.config, &client).await {
            Ok((keys, expiry)) => {
                println!("✅ Successfully fetched public keys:");
                println!("Keys: {:#?}", keys);
                println!("Expiry: {}", expiry);
                assert!(!keys.keys.is_empty(), "Keys should not be empty");
            }
            Err(e) => {
                println!("❌ Failed to fetch public keys:");
                println!("Error: {:?}", e);
                panic!("Public key fetch failed");
            }
        }
    }

    #[tokio::test]
    async fn test_key_refresh() {
        println!("Starting key refresh test");

        let auth = FirebaseAuth::new("test-project".to_string()).await;
        println!(
            "Initial cached keys: {:#?}",
            auth.cached_public_keys.read().await
        );

        auth.update_public_keys().await.expect("Key refresh failed");

        let cached = auth.cached_public_keys.read().await;
        println!("Updated cached keys: {:#?}", cached);
        assert!(
            cached.is_some(),
            "Cached keys should be present after refresh"
        );
    }
}
