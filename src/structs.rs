use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::RwLock;

/// Update FirebaseAuth to use Arc and RwLock for shared state
#[derive(Debug, Clone)]
pub struct SharedState {
    pub keys: PublicKeysResponse,
    pub expiry: OffsetDateTime,
}


/// Represents the header of a Firebase ID token as specified in the documentation
#[derive(Debug, Deserialize, Serialize)]
pub struct FirebaseTokenHeader {
    /// Algorithm used for the token signature (must be "RS256")
    pub alg: String,
    /// Key ID corresponding to the public key used for signature verification
    pub kid: String,
}

/// Represents the payload of a Firebase ID token as specified in the documentation
#[derive(Debug, Deserialize, Serialize)]
pub struct FirebaseTokenPayload {
    /// Expiration time (in seconds since UNIX epoch)
    pub exp: i64,
    /// Issued at time (in seconds since UNIX epoch)
    pub iat: i64,
    /// Audience (must be your Firebase project ID)
    pub aud: String,
    /// Issuer (must be "https://securetoken.google.com/<projectId>")
    pub iss: String,
    /// Subject (must be the uid of the user or device)
    pub sub: String,
    /// Authentication time (must be in the past)
    pub auth_time: i64,
}

/// Response from Google's public key endpoint
#[derive(Debug, Deserialize, Clone)]
pub struct PublicKeysResponse {
    #[serde(flatten)]
    pub keys: HashMap<String, String>,
}

/// Configuration for Firebase Authentication
#[derive(Debug, Clone)]
pub struct FirebaseAuthConfig {
    /// Firebase project ID
    pub project_id: String,
    /// Base URL for public key metadata
    pub public_keys_url: String,
}

/// Represents a verified Firebase user
#[derive(Debug, Clone)]
pub struct FirebaseAuthUser {
    /// User's unique ID (from sub claim)
    pub uid: String,
    /// Time when the token was issued
    pub issued_at: OffsetDateTime,
    /// Time when the token expires
    pub expires_at: OffsetDateTime,
    /// Time when the user was authenticated
    pub auth_time: OffsetDateTime,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct FirebaseGoogleTokenPayload {
    pub name: Option<String>,
    pub picture: Option<String>,
    pub iss: Option<String>,
    pub aud: Option<String>,
    pub auth_time: Option<u64>,
    pub user_id: Option<String>,
    pub sub: Option<String>,
    pub iat: Option<u64>,
    pub exp: Option<u64>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub firebase: Option<FirebaseGoogleUserData>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirebaseGoogleUserData {
    pub identities: Option<HashMap<String, Vec<String>>>,
    pub sign_in_provider: Option<String>,
}


/// Main struct for Firebase Authentication operations
#[derive(Debug)]
pub struct FirebaseAuth {
    /// Configuration for Firebase Authentication
    pub config: FirebaseAuthConfig,
    /// Cached public keys with their expiration time
    pub cached_public_keys: Arc<RwLock<Option<SharedState>>>,
}

/// Custom error types for Firebase Authentication
#[derive(Debug)]
pub enum FirebaseAuthError {
    InvalidTokenFormat,
    TokenExpired,
    InvalidSignature,
    InvalidIssuer,
    InvalidAudience,
    InvalidSubject,
    InvalidAuthTime,
    HttpError(String),
    JwtError(String),
}

// Implement Display trait for FirebaseAuthError
impl fmt::Display for FirebaseAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FirebaseAuthError::InvalidTokenFormat => write!(f, "Invalid token format"),
            FirebaseAuthError::TokenExpired => write!(f, "Token expired"),
            FirebaseAuthError::InvalidSignature => write!(f, "Invalid signature"),
            FirebaseAuthError::InvalidIssuer => write!(f, "Invalid issuer"),
            FirebaseAuthError::InvalidAudience => write!(f, "Invalid audience"),
            FirebaseAuthError::InvalidSubject => write!(f, "Invalid subject"),
            FirebaseAuthError::InvalidAuthTime => write!(f, "Invalid authentication time"),
            FirebaseAuthError::HttpError(msg) => write!(f, "HTTP request failed: {}", msg),
            FirebaseAuthError::JwtError(msg) => write!(f, "JWT error: {}", msg),
        }
    }
}

// Implement Error trait for FirebaseAuthError
impl Error for FirebaseAuthError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

// Type alias for Result with FirebaseAuthError
pub type FirebaseAuthResult<T> = Result<T, FirebaseAuthError>;

/// Trait for token verification
pub trait TokenVerifier {
    fn verify(&self, project_id: &str, current_time: OffsetDateTime) -> FirebaseAuthResult<()>;
    fn to_auth_user(&self) -> FirebaseAuthUser;
}

impl TokenVerifier for FirebaseTokenPayload {
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

impl TokenVerifier for FirebaseGoogleTokenPayload {
    fn verify(&self, project_id: &str, current_time: OffsetDateTime) -> FirebaseAuthResult<()> {
        // Verify expiration time
        if let Some(exp) = self.exp {
            if (exp as i64) <= current_time.unix_timestamp() {
                return Err(FirebaseAuthError::TokenExpired);
            }
        }

        // Verify issued at time
        if let Some(iat) = self.iat {
            if (iat as i64) >= current_time.unix_timestamp() {
                return Err(FirebaseAuthError::InvalidTokenFormat);
            }
        }

        // Verify authentication time
        if let Some(auth_time) = self.auth_time {
            if (auth_time as i64) >= current_time.unix_timestamp() {
                return Err(FirebaseAuthError::InvalidAuthTime);
            }
        }

        // Verify audience
        if let Some(aud) = &self.aud {
            if aud != project_id {
                return Err(FirebaseAuthError::InvalidAudience);
            }
        }

        // Verify issuer
        if let Some(iss) = &self.iss {
            let expected_issuer = format!("https://securetoken.google.com/{}", project_id);
            if iss != &expected_issuer {
                return Err(FirebaseAuthError::InvalidIssuer);
            }
        }

        // Verify subject
        if let Some(sub) = &self.sub {
            if sub.is_empty() {
                return Err(FirebaseAuthError::InvalidSubject);
            }
        } else {
            return Err(FirebaseAuthError::InvalidSubject);
        }

        Ok(())
    }

    fn to_auth_user(&self) -> FirebaseAuthUser {
        FirebaseAuthUser {
            uid: self.sub.clone().unwrap_or_default(),
            issued_at: OffsetDateTime::from_unix_timestamp(self.iat.unwrap_or(0) as i64)
                .unwrap_or_else(|_| OffsetDateTime::now_utc()),
            expires_at: OffsetDateTime::from_unix_timestamp(self.exp.unwrap_or(0) as i64)
                .unwrap_or_else(|_| OffsetDateTime::now_utc()),
            auth_time: OffsetDateTime::from_unix_timestamp(self.auth_time.unwrap_or(0) as i64)
                .unwrap_or_else(|_| OffsetDateTime::now_utc()),
        }
    }
}