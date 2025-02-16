use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared state for caching public keys
#[derive(Debug, Clone)]
pub struct SharedState {
    pub keys: PublicKeysResponse,
    pub expiry: i64,  // Unix timestamp
}

/// Firebase normal user authentication payload
#[derive(Debug, Serialize, Deserialize)]
pub struct FirebaseAuthUser {
    pub exp: i64,
    pub iat: i64,
    pub aud: String,
    pub iss: String,
    pub sub: String,
    pub auth_time: i64,
}

/// Firebase Google user authentication payload
#[derive(Debug, Serialize, Deserialize)]
pub struct FirebaseAuthGoogleUser {
    pub name: Option<String>,
    pub picture: Option<String>,
    pub iss: Option<String>,
    pub aud: Option<String>,
    pub auth_time: Option<i64>,
    pub user_id: Option<String>,
    pub sub: Option<String>,
    pub iat: Option<i64>,
    pub exp: Option<i64>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub firebase: Option<FirebaseGoogleUserData>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirebaseGoogleUserData {
    pub identities: Option<HashMap<String, Vec<String>>>,
    pub sign_in_provider: Option<String>,
}

/// Represents the header of a Firebase ID token as specified in the documentation
#[derive(Debug, Deserialize, Serialize)]
pub struct FirebaseTokenHeader {
    /// Algorithm used for the token signature (must be "RS256")
    pub alg: String,
    /// Key ID corresponding to the public key used for signature verification
    pub kid: String,
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
    fn verify(&self, project_id: &str, current_time: i64) -> FirebaseAuthResult<()>;
}

impl TokenVerifier for FirebaseAuthUser {
    fn verify(&self, project_id: &str, current_time: i64) -> FirebaseAuthResult<()> {
        if self.exp <= current_time {
            return Err(FirebaseAuthError::TokenExpired);
        }

        if self.iat >= current_time {
            return Err(FirebaseAuthError::InvalidTokenFormat);
        }

        if self.auth_time >= current_time {
            return Err(FirebaseAuthError::InvalidAuthTime);
        }

        if self.aud != project_id {
            return Err(FirebaseAuthError::InvalidAudience);
        }

        let expected_issuer = format!("https://securetoken.google.com/{}", project_id);
        if self.iss != expected_issuer {
            return Err(FirebaseAuthError::InvalidIssuer);
        }

        if self.sub.is_empty() {
            return Err(FirebaseAuthError::InvalidSubject);
        }

        Ok(())
    }
}

impl TokenVerifier for FirebaseAuthGoogleUser {
    fn verify(&self, project_id: &str, current_time: i64) -> FirebaseAuthResult<()> {
        if let Some(exp) = self.exp {
            if exp <= current_time {
                return Err(FirebaseAuthError::TokenExpired);
            }
        }

        if let Some(iat) = self.iat {
            if iat >= current_time {
                return Err(FirebaseAuthError::InvalidTokenFormat);
            }
        }

        if let Some(auth_time) = self.auth_time {
            if auth_time >= current_time {
                return Err(FirebaseAuthError::InvalidAuthTime);
            }
        }

        if let Some(aud) = &self.aud {
            if aud != project_id {
                return Err(FirebaseAuthError::InvalidAudience);
            }
        }

        if let Some(iss) = &self.iss {
            let expected_issuer = format!("https://securetoken.google.com/{}", project_id);
            if iss != &expected_issuer {
                return Err(FirebaseAuthError::InvalidIssuer);
            }
        }

        if let Some(sub) = &self.sub {
            if sub.is_empty() {
                return Err(FirebaseAuthError::InvalidSubject);
            }
        } else {
            return Err(FirebaseAuthError::InvalidSubject);
        }

        Ok(())
    }
}