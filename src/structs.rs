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