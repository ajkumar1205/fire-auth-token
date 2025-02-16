# Fire Auth Token

A Rust library for verifying Firebase ID tokens. It handles token validation, public key caching, and automatic background public key refresh using async operations.

## Features
- Verifies Firebase ID token claims
- Caches and refreshes public keys automatically
- Handles various error scenarios during token validation

## Installation
Add the package with Cargo:
```toml
[dependencies]
fire-auth-token = "0.1.2"
```
Or run 

`cargo add fire-auth-token`

```
use fire_auth_token::FirebaseAuth;

#[tokio::main]
async fn main() {
    let project_id = "your-project-id".to_string();
    let auth = FirebaseAuth::new(project_id).await;
    let token = "your-firebase-id-token";
    
    // For regular Firebase tokens
    let user = auth.verify_token::<FirebaseAuthUser>(token).await?;

    // For Google Firebase tokens
    let user = auth.verify_token::<FirebaseAuthGoogleUser>(token).await?;
}
```
