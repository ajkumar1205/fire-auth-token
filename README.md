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
fire-auth-token = "0.1.0"
```

```
use fire_auth_token::FirebaseAuth;

#[tokio::main]
async fn main() {
    let project_id = "your-project-id".to_string();
    let auth = FirebaseAuth::new(project_id).await;
    let token = "your-firebase-id-token";
    
    match auth.verify_token(token).await {
        Ok(user) => println!("Authenticated user: {:?}", user),
        Err(e) => eprintln!("Token verification failed: {:?}", e),
    }
}
```
