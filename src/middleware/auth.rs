use actix_web::{dev::Payload, error::ErrorUnauthorized, web, Error, FromRequest, HttpRequest};
use futures::future::LocalBoxFuture;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[allow(dead_code)]
pub struct AuthenticatedUser {
    pub user_id: i32,
    pub role: String, // Add role field
}

impl FromRequest for AuthenticatedUser {
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Error>>; // <- Ubah Future ke LocalBoxFuture

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let auth_header = req.headers().get("Authorization").cloned();
        let pool = req.app_data::<web::Data<MySqlPool>>().cloned();

        Box::pin(async move {
            if let Some(auth_str) = auth_header {
                if let Ok(auth_str) = auth_str.to_str() {
                    if auth_str.starts_with("Bearer ") {
                        let token = auth_str[7..].to_string();

                        if let Ok(token_data) = decode::<Claims>(
                            &token,
                            &DecodingKey::from_secret(
                                std::env::var("JWT_SECRET").unwrap_or_default().as_bytes(),
                            ),
                            &Validation::new(Algorithm::HS256),
                        ) {
                            // Check token expiration explicitly
                            let current_time = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as usize;

                            if token_data.claims.exp < current_time {
                                return Err(ErrorUnauthorized("Token has expired"));
                            }

                            let user_id = token_data.claims.sub.parse().unwrap_or(0);
                            if user_id <= 0 {
                                return Err(ErrorUnauthorized("Invalid user ID"));
                            }

                            // Check if token is revoked
                            if let Some(pool) = pool {
                                if is_token_revoked(&token, pool.get_ref()).await {
                                    return Err(ErrorUnauthorized("Token has been revoked"));
                                }

                                // Fetch user role from database
                                let user =
                                    sqlx::query!("SELECT role FROM users WHERE id = ?", user_id)
                                        .fetch_optional(pool.get_ref())
                                        .await
                                        .map_err(|_| ErrorUnauthorized("Database error"))?
                                        .ok_or_else(|| ErrorUnauthorized("User not found"))?;

                                return Ok(AuthenticatedUser {
                                    user_id,
                                    role: user.role,
                                });
                            }
                        }
                    }
                }
            }
            Err(ErrorUnauthorized("Invalid token"))
        })
    }
}

async fn is_token_revoked(token: &str, pool: &MySqlPool) -> bool {
    let result = sqlx::query!("SELECT token FROM revoked_tokens WHERE token = ?", token)
        .fetch_optional(pool)
        .await;

    match result {
        Ok(Some(_)) => true, // Token ditemukan di database, berarti revoked
        _ => false,          // Token masih valid
    }
}