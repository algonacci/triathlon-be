use crate::response::Response;
use actix_web::{HttpResponse, post, web};
use bcrypt::{DEFAULT_COST, hash};
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;

#[derive(Deserialize)]
pub struct RegisterRequest {
    name: String,
    username: String,
    email: String,
    password: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    username: String,
    email: String,
}

#[post("/auth/register")]
pub async fn register(
    user: web::Json<RegisterRequest>,
    pool: web::Data<MySqlPool>,
) -> HttpResponse {
    let existing_user = sqlx::query!(
        "SELECT username, email FROM users WHERE username = ? OR email = ?",
        user.username,
        user.email
    )
    .fetch_optional(pool.get_ref())
    .await;

    match existing_user {
        Ok(Some(_)) => {
            return HttpResponse::Conflict().json(Response {
                message: "Username or email already exists".to_string(),
                data: None::<RegisterResponse>,
            });
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(Response {
                message: "Database error".to_string(),
                data: None::<RegisterResponse>,
            });
        }
        Ok(None) => {}
    }

    let hashed_password = match hash(user.password.as_bytes(), DEFAULT_COST) {
        Ok(hashed) => hashed,
        Err(_) => {
            return HttpResponse::InternalServerError().json(Response {
                message: "Password hasing failed".to_string(),
                data: None::<RegisterResponse>,
            });
        }
    };

    let result = sqlx::query!(
        "INSERT INTO users (email, password_hash, name, username) VALUES (?, ?, ?, ?)",
        user.email,
        hashed_password,
        user.name,
        user.username,
    )
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(Response {
            message: "User registered successfully".to_string(),
            data: Some(RegisterResponse {
                username: user.username.clone(),
                email: user.email.clone(),
            }),
        }),
        Err(e) => {
            if e.to_string().contains("Duplicate entry") {
                HttpResponse::Conflict().json(Response {
                    message: "Username or email already exists".to_string(),
                    data: None::<RegisterResponse>,
                })
            } else {
                HttpResponse::InternalServerError().json(Response {
                    message: "Failed to register user".to_string(),
                    data: None::<RegisterResponse>,
                })
            }
        }
    }
}
