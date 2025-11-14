use crate::response::Response;
use actix_web::{HttpRequest, HttpResponse, post, web};
use sqlx::MySqlPool;

#[post("/auth/logout")]
pub async fn logout(req: HttpRequest, pool: web::Data<MySqlPool>) -> HttpResponse {
    let auth_header = req
        .headers()
        .get("Authorization")
        .unwrap()
        .to_str()
        .unwrap();

    let token = auth_header[7..].to_string();

    sqlx::query!("INSERT INTO revoked_tokens (token) VALUES (?)", token)
        .execute(pool.get_ref())
        .await
        .unwrap();

    HttpResponse::Ok().json(Response {
        message: "Logged out successfully".to_string(),
        data: None::<()>,
    })
}
