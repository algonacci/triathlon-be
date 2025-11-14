use crate::response::Response;
use actix_web::{Responder, web};

#[derive(serde::Serialize)]
struct HealthCheck {
    health: String,
}

pub async fn get_index() -> impl Responder {
    let response = Response::<HealthCheck> {
        message: "Hello, world!".to_string(),
        data: Some(HealthCheck {
            health: "OK".to_string(),
        }),
    };
    web::Json(response)
}
