use actix_cors::Cors;
use actix_web::{App, HttpServer, web};

mod auth;
mod config;
mod db;
mod index;
mod logging;
mod response;
mod middleware;

use crate::index::get_index;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    logging::init_logger();
    let config = config::Config::from_env();
    let pool = db::get_db_pool().await;
    log::info!(
        "Starting server at {}:{}",
        config.server_host,
        config.server_port
    );
    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(cors)
            .wrap(logging::get_logger())
            .route("/", web::get().to(get_index))
            .service(auth::register::register)
            .service(auth::login::login)
            .service(auth::logout::logout)
    })
    .bind(format!("{}:{}", config.server_host, config.server_port))?
    .run()
    .await
}
