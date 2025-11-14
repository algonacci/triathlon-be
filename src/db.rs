use crate::config::Config;
use sqlx::{MySql, Pool};

pub async fn get_db_pool() -> Pool<MySql> {
    let config = Config::from_env();

    Pool::connect(&config.database_url)
        .await
        .expect("Failed to create connection pool")
}
