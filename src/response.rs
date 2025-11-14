use serde::Serialize;

#[derive(Serialize)]
pub struct Response<T> {
    pub message: String,
    pub data: Option<T>,
}
