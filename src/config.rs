#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub client_origin: String,

    pub access_token_private_key: String,
    pub access_token_public_key: String,
    pub access_token_expires_in: String,
    pub access_token_max_age: i64,

    pub refresh_token_private_key: String,
    pub refresh_token_public_key: String,
    pub refresh_token_expires_in: String,
    pub refresh_token_max_age: i64,
}

impl Config {
    pub fn init() -> Config {
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
        let client_origin = std::env::var("CLIENT_ORIGIN").expect("CLIENT_ORIGIN must be set");
        let access_token_private_key = std::env::var("ACCESS_TOKEN_PRIVATE_KEY")
            .expect("ACCESS_TOKEN_PRIVATE_KEY must be set");
        let access_token_public_key =
            std::env::var("ACCESS_TOKEN_PUBLIC_KEY").expect("ACCESS_TOKEN_PUBLIC_KEY must be set");
        let refresh_token_private_key = std::env::var("REFRESH_TOKEN_PRIVATE_KEY")
            .expect("REFRESH_TOKEN_PRIVATE_KEY must be set");
        let refresh_token_public_key = std::env::var("REFRESH_TOKEN_PUBLIC_KEY")
            .expect("REFRESH_TOKEN_PUBLIC_KEY must be set");
        let access_token_expires_in =
            std::env::var("ACCESS_TOKEN_EXPIRED_IN").expect("ACCESS_TOKEN_EXPIRED_IN must be set");
        let refresh_token_expires_in = std::env::var("REFRESH_TOKEN_EXPIRED_IN")
            .expect("REFRESH_TOKEN_EXPIRED_IN must be set");
        let access_token_max_age =
            std::env::var("ACCESS_TOKEN_MAXAGE").expect("ACCESS_TOKEN_MAXAGE must be set");
        let refresh_token_max_age =
            std::env::var("REFRESH_TOKEN_MAXAGE").expect("REFRESH_TOKEN_MAXAGE must be set");
        Config {
            database_url,
            redis_url,
            client_origin,
            access_token_private_key,
            access_token_public_key,
            refresh_token_private_key,
            refresh_token_public_key,
            access_token_expires_in,
            refresh_token_expires_in,
            access_token_max_age: access_token_max_age.parse::<i64>().unwrap(),
            refresh_token_max_age: refresh_token_max_age.parse::<i64>().unwrap(),
        }
    }
}
