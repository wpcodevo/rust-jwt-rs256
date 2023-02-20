use core::fmt;
use std::future::{ready, Ready};

use actix_web::error::{ErrorInternalServerError, ErrorUnauthorized};
use actix_web::{dev::Payload, Error as ActixWebError};
use actix_web::{http, web, FromRequest, HttpRequest};
use futures::executor::block_on;
use redis::Commands;
use serde::{Deserialize, Serialize};

use crate::model::User;
use crate::token;
use crate::AppState;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    status: String,
    message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtMiddleware {
    pub user: User,
    pub access_token_uuid: uuid::Uuid,
}

impl FromRequest for JwtMiddleware {
    type Error = ActixWebError;
    type Future = Ready<Result<Self, Self::Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let data = req.app_data::<web::Data<AppState>>().unwrap();

        let access_token = req
            .cookie("access_token")
            .map(|c| c.value().to_string())
            .or_else(|| {
                req.headers()
                    .get(http::header::AUTHORIZATION)
                    .map(|h| h.to_str().unwrap().split_at(7).1.to_string())
            });

        if access_token.is_none() {
            let json_error = ErrorResponse {
                status: "fail".to_string(),
                message: "You are not logged in, please provide token".to_string(),
            };
            return ready(Err(ErrorUnauthorized(json_error)));
        }

        let access_token_details = match token::verify_jwt_token(
            data.env.access_token_public_key.to_owned(),
            &access_token.unwrap(),
        ) {
            Ok(token_details) => token_details,
            Err(e) => {
                let json_error = ErrorResponse {
                    status: "fail".to_string(),
                    message: format!("{:?}", e),
                };
                return ready(Err(ErrorUnauthorized(json_error)));
            }
        };

        let access_token_uuid =
            uuid::Uuid::parse_str(&access_token_details.token_uuid.to_string()).unwrap();

        let user_id_redis_result = async move {
            let mut redis_client = match data.redis_client.get_connection() {
                Ok(redis_client) => redis_client,
                Err(e) => {
                    return Err(ErrorInternalServerError(ErrorResponse {
                        status: "fail".to_string(),
                        message: format!("Could not connect to Redis: {}", e),
                    }));
                }
            };

            let redis_result = redis_client.get::<_, String>(access_token_uuid.clone().to_string());

            match redis_result {
                Ok(value) => Ok(value),
                Err(_) => Err(ErrorUnauthorized(ErrorResponse {
                    status: "fail".to_string(),
                    message: "Token is invalid or session has expired".to_string(),
                })),
            }
        };

        let user_exists_result = async move {
            let user_id = user_id_redis_result.await?;
            let user_id_uuid = uuid::Uuid::parse_str(user_id.as_str()).unwrap();

            let query_result =
                sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id_uuid)
                    .fetch_optional(&data.db)
                    .await;

            match query_result {
                Ok(Some(user)) => Ok(user),
                Ok(None) => {
                    let json_error = ErrorResponse {
                        status: "fail".to_string(),
                        message: "the user belonging to this token no logger exists".to_string(),
                    };
                    Err(ErrorUnauthorized(json_error))
                }
                Err(_) => {
                    let json_error = ErrorResponse {
                        status: "error".to_string(),
                        message: "Faled to check user existence".to_string(),
                    };
                    Err(ErrorInternalServerError(json_error))
                }
            }
        };

        match block_on(user_exists_result) {
            Ok(user) => ready(Ok(JwtMiddleware {
                access_token_uuid,
                user,
            })),
            Err(error) => ready(Err(error)),
        }
    }
}
