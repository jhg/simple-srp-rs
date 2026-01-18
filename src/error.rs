use std::fmt::{Display, Formatter};
use srp::AuthError;
use hex::FromHexError;

#[derive(Debug)]
pub enum SimpleSrpError {
    AuthError(AuthError),
    FromHexError(FromHexError),
}

impl From<AuthError> for SimpleSrpError {
    fn from(err: AuthError) -> Self {
        SimpleSrpError::AuthError(err)
    }
}

impl From<FromHexError> for SimpleSrpError {
    fn from(err: FromHexError) -> Self {
        SimpleSrpError::FromHexError(err)
    }
}

impl Display for SimpleSrpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SimpleSrpError::AuthError(e) => e as &dyn Display,
            SimpleSrpError::FromHexError(e) => e as &dyn Display,
        }.fmt(f)
    }
}

impl std::error::Error for SimpleSrpError {}
