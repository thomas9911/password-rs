use crate::bcrypt_copy;
use base64::Engine;
use bcrypt::BcryptError;
use password_hash::errors::{B64Error, InvalidValue};
use password_hash::{Decimal, Error, Ident, ParamsString, PasswordHash, PasswordHasher, Salt};
use std::collections::HashMap;

pub const BCRYPT_2A_IDENT: Ident<'static> = Ident::new_unwrap("2a");
pub const BCRYPT_2X_IDENT: Ident<'static> = Ident::new_unwrap("2x");
pub const BCRYPT_2Y_IDENT: Ident<'static> = Ident::new_unwrap("2y");
pub const BCRYPT_2B_IDENT: Ident<'static> = Ident::new_unwrap("2b");

pub enum BcryptSubversion {
    A,
    X,
    Y,
    B,
}

#[derive(Debug, Clone)]
pub struct BcryptWrapper;

#[derive(Debug, Clone)]
pub struct BcryptWrapperParams {
    pub cost: u32,
}

impl Default for BcryptWrapperParams {
    fn default() -> BcryptWrapperParams {
        BcryptWrapperParams {
            cost: bcrypt::DEFAULT_COST,
        }
    }
}

impl TryInto<ParamsString> for BcryptWrapperParams {
    type Error = Error;

    fn try_into(self) -> Result<ParamsString, Self::Error> {
        let mut encoded_params = ParamsString::new();
        encoded_params
            .add_decimal(Ident::new_unwrap("cost"), self.cost)
            .map_err(|_err| Error::ParamValueInvalid(InvalidValue::Malformed))?;

        Ok(encoded_params)
    }
}

impl<'a> TryFrom<&'a PasswordHash<'a>> for BcryptWrapperParams {
    type Error = Error;

    fn try_from(value: &'a PasswordHash<'a>) -> Result<Self, Self::Error> {
        let cost = value
            .params
            .get_decimal("cost")
            .ok_or(Error::ParamNameInvalid)?;
        Ok(BcryptWrapperParams { cost })
    }
}

impl PasswordHasher for BcryptWrapper {
    type Params = BcryptWrapperParams;

    fn hash_password_customized<'a>(
        &self,
        password: &[u8],
        algorithm: Option<Ident<'a>>,
        _version: Option<Decimal>,
        params: Self::Params,
        salt: impl Into<Salt<'a>>,
    ) -> Result<PasswordHash<'a>, Error> {
        let algorithm = if let Some(algorithm) = algorithm {
            algorithm
        } else {
            return Err(Error::Algorithm);
        };

        let mut encoded_params = password_hash::ParamsString::new();
        encoded_params
            .add_decimal(Ident::new_unwrap("cost"), params.cost)
            .map_err(|_err| Error::ParamValueInvalid(InvalidValue::Malformed))?;

        let salt: Salt = salt.into();
        let mut salt_buffer = [0; 16];
        // decode weird base64 thing
        let bytes = bcrypt::BASE_64.decode(salt.as_str()).map_err(|err| {
            dbg!(err);
            Error::B64Encoding(B64Error::InvalidEncoding)
        })?;

        if bytes.len() != 16 {
            return Err(Error::SaltInvalid(InvalidValue::Malformed));
        }
        salt_buffer.copy_from_slice(&bytes);

        let parts = bcrypt::hash_with_salt(password, params.cost, salt_buffer)
            .map_err(map_bcrypt_error_to_password_hash_error)?;
        let hashed = parts.to_string();
        let parts =
            bcrypt_copy::split_hash(&hashed).map_err(map_bcrypt_error_to_password_hash_error)?;
        let hashx = password_hash::Output::decode(&parts.hash, password_hash::Encoding::Bcrypt)
            .map_err(|_| Error::B64Encoding(B64Error::InvalidEncoding))?;

        Ok(PasswordHash {
            algorithm,
            version: None,
            params: encoded_params,
            salt: Some(salt),
            hash: Some(hashx),
        })
    }
}

fn map_bcrypt_error_to_password_hash_error(err: BcryptError) -> Error {
    use BcryptError::*;

    match err {
        Io(_) => Error::Crypto,
        CostNotAllowed(_) => Error::ParamValueInvalid(InvalidValue::Malformed),
        InvalidCost(_) => Error::ParamValueInvalid(InvalidValue::Malformed),
        InvalidPrefix(_) => Error::Algorithm,
        InvalidHash(_) => Error::Password,
        InvalidSaltLen(_) => Error::SaltInvalid(InvalidValue::Malformed),
        InvalidBase64(_) => Error::B64Encoding(B64Error::InvalidEncoding),
        Rand(_) => Error::Crypto,
    }
}

impl crate::PasswordVersion for BcryptSubversion {
    fn identifier(&self) -> Ident {
        match self {
            BcryptSubversion::A => BCRYPT_2A_IDENT,
            BcryptSubversion::X => BCRYPT_2X_IDENT,
            BcryptSubversion::Y => BCRYPT_2Y_IDENT,
            BcryptSubversion::B => BCRYPT_2B_IDENT,
        }
    }

    fn from_identifier(identifier: Ident) -> Option<Self> {
        match identifier {
            BCRYPT_2A_IDENT => Some(BcryptSubversion::A),
            BCRYPT_2X_IDENT => Some(BcryptSubversion::X),
            BCRYPT_2Y_IDENT => Some(BcryptSubversion::Y),
            BCRYPT_2B_IDENT => Some(BcryptSubversion::B),
            _ => None,
        }
    }

    fn find_algorithm_verifier(
        algorithm: &password_hash::Ident,
    ) -> Result<Box<dyn password_hash::PasswordVerifier>, String> {
        if [
            BCRYPT_2A_IDENT,
            BCRYPT_2X_IDENT,
            BCRYPT_2Y_IDENT,
            BCRYPT_2B_IDENT,
        ]
        .contains(algorithm)
        {
            Ok(Box::new(BcryptWrapper))
        } else {
            Err(String::from("invalid algorithm"))
        }
    }

    fn hash_password(
        &self,
        password: &str,
        salt: Salt,
        options: HashMap<String, u32>,
    ) -> Result<String, String> {
        let cost = *options.get("cost").unwrap_or(&bcrypt::DEFAULT_COST);
        let algorithm = self.identifier();
        let params = BcryptWrapperParams { cost };

        let password_struct = BcryptWrapper
            .hash_password_customized(password.as_bytes(), Some(algorithm), None, params, salt)
            .map_err(|err| err.to_string())?;

        Ok(format_mfc_format(password_struct))
    }
}

fn format_mfc_format(password_struct: PasswordHash) -> String {
    format!(
        "${}${:02}${}{}",
        password_struct.algorithm,
        password_struct
            .params
            .get_decimal("cost")
            .unwrap_or(bcrypt::DEFAULT_COST),
        password_struct.salt.expect("salt is missing"),
        password_struct.hash.expect("hash is missing")
    )
}

impl std::str::FromStr for BcryptSubversion {
    type Err = &'static str;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if "2a" == input {
            Ok(BcryptSubversion::A)
        } else if "2x" == input {
            Ok(BcryptSubversion::X)
        } else if "2y" == input {
            Ok(BcryptSubversion::Y)
        } else if "2b" == input {
            Ok(BcryptSubversion::B)
        } else if "bcrypt" == input {
            Ok(BcryptSubversion::B)
        } else {
            Err("invalid bcrypt identifier")
        }
    }
}
