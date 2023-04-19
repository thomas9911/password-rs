use crate::bcrypt_copy;
use bcrypt::BcryptError;
use password_hash::errors::{B64Error, InvalidValue};
use password_hash::{Decimal, Error, Ident, ParamsString, PasswordHash, PasswordHasher, Salt};
use base64::Engine;

pub const BCRYTP_2A_IDENT: Ident<'static> = Ident::new_unwrap("2a");
pub const BCRYTP_2X_IDENT: Ident<'static> = Ident::new_unwrap("2x");
pub const BCRYTP_2Y_IDENT: Ident<'static> = Ident::new_unwrap("2y");
pub const BCRYTP_2B_IDENT: Ident<'static> = Ident::new_unwrap("2b");


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

// impl<'a> From<&'a PasswordHash<'a>> for BcryptWrapperParams {

// }

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
        // let encoded_params = value.try_into()?;

        // Ok(PasswordHash{
        //     algorithm: Ident::new_unwrap("2b"),
        //     version: None,
        //     params: encoded_params,
        //     salt: None,
        //     hash: None,
        // })
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
        version: Option<Decimal>,
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

        let bytes = bcrypt::BASE_64.decode(salt.as_str()).map_err(|_| Error::B64Encoding(B64Error::InvalidEncoding))?;

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
            BcryptSubversion::A => BCRYTP_2A_IDENT,
            BcryptSubversion::X => BCRYTP_2X_IDENT,
            BcryptSubversion::Y => BCRYTP_2Y_IDENT,
            BcryptSubversion::B => BCRYTP_2B_IDENT,
        }
    }

    fn find_algorithm(
        options: &password_hash::PasswordHash<'_>,
    ) -> Result<Box<dyn password_hash::PasswordVerifier>, String> {
        if [
            BCRYTP_2A_IDENT,
            BCRYTP_2X_IDENT,
            BCRYTP_2Y_IDENT,
            BCRYTP_2B_IDENT
        ]
        .contains(&options.algorithm)
        {
            Ok(Box::new(BcryptWrapper))
        } else {
            Err(String::from("invalid algorithm"))
        }
    }
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
        } else {
            Err("invalid bcrypt identifier")
        }
    }
}
