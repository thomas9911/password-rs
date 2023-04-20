use std::collections::HashMap;

use password_hash::Salt;

pub enum Pbkdf2Subversion {
    Sha1,
    Sha256,
    Sha512,
}

impl crate::PasswordVersion for Pbkdf2Subversion {
    fn identifier(&self) -> password_hash::Ident {
        match self {
            Pbkdf2Subversion::Sha1 => pbkdf2::Algorithm::PBKDF2_SHA1_IDENT,
            Pbkdf2Subversion::Sha256 => pbkdf2::Algorithm::PBKDF2_SHA256_IDENT,
            Pbkdf2Subversion::Sha512 => pbkdf2::Algorithm::PBKDF2_SHA512_IDENT,
        }
    }

    fn from_identifier(identifier: password_hash::Ident) -> Option<Self> {
        match identifier {
            pbkdf2::Algorithm::PBKDF2_SHA1_IDENT => Some(Pbkdf2Subversion::Sha1),
            pbkdf2::Algorithm::PBKDF2_SHA256_IDENT => Some(Pbkdf2Subversion::Sha256),
            pbkdf2::Algorithm::PBKDF2_SHA512_IDENT => Some(Pbkdf2Subversion::Sha512),
            _ => None,
        }
    }

    fn find_algorithm_verifier(
        algorithm: &password_hash::Ident,
    ) -> Result<Box<dyn password_hash::PasswordVerifier>, String> {
        if [
            pbkdf2::Algorithm::PBKDF2_SHA1_IDENT,
            pbkdf2::Algorithm::PBKDF2_SHA256_IDENT,
            pbkdf2::Algorithm::PBKDF2_SHA512_IDENT,
        ]
        .contains(algorithm)
        {
            Ok(Box::new(pbkdf2::Pbkdf2))
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
        Ok(String::from("oke"))
    }
}

impl std::str::FromStr for Pbkdf2Subversion {
    type Err = &'static str;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if pbkdf2::Algorithm::PBKDF2_SHA1_IDENT.as_str() == input {
            Ok(Pbkdf2Subversion::Sha1)
        } else if pbkdf2::Algorithm::PBKDF2_SHA256_IDENT.as_str() == input {
            Ok(Pbkdf2Subversion::Sha256)
        } else if pbkdf2::Algorithm::PBKDF2_SHA512_IDENT.as_str() == input {
            Ok(Pbkdf2Subversion::Sha512)
        } else {
            Err("invalid pbkdf2 identifier")
        }
    }
}
