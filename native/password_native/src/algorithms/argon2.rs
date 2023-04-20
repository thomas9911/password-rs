use argon2::Argon2;
use password_hash::{Ident, PasswordHasher, Salt};
use std::collections::HashMap;

pub enum Argon2Subversion {
    I,
    D,
    Id,
}

impl Argon2Subversion {
    fn to_argon2_version(&self) -> argon2::Algorithm {
        match self {
            Argon2Subversion::I => argon2::Algorithm::Argon2i,
            Argon2Subversion::D => argon2::Algorithm::Argon2d,
            Argon2Subversion::Id => argon2::Algorithm::Argon2id,
        }
    }
}

impl crate::PasswordVersion for Argon2Subversion {
    fn identifier(&self) -> Ident {
        match self {
            Argon2Subversion::I => argon2::ARGON2I_IDENT,
            Argon2Subversion::D => argon2::ARGON2D_IDENT,
            Argon2Subversion::Id => argon2::ARGON2ID_IDENT,
        }
    }

    fn from_identifier(identifier: Ident) -> Option<Self> {
        match identifier {
            argon2::ARGON2I_IDENT => Some(Argon2Subversion::I),
            argon2::ARGON2D_IDENT => Some(Argon2Subversion::D),
            argon2::ARGON2ID_IDENT => Some(Argon2Subversion::Id),
            _ => None,
        }
    }

    fn find_algorithm_verifier(
        algorithm: &password_hash::Ident,
    ) -> Result<Box<dyn password_hash::PasswordVerifier>, String> {
        if [
            argon2::ARGON2I_IDENT,
            argon2::ARGON2D_IDENT,
            argon2::ARGON2ID_IDENT,
        ]
        .contains(algorithm)
        {
            Ok(Box::new(argon2::Argon2::default()))
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
        let mut builder = argon2::ParamsBuilder::new();

        if let Some(m) = options.get("m") {
            builder.m_cost(*m);
        };

        if let Some(t) = options.get("t") {
            builder.t_cost(*t);
        };

        if let Some(p) = options.get("p") {
            builder.p_cost(*p);
        };

        let params = builder.build().map_err(|err| err.to_string())?;
        let algo_version = self.to_argon2_version();

        let argon2 = Argon2::new(algo_version, argon2::Version::default(), params);
        let password_struct = argon2
            .hash_password(password.as_bytes(), salt)
            .map_err(|err| err.to_string())?;
        Ok(password_struct.to_string())
    }
}

impl std::str::FromStr for Argon2Subversion {
    type Err = &'static str;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if argon2::ARGON2ID_IDENT.as_str() == input {
            Ok(Argon2Subversion::Id)
        } else if argon2::ARGON2I_IDENT.as_str() == input {
            Ok(Argon2Subversion::I)
        } else if argon2::ARGON2D_IDENT.as_str() == input {
            Ok(Argon2Subversion::D)
        } else {
            Err("invalid argon2 identifier")
        }
    }
}
