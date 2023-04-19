pub enum Argon2Subversion {
    I,
    D,
    Id,
}

impl crate::PasswordVersion for Argon2Subversion {
    fn identifier(&self) -> password_hash::Ident {
        match self {
            Argon2Subversion::I => argon2::ARGON2I_IDENT,
            Argon2Subversion::D => argon2::ARGON2D_IDENT,
            Argon2Subversion::Id => argon2::ARGON2ID_IDENT,
        }
    }

    fn find_algorithm(
        options: &password_hash::PasswordHash<'_>,
    ) -> Result<Box<dyn password_hash::PasswordVerifier>, String> {
        if [
            argon2::ARGON2I_IDENT,
            argon2::ARGON2D_IDENT,
            argon2::ARGON2ID_IDENT,
        ]
        .contains(&options.algorithm)
        {
            Ok(Box::new(argon2::Argon2::default()))
        } else {
            Err(String::from("invalid algorithm"))
        }
    }
}

impl std::str::FromStr for Argon2Subversion {
    type Err = &'static str;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if argon2::ARGON2ID_IDENT.as_str() == input {
            Ok(Argon2Subversion::Id)
        } else if argon2::ARGON2I_IDENT.as_str() == input {
            Ok(Argon2Subversion::I)
        } else if argon2::ARGON2ID_IDENT.as_str() == input {
            Ok(Argon2Subversion::D)
        } else {
            Err("invalid argon2 identifier")
        }
    }
}
