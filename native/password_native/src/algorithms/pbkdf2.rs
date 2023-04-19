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

    fn find_algorithm(
        options: &password_hash::PasswordHash<'_>,
    ) -> Result<Box<dyn password_hash::PasswordVerifier>, String> {
        if [
            pbkdf2::Algorithm::PBKDF2_SHA1_IDENT,
            pbkdf2::Algorithm::PBKDF2_SHA256_IDENT,
            pbkdf2::Algorithm::PBKDF2_SHA512_IDENT,
        ]
        .contains(&options.algorithm)
        {
            Ok(Box::new(pbkdf2::Pbkdf2))
        } else {
            Err(String::from("invalid algorithm"))
        }
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
