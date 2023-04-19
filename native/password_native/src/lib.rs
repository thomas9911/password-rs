use password_hash::Ident;
use rustler::{Env, NifResult, Term};

mod algorithms;
pub(crate) mod bcrypt_copy;

cfg_if::cfg_if! {
    if #[cfg(feature = "argon2")] {
        const DEFAULT_ALG: Algorithm = Algorithm::Argon2(algorithms::argon2::Argon2Subversion::Id);
    } else if #[cfg(feature = "scrypt")] {
        const DEFAULT_ALG: Algorithm = Algorithm::Scrypt;
    } else if #[cfg(feature = "bcrypt")] {
        const DEFAULT_ALG: Algorithm = Algorithm::Bcrypt(algorithms::bcrypt::BcryptSubversion::B);
    } else if #[cfg(feature = "pbkdf2")] {
        const DEFAULT_ALG: Algorithm = Algorithm::Pbkdf2(algorithms::pbkdf2::Pbkdf2Subversion::Sha512);
    } else {
        compiler_error!("no algorithm compiled");
    }
}

pub enum Algorithm {
    #[cfg(feature = "argon2")]
    Argon2(algorithms::argon2::Argon2Subversion),
    #[cfg(feature = "scrypt")]
    Scrypt,
    #[cfg(feature = "pbkdf2")]
    Pbkdf2(algorithms::pbkdf2::Pbkdf2Subversion),
    #[cfg(feature = "bcrypt")]
    Bcrypt(algorithms::bcrypt::BcryptSubversion),
}


impl PasswordVersion for Algorithm {
    fn identifier(&self) -> password_hash::Ident {
        match self {
            #[cfg(feature = "argon2")]
            Algorithm::Argon2(version) => version.identifier(),
            #[cfg(feature = "scrypt")]
            Algorithm::Scrypt => scrypt::ALG_ID,
            #[cfg(feature = "pbkdf2")]
            Algorithm::Pbkdf2(version) => version.identifier(),
            #[cfg(feature = "bcrypt")]
            Algorithm::Bcrypt(version) => version.identifier(),
            _ => unreachable!(),
        }
    }

    fn find_algorithm(
        options: &password_hash::PasswordHash<'_>,
    ) -> Result<Box<dyn password_hash::PasswordVerifier>, String> {
        #[cfg(feature = "argon2")]
        if let Ok(algo) = algorithms::argon2::Argon2Subversion::find_algorithm(options) {
            dbg!("argon2");
            return Ok(algo);
        }

        #[cfg(feature = "scrypt")]
        if options.algorithm == scrypt::ALG_ID {
            dbg!("scrypt");
            return Ok(Box::new(scrypt::Scrypt));
        }

        #[cfg(feature = "pbkdf2")]
        if let Ok(algo) = algorithms::pbkdf2::Pbkdf2Subversion::find_algorithm(options) {
            dbg!("pbkdf2");
            return Ok(algo);
        }

        #[cfg(feature = "bcrypt")]
        if let Ok(algo) = algorithms::bcrypt::BcryptSubversion::find_algorithm(options) {
            dbg!("bcrypt");
            return Ok(algo);
        }

        return Err(String::from("algorithm not found"));
    }
}

pub trait PasswordVersion {
    fn identifier(&self) -> password_hash::Ident;
    fn find_algorithm(
        options: &password_hash::PasswordHash<'_>,
    ) -> Result<Box<dyn password_hash::PasswordVerifier>, String>;
}

impl<'a> rustler::Decoder<'a> for Algorithm {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let atom = term.atom_to_string()?;

        #[cfg(feature = "argon2")]
        if let Ok(algo) = atom.parse::<algorithms::argon2::Argon2Subversion>() {
            return Ok(Algorithm::Argon2(algo));
        }

        #[cfg(feature = "scrypt")]
        if scrypt::ALG_ID.as_str() == atom {
            return Ok(Algorithm::Scrypt);
        }

        #[cfg(feature = "pbkdf2")]
        if let Ok(algo) = atom.parse::<algorithms::pbkdf2::Pbkdf2Subversion>() {
            return Ok(Algorithm::Pbkdf2(algo));
        }

        #[cfg(feature = "bcrypt")]
        if let Ok(algo) = atom.parse::<algorithms::bcrypt::BcryptSubversion>() {
            return Ok(Algorithm::Bcrypt(algo));
        }

        Err(rustler::Error::BadArg)
    }
}

impl rustler::Encoder for Algorithm {
    fn encode<'a>(&self, env: Env<'a>) -> rustler::Term<'a> {
        rustler::Atom::from_str(env, self.identifier().as_str())
            .expect("algo identifier is always valid for an atom")
            .to_term(env)
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn hash(password: &str) -> Result<String, String> {
    inner_hash_with(password, DEFAULT_ALG)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn hash_with(password: &str, algorithm: Algorithm) -> Result<String, String> {
    inner_hash_with(password, algorithm)
}

fn inner_hash_with(password: &str, algorithm: Algorithm) -> Result<String, String> {
    Ok(String::from("oke"))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn verify(password: &str, hash_string: &str) -> Result<(), String> {
    let password_struct = to_password_struct(hash_string)?;
    inner_verify(password, password_struct)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn verify_with(
    password: &str,
    hash_string: &str,
    algorithms: Vec<Algorithm>,
) -> Result<bool, String> {
    Ok(false)
}

fn inner_verify(
    password: &str,
    password_struct: password_hash::PasswordHash<'_>,
) -> Result<(), String> {
    let verifier = Algorithm::find_algorithm(&password_struct)?;

    if let Err(err) = verifier.verify_password(password.as_bytes(), &password_struct) {
        // dbg!(err);
        // Ok(false)
        Err(err.to_string())
    } else {
        Ok(())
    }
}

fn to_password_struct<'a>(hash_string: &'a str) -> Result<password_hash::PasswordHash<'a>, String> {
    if let Ok(parts) = bcrypt_copy::split_hash(hash_string) {
        let mut params = password_hash::ParamsString::new();
        params
            .add_decimal(Ident::new_unwrap("cost"), parts.cost)
            .map_err(|err| err.to_string())?;
        let salt = password_hash::Salt::from_b64(&parts.salt).map_err(|err| err.to_string())?;
        let hashx = password_hash::Output::decode(&parts.hash, password_hash::Encoding::Bcrypt)
            .map_err(|err| err.to_string())?;

        return Ok(password_hash::PasswordHash {
            algorithm: Ident::new_unwrap("2b"),
            version: None,
            params: params,
            salt: Some(salt),
            hash: Some(hashx),
        });
    }

    password_hash::PasswordHash::new(hash_string).map_err(|err| err.to_string())
}

#[rustler::nif]
fn known_algorithms() -> Vec<Algorithm> {
    vec![
        #[cfg(feature = "argon2")]
        Algorithm::Argon2(algorithms::argon2::Argon2Subversion::Id),
        #[cfg(feature = "argon2")]
        Algorithm::Argon2(algorithms::argon2::Argon2Subversion::I),
        #[cfg(feature = "argon2")]
        Algorithm::Argon2(algorithms::argon2::Argon2Subversion::D),
        #[cfg(feature = "scrypt")]
        Algorithm::Scrypt,
        #[cfg(feature = "bcrypt")]
        Algorithm::Bcrypt(algorithms::bcrypt::BcryptSubversion::B),
        #[cfg(feature = "bcrypt")]
        Algorithm::Bcrypt(algorithms::bcrypt::BcryptSubversion::Y),
        #[cfg(feature = "bcrypt")]
        Algorithm::Bcrypt(algorithms::bcrypt::BcryptSubversion::X),
        #[cfg(feature = "bcrypt")]
        Algorithm::Bcrypt(algorithms::bcrypt::BcryptSubversion::A),
        #[cfg(feature = "pbkdf2")]
        Algorithm::Pbkdf2(algorithms::pbkdf2::Pbkdf2Subversion::Sha512),
        #[cfg(feature = "pbkdf2")]
        Algorithm::Pbkdf2(algorithms::pbkdf2::Pbkdf2Subversion::Sha256),
        #[cfg(feature = "pbkdf2")]
        Algorithm::Pbkdf2(algorithms::pbkdf2::Pbkdf2Subversion::Sha1),
    ]
}

rustler::init!(
    "Elixir.Password.Native",
    [hash, hash_with, verify, verify_with, known_algorithms]
);
