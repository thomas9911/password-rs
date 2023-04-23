#[cfg(feature = "bcrypt")]
use base64::Engine;

use password_hash::rand_core::OsRng;
use password_hash::{Ident, Salt};
use rustler::types::atom;
use rustler::{Env, NifResult, Term};
use std::collections::HashMap;

mod algorithms;
#[cfg(feature = "bcrypt")]
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

pub enum ErrorTuple<E> {
    Ok,
    Err(E),
}

impl<E> rustler::Encoder for ErrorTuple<E>
where
    E: std::fmt::Display + rustler::Encoder,
{
    fn encode<'c>(&self, env: Env<'c>) -> Term<'c> {
        match *self {
            ErrorTuple::Ok => atom::ok().encode(env),
            ErrorTuple::Err(ref err) => (atom::error().encode(env), err.encode(env)).encode(env),
        }
    }
}

impl<T, E> From<Result<T, E>> for ErrorTuple<E> {
    fn from(res: Result<T, E>) -> ErrorTuple<E> {
        match res {
            Ok(_) => ErrorTuple::Ok,
            Err(err) => ErrorTuple::Err(err),
        }
    }
}

pub trait PasswordVersion {
    fn identifier(&self) -> Ident;
    fn find_algorithm_verifier(
        algorithm: &Ident,
    ) -> Result<Box<dyn password_hash::PasswordVerifier>, String>;
    fn hash_password(
        &self,
        password: &str,
        salt: Salt,
        options: HashMap<String, u32>,
    ) -> Result<String, String>;
    fn from_identifier(identifier: Ident) -> Option<Self>
    where
        Self: Sized;
}

#[non_exhaustive]
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
    fn identifier(&self) -> Ident {
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

    fn from_identifier(identifier: Ident) -> Option<Self> {
        #[cfg(feature = "argon2")]
        if let Some(algo) = algorithms::argon2::Argon2Subversion::from_identifier(identifier) {
            return Some(Algorithm::Argon2(algo));
        }

        #[cfg(feature = "scrypt")]
        if identifier == scrypt::ALG_ID {
            return Some(Algorithm::Scrypt);
        }

        #[cfg(feature = "pbkdf2")]
        if let Some(algo) = algorithms::pbkdf2::Pbkdf2Subversion::from_identifier(identifier) {
            return Some(Algorithm::Pbkdf2(algo));
        }

        #[cfg(feature = "bcrypt")]
        if let Some(algo) = algorithms::bcrypt::BcryptSubversion::from_identifier(identifier) {
            return Some(Algorithm::Bcrypt(algo));
        }

        None
    }

    fn find_algorithm_verifier(
        algorithm: &Ident,
    ) -> Result<Box<dyn password_hash::PasswordVerifier>, String> {
        #[cfg(feature = "argon2")]
        if let Ok(algo) = algorithms::argon2::Argon2Subversion::find_algorithm_verifier(algorithm) {
            return Ok(algo);
        }

        #[cfg(feature = "scrypt")]
        if algorithm == &scrypt::ALG_ID {
            return Ok(Box::new(scrypt::Scrypt));
        }

        #[cfg(feature = "pbkdf2")]
        if let Ok(algo) = algorithms::pbkdf2::Pbkdf2Subversion::find_algorithm_verifier(algorithm) {
            return Ok(algo);
        }

        #[cfg(feature = "bcrypt")]
        if let Ok(algo) = algorithms::bcrypt::BcryptSubversion::find_algorithm_verifier(algorithm) {
            return Ok(algo);
        }

        return Err(String::from("algorithm not found"));
    }

    fn hash_password(
        &self,
        password: &str,
        salt: Salt,
        options: HashMap<String, u32>,
    ) -> Result<String, String> {
        match self {
            #[cfg(feature = "argon2")]
            Algorithm::Argon2(argon2) => argon2.hash_password(password, salt, options),
            #[cfg(feature = "scrypt")]
            Algorithm::Scrypt => algorithms::scrypt::hash_password(password, salt, options),
            #[cfg(feature = "bcrypt")]
            Algorithm::Bcrypt(bcrypt) => bcrypt.hash_password(password, salt, options),
            #[cfg(feature = "pbkdf2")]
            Algorithm::Pbkdf2(pbkdf2) => pbkdf2.hash_password(password, salt, options),
        }
    }
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
    inner_hash_with(password, DEFAULT_ALG, None)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn hash_with(
    password: &str,
    algorithm: Algorithm,
    options: Option<HashMap<String, u32>>,
) -> Result<String, String> {
    inner_hash_with(password, algorithm, options)
}

fn inner_hash_with(
    password: &str,
    algorithm: Algorithm,
    options: Option<HashMap<String, u32>>,
) -> Result<String, String> {
    let options = options.unwrap_or(HashMap::new());

    #[cfg(feature = "bcrypt")]
    let salt_string = if let Algorithm::Bcrypt(_) = algorithm {
        use password_hash::rand_core::RngCore;

        // bcrypt uses non standard base64 encode and needs a salt that is 16 bytes
        let mut buffer = [0; 16];
        OsRng.fill_bytes(&mut buffer);
        let salt = bcrypt::BASE_64.encode(buffer);
        let salt = password_hash::SaltString::from_b64(&salt).map_err(|err| err.to_string())?;
        salt
    } else {
        password_hash::SaltString::generate(OsRng)
    };

    #[cfg(not(feature = "bcrypt"))]
    let salt_string = password_hash::SaltString::generate(OsRng);

    algorithm.hash_password(password, salt_string.as_salt(), options)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn verify(password: &str, hash_string: &str) -> ErrorTuple<String> {
    let password_struct_result = to_password_struct(hash_string);
    match password_struct_result {
        Ok(password_struct) => ErrorTuple::from(inner_verify(password, password_struct)),
        Err(e) => ErrorTuple::Err(e),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn verify_with(
    password: &str,
    hash_string: &str,
    algorithms: Vec<Algorithm>,
) -> ErrorTuple<String> {
    let password_struct_result = to_password_struct(hash_string);
    match password_struct_result {
        Ok(password_struct) => {
            if algorithms
                .iter()
                .find(|a| a.identifier() == password_struct.algorithm)
                .is_some()
            {
                ErrorTuple::from(inner_verify(password, password_struct))
            } else {
                ErrorTuple::Err(String::from("algorithm not in allowed list"))
            }
        }
        Err(e) => ErrorTuple::Err(e),
    }
}

fn inner_verify(
    password: &str,
    password_struct: password_hash::PasswordHash<'_>,
) -> Result<(), String> {
    let verifier = Algorithm::find_algorithm_verifier(&password_struct.algorithm)?;

    if let Err(err) = verifier.verify_password(password.as_bytes(), &password_struct) {
        Err(err.to_string())
    } else {
        Ok(())
    }
}

fn to_password_struct<'a>(hash_string: &'a str) -> Result<password_hash::PasswordHash<'a>, String> {
    #[cfg(feature = "bcrypt")]
    if let Ok(parts) = bcrypt_copy::split_hash(hash_string) {
        let mut params = password_hash::ParamsString::new();
        params
            .add_decimal(Ident::new_unwrap("cost"), parts.cost)
            .map_err(|err| err.to_string())?;
        let salt = password_hash::Salt::from_b64(&parts.salt).map_err(|err| err.to_string())?;
        let hashx = password_hash::Output::decode(&parts.hash, password_hash::Encoding::Bcrypt)
            .map_err(|err| err.to_string())?;

        return Ok(password_hash::PasswordHash {
            algorithm: Ident::new_unwrap(parts.version),
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

#[rustler::nif]
fn recommended_algorithms() -> Vec<Algorithm> {
    vec![
        #[cfg(feature = "argon2")]
        Algorithm::Argon2(algorithms::argon2::Argon2Subversion::Id),
        #[cfg(feature = "scrypt")]
        Algorithm::Scrypt,
    ]
}

rustler::init!(
    "Elixir.Password.Native",
    [
        hash,
        hash_with,
        verify,
        verify_with,
        known_algorithms,
        recommended_algorithms
    ]
);
