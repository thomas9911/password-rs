// #[test]
// fn asdf() {
//     use scrypt::{
//         password_hash::{
//             rand_core::OsRng,
//             PasswordHash, PasswordHasher, PasswordVerifier, SaltString
//         },
//         Scrypt
//     };

//     let password = b"testing1234"; // Bad password; don't actually use!
//     let salt = SaltString::generate(&mut OsRng);
//     let params = scrypt::Params::new(10, 8, 1, 32).unwrap();

//     // Hash password to PHC string ($scrypt$...)
//     let password_hash = Scrypt.hash_password_customized(password, None, None, params, &salt).unwrap().to_string();

//     panic!("{}", password_hash);
// }

use password_hash::{PasswordHasher, Salt};
use std::collections::HashMap;

pub fn hash_password(
    password: &str,
    salt: Salt,
    options: HashMap<String, u32>,
) -> Result<String, String> {
    let log_n = *options
        .get("ln")
        .unwrap_or(&(scrypt::Params::RECOMMENDED_LOG_N as u32)) as u8;
    let r = *options.get("r").unwrap_or(&scrypt::Params::RECOMMENDED_R);
    let p = *options.get("p").unwrap_or(&scrypt::Params::RECOMMENDED_P);
    let len = scrypt::Params::RECOMMENDED_LEN;
    let params = scrypt::Params::new(log_n, r, p, len).map_err(|err| err.to_string())?;

    let password_struct = scrypt::Scrypt
        .hash_password_customized(password.as_bytes(), None, None, params, salt)
        .map_err(|err| err.to_string())?;
    Ok(password_struct.to_string())
}
