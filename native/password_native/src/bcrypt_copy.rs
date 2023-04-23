//! copy paste from <https://github.com/Keats/rust-bcrypt/blob/master/src/lib.rs>
//! but make the hash parts fields public
//!

use bcrypt::{BcryptError, BcryptResult};

#[derive(Debug, PartialEq)]
/// A bcrypt hash result before concatenating
pub struct HashParts<'a> {
    pub cost: u32,
    pub version: &'a str,
    pub salt: &'a str,
    pub hash: &'a str,
}

/// Takes a full hash and split it into 3 parts:
/// cost, salt and hash
pub fn split_hash<'a>(hash: &'a str) -> BcryptResult<HashParts<'a>> {
    let mut parts = HashParts {
        cost: 0,
        version: "",
        salt: "",
        hash: "",
    };

    // Should be [prefix, cost, hash]
    let raw_parts: Vec<_> = hash.split('$').filter(|s| !s.is_empty()).collect();

    if raw_parts.len() != 3 {
        return Err(BcryptError::InvalidHash(hash.to_string()));
    }

    if raw_parts[0] != "2y" && raw_parts[0] != "2b" && raw_parts[0] != "2a" && raw_parts[0] != "2x"
    {
        return Err(BcryptError::InvalidPrefix(raw_parts[0].to_string()));
    }

    parts.version = raw_parts[0];

    if let Ok(c) = raw_parts[1].parse::<u32>() {
        parts.cost = c;
    } else {
        return Err(BcryptError::InvalidCost(raw_parts[1].to_string()));
    }

    if raw_parts[2].len() == 53 && raw_parts[2].is_char_boundary(22) {
        parts.salt = &raw_parts[2][..22];
        parts.hash = &raw_parts[2][22..];
    } else {
        return Err(BcryptError::InvalidHash(hash.to_string()));
    }

    Ok(parts)
}

#[test]
fn split_hash_test() {
    let input = "$2a$12$5udTI/WUkIdt4n7Rt5x0cOcLjoc.Ax1sSvr3qrBkTTQu1y6sbDVLK";
    assert_eq!(
        HashParts {
            cost: 12,
            version: "2a",
            salt: "5udTI/WUkIdt4n7Rt5x0cO",
            hash: "cLjoc.Ax1sSvr3qrBkTTQu1y6sbDVLK"
        },
        split_hash(input).unwrap()
    )
}
