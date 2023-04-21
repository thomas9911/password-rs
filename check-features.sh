#! /bin/bash

pushd native/password_native
for feature in argon2 bcrypt scrypt pbkdf2; do
    echo "feature => $feature"
    cargo test --no-default-features --features $feature
done
echo "feature => 'scrypt' + 'bcrypt' "
cargo test --no-default-features --features scrypt --features bcrypt
popd
