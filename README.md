# Password

## Usage

Hashes and verifies passwords.

Nearly all password formats are [PHC](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md),
except for Bcrypt which uses its own format.

examples:

```js
// argon2id
"$argon2id$v=19$m=19456,t=2,p=1$gxbjqzYr4kRe9XSK9k4geA$PIJQSj+ooUKQp86FUZf7xkbmNqpHEuL9lnQlHCGPCHg"
// bcrypt
"$2a$12$5udTI/WUkIdt4n7Rt5x0cOcLjoc.Ax1sSvr3qrBkTTQu1y6sbDVLK"
```

This because Bcrypt in other libraries in other languages also use this format (checked: python, ruby, rust, elixir)

### Hashing

```elixir
iex> # just use the default algorithm set
iex> {:ok, "$argon2id" <> _ } = Password.hash("qwerty")
iex> # pick the algorithm you want
iex> {:ok, "$scrypt" <> _ } = Password.hash_with("qwerty", :scrypt)
iex> # bcrypt version 2b
iex> {:ok, "$2b" <> _ } = Password.hash_with("qwerty", :"2b")
iex> {:ok, "$pbkdf2" <> _ } = Password.hash_with("qwerty", :pbkdf2)
iex> # pick the algorithm you want with setting custom options (this is another option OWASP suggests)
iex> {:ok, "$argon2id$v=19$m=7168,t=5,p=1$" <> _ } = Password.hash_with("qwerty", :argon2id, %{"m" => 7168, "t" => 5, "p" => 1})
```

### Verifying

```elixir
iex> hash = "$argon2id$v=19$m=19456,t=2,p=1$gxbjqzYr4kRe9XSK9k4geA$PIJQSj+ooUKQp86FUZf7xkbmNqpHEuL9lnQlHCGPCHg"
iex> Password.verify("testing1234", hash)
:ok
iex> # set a list of allowed algorithms that are used
iex> Password.verify_with("testing1234", hash, [:argon2id])
:ok
iex> Password.verify_with("testing1234", hash, [:scrypt, :bcrypt])
{:error, "algorithm not in allowed list"}
```

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `password_rs` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:password_rs, "~> 0.1.0"}
  ]
end
```

## URLs

- https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
- https://github.com/RustCrypto/traits/tree/master/password-hash
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#maximum-password-lengths

