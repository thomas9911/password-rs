# Password

## Usage

Hashes and verifies passwords.

Nearly all password formats are
[PHC](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md),
except for Bcrypt which uses its own format.

examples:

```js
// argon2id
"$argon2id$v=19$m=16,t=2,p=1$ekwxb1piSWRxS1dzM2FnMQ$JGGTmshkt4PaO1sSX7w1Gg";
// bcrypt
"$2a$12$5udTI/WUkIdt4n7Rt5x0cOcLjoc.Ax1sSvr3qrBkTTQu1y6sbDVLK";
```

This because Bcrypt in other libraries in other languages also use this format
(checked: python, ruby, rust, elixir)

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
