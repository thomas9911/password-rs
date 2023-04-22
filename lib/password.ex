defmodule Password do
  @moduledoc """
  Hashes and verifies passwords.

  Nearly all password formats are [PHC](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md),
  except for Bcrypt which uses its own format.

  examples:

  ```js
  // argon2id
  "$argon2id$v=19$m=16,t=2,p=1$ekwxb1piSWRxS1dzM2FnMQ$JGGTmshkt4PaO1sSX7w1Gg"
  // bcrypt
  "$2a$12$5udTI/WUkIdt4n7Rt5x0cOcLjoc.Ax1sSvr3qrBkTTQu1y6sbDVLK"
  ```

  This because Bcrypt in other libraries in other languages also use this format (checked: python, ruby, rust, elixir)

  """

  @type algorithm :: atom
  @type hash_settings :: map
  @type plain_text :: String.t()
  @type hashed_password :: binary
  @type error :: binary

  @spec hash(plain_text) :: {:ok, hashed_password} | {:error, error}
  defdelegate hash(password), to: Password.Native
  @spec hash_with(plain_text, algorithm) :: {:ok, hashed_password} | {:error, error}
  defdelegate hash_with(password, algorithm), to: Password.Native

  @spec hash_with(plain_text, algorithm, hash_settings) ::
          {:ok, hashed_password} | {:error, error}
  defdelegate hash_with(password, algorithm, options), to: Password.Native
  @spec verify(plain_text, hashed_password) :: :ok | {:error, error}
  defdelegate verify(password, hash), to: Password.Native
  @spec verify_with(plain_text, hashed_password, [algorithm]) :: :ok | {:error, error}
  defdelegate verify_with(password, hash, algorithms), to: Password.Native
  @spec known_algorithms :: [algorithm()]
  defdelegate known_algorithms, to: Password.Native
  @spec recommended_algorithms :: [algorithm()]
  defdelegate recommended_algorithms, to: Password.Native
end
