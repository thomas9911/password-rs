defmodule Password do
  @moduledoc """
  Documentation for `Password`.

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

  defdelegate hash(password), to: Password.Native
  defdelegate hash_with(password, algorithm), to: Password.Native
  defdelegate hash_with(password, algorithm, options), to: Password.Native
  defdelegate verify(password, hash), to: Password.Native
  defdelegate verify_with(password, hash, algorithms), to: Password.Native
  defdelegate known_algorithms, to: Password.Native
  defdelegate recommended_algorithms, to: Password.Native
end
