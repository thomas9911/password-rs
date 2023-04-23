defmodule Password do
  @moduledoc """
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
  """

  @type algorithm :: atom
  @type hash_settings :: map
  @type plain_text :: String.t()
  @type hashed_password :: binary
  @type error :: binary

  @doc """
  Hashes password and returns the hashed password in PHC form
  ```elixir
  iex> {:ok, "$argon2id" <> _ } = Password.hash("qwerty")
  ```
  """
  @spec hash(plain_text) :: {:ok, hashed_password} | {:error, error}
  defdelegate hash(password), to: Password.Native

  @doc """
  Same as `Password.hash_with/3` but with the default settings for each algorithm
  """
  @spec hash_with(plain_text, algorithm) :: {:ok, hashed_password} | {:error, error}
  defdelegate hash_with(password, algorithm), to: Password.Native

  @doc """
  Hashes password and returns the hashed password in PHC form. Unless it is bcrypt which returns its own format.

  ```elixir
  iex> {:ok, "$argon2id" <> _ } = Password.hash_with("qwerty", :argon2id)
  iex> {:ok, "$argon2id" <> _ } = Password.hash_with("qwerty", :argon2) # :argon2 is an alias for :argon2id
  iex> {:ok, "$scrypt" <> _ } = Password.hash_with("qwerty", :scrypt)
  iex> {:ok, "$2b$12$" <> _ } = Password.hash_with("qwerty", :"2b")
  iex> {:ok, "$2b$12$" <> _ } = Password.hash_with("qwerty", :bcrypt) # :bcrypt is an alias for :"2b"
  iex> {:ok, "$pbkdf2" <> _ } = Password.hash_with("qwerty", :pbkdf2)
  ```

  Set custom options, the arguments are the same as set in the PHC format

  ```elixir
  iex> {:ok, "$argon2id$v=19$m=7168,t=5,p=1$" <> _ } = Password.hash_with("qwerty", :argon2id, %{"m" => 7168, "t" => 5, "p" => 1})
  iex> {:ok, "$scrypt$ln=5,r=2,p=1$" <> _ } = Password.hash_with("qwerty", :scrypt, %{"ln" => 5, "r" => 2, "p" => 1})
  iex> {:ok, "$2b$08$" <> _ } = Password.hash_with("qwerty", :"2b", %{"cost" => 8})
  iex> {:ok, "$pbkdf2-sha256$i=8000,l=32$" <> _ } = Password.hash_with("qwerty", :"pbkdf2-sha256", %{"i" => 8000})
  ```
  """
  @spec hash_with(plain_text, algorithm, hash_settings) ::
          {:ok, hashed_password} | {:error, error}
  defdelegate hash_with(password, algorithm, options), to: Password.Native

  @doc """
  Verify password against the given hashed password

  ```elixir
  iex> {:ok, hash} = Password.hash("qwerty")
  iex> Password.verify("qwerty", hash)
  :ok
  iex> Password.verify("qwerty!", hash)
  {:error, "invalid password"}
  ```
  """
  @spec verify(plain_text, hashed_password) :: :ok | {:error, error}
  defdelegate verify(password, hash), to: Password.Native

  @doc """
  Verify password against the given hashed password.
  The last argument is a list of allowed password algorithms,
  for if you still store some passwords in a old algorithm which is not allowed anymore.

  ```elixir
  iex> {:ok, hash} = Password.hash_with("qwerty", :"2a")
  iex> Password.verify_with("qwerty", hash, [:argon2id, :scrypt])
  {:error, "algorithm not in allowed list"}
  iex> Password.verify_with("qwerty", hash, [:"2b", :"2a"])
  :ok
  ```
  """
  @spec verify_with(plain_text, hashed_password, [algorithm]) :: :ok | {:error, error}
  defdelegate verify_with(password, hash, algorithms), to: Password.Native

  @doc """
  Returns a list of known algorithms ordered by relevance

  ```elixir
  iex> Password.known_algorithms()
  [:argon2id, :argon2i, :argon2d, :scrypt, :"2b", :"2y", :"2x", :"2a", :"pbkdf2-sha512", :"pbkdf2-sha256", :pbkdf2]
  ```
  """
  @spec known_algorithms :: [algorithm()]
  defdelegate known_algorithms, to: Password.Native

  @doc """
  Returns a list of recommended algorithms

  ```elixir
  iex> Password.recommended_algorithms()
  [:argon2id, :scrypt]
  ```
  """
  @spec recommended_algorithms :: [algorithm()]
  defdelegate recommended_algorithms, to: Password.Native
end
