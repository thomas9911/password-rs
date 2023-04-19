defmodule Password do
  @moduledoc """
  Documentation for `Password`.
  """

  defdelegate hash(password), to: Password.Native
  defdelegate hash_with(password, algorithm), to: Password.Native
  defdelegate verify(password, hash), to: Password.Native
  defdelegate verify_with(password, hash, algorithms), to: Password.Native
  defdelegate known_algorithms, to: Password.Native
end
