defmodule Password.PropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  @options %{"i" => 1000, "m" => 1024, "ln" => 5, "cost" => 4}

  Password.known_algorithms()
  |> Enum.map(fn algo ->
    test "proptest #{algo}" do
      check all(generated <- StreamData.string(:printable)) do
        assert {:ok, hash} = Password.hash_with(generated, unquote(algo), @options)
        prefix = "$#{unquote(algo)}"
        assert String.starts_with?(hash, prefix)
        assert :ok == Password.verify(generated, hash)
      end
    end
  end)
end
