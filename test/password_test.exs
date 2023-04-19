defmodule PasswordTest do
  use ExUnit.Case
  doctest Password

  describe "verify" do
    test "bcrypt" do
      # should be true
      assert :ok ==
               Password.verify(
                 "testing1234",
                 "$2a$12$5udTI/WUkIdt4n7Rt5x0cOcLjoc.Ax1sSvr3qrBkTTQu1y6sbDVLK"
               )
    end
  end
end
