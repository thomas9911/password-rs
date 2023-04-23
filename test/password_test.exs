defmodule PasswordTest do
  use ExUnit.Case, async: true
  doctest Password

  describe "verify" do
    test "bcrypt" do
      assert :ok ==
               Password.verify(
                 "testing1234",
                 "$2a$12$5udTI/WUkIdt4n7Rt5x0cOcLjoc.Ax1sSvr3qrBkTTQu1y6sbDVLK"
               )

      assert {:error, "invalid password"} ==
               Password.verify(
                 "testing1234",
                 "$2a$05$5udTI/WUkIdt4n7Rt5x0cOcLjoc.Ax1sSvr3qrBkTTQu1y6sbDVLK"
               )
    end

    test "argon2" do
      assert :ok ==
               Password.verify(
                 "testing1234",
                 "$argon2id$v=19$m=16,t=2,p=1$ekwxb1piSWRxS1dzM2FnMQ$JGGTmshkt4PaO1sSX7w1Gg"
               )

      assert {:error, "invalid password"} ==
               Password.verify(
                 "testing1234",
                 "$argon2id$v=19$m=10,t=2,p=1$ekwxb1piSWRxS1dzM2FnMQ$JGGTmshkt4PaO1sSX7w1Gg"
               )
    end

    test "scrypt" do
      assert :ok ==
               Password.verify(
                 "testing1234",
                 "$scrypt$ln=10,r=8,p=1$+h7sTjFtfHSn5HaVhG+yOA$hrO7W/4yrYrgqQfHMCF922oCFizjfezxlL3JuUEvrbM"
               )

      assert {:error, "invalid password"} ==
               Password.verify(
                 "testing1234",
                 "$scrypt$ln=7,r=8,p=1$+h7sTjFtfHSn5HaVhG+yOA$hrO7W/4yrYrgqQfHMCF922oCFizjfezxlL3JuUEvrbM"
               )
    end

    test "pbkdf2-sha256" do
      assert :ok ==
               Password.verify(
                 "testing1234",
                 "$pbkdf2-sha256$i=1000,l=32$JVUJglG6febK3Z4xmlDMvQ$aAMkB1orgDP4qf87SZSIRcc++3eS5aNjgyCF9rFiaps"
               )

      assert {:error, "invalid password"} ==
               Password.verify(
                 "testing1234",
                 "$pbkdf2-sha256$i=2500,l=32$JVUJglG6febK3Z4xmlDMvQ$aAMkB1orgDP4qf87SZSIRcc++3eS5aNjgyCF9rFiaps"
               )
    end
  end

  describe "verify_with" do
    test "argon2-scrypt allowed" do
      allowed = [:argon2id, :scrypt]

      assert :ok ==
               Password.verify_with(
                 "testing1234",
                 "$argon2id$v=19$m=16,t=2,p=1$ekwxb1piSWRxS1dzM2FnMQ$JGGTmshkt4PaO1sSX7w1Gg",
                 allowed
               )

      assert :ok ==
               Password.verify_with(
                 "testing1234",
                 "$scrypt$ln=10,r=8,p=1$+h7sTjFtfHSn5HaVhG+yOA$hrO7W/4yrYrgqQfHMCF922oCFizjfezxlL3JuUEvrbM",
                 allowed
               )

      assert {:error, "algorithm not in allowed list"} ==
               Password.verify_with(
                 "testing1234",
                 "$2a$12$5udTI/WUkIdt4n7Rt5x0cOcLjoc.Ax1sSvr3qrBkTTQu1y6sbDVLK",
                 allowed
               )

      # still verifies password
      assert {:error, "invalid password"} ==
               Password.verify_with(
                 "testing1234",
                 "$scrypt$ln=5,r=8,p=1$+h7sTjFtfHSn5HaVhG+yOA$hrO7W/4yrYrgqQfHMCF922oCFizjfezxlL3JuUEvrbM",
                 allowed
               )
    end

    test "old bcrypt" do
      allowed = [:"2b"]

      assert {:error, "algorithm not in allowed list"} ==
               Password.verify_with(
                 "testing1234",
                 "$2a$12$5udTI/WUkIdt4n7Rt5x0cOcLjoc.Ax1sSvr3qrBkTTQu1y6sbDVLK",
                 allowed
               )

      assert {:error, "algorithm not in allowed list"} ==
               Password.verify_with(
                 "testing1234",
                 "$2x$12$5udTI/WUkIdt4n7Rt5x0cOcLjoc.Ax1sSvr3qrBkTTQu1y6sbDVLK",
                 allowed
               )

      assert :ok ==
               Password.verify_with(
                 "testing1234",
                 "$2b$12$5udTI/WUkIdt4n7Rt5x0cOcLjoc.Ax1sSvr3qrBkTTQu1y6sbDVLK",
                 allowed
               )
    end
  end

  describe "hash" do
    test "default" do
      assert {:ok, "$argon2id$v=19$m=19456,t=2,p=1$" <> _} = Password.hash("testing1234")
    end

    test "argon2id" do
      assert {:ok, "$argon2id$v=19$m=19456,t=2,p=1$" <> _} =
               Password.hash_with("testing1234", :argon2id)
    end

    test "argon2id, custom" do
      assert {:ok, "$argon2id$v=19$m=1024,t=1,p=1$" <> _} =
               Password.hash_with("testing1234", :argon2id, %{"m" => 1024, "t" => 1})
    end

    test "argon2i" do
      assert {:ok, "$argon2i$v=19$m=19456,t=2,p=1$" <> _} =
               Password.hash_with("testing1234", :argon2i)
    end

    test "argon2d" do
      assert {:ok, "$argon2d$v=19$m=19456,t=2,p=1$" <> _} =
               Password.hash_with("testing1234", :argon2d)
    end

    test "scrypt" do
      assert {:ok, "$scrypt$ln=17,r=8,p=1$" <> _} = Password.hash_with("testing1234", :scrypt)
    end

    test "scrypt, custom" do
      assert {:ok, "$scrypt$ln=12,r=5,p=1$" <> _} =
               Password.hash_with("testing1234", :scrypt, %{"ln" => 12, "r" => 5})
    end

    test "bcrypt" do
      assert {:ok, "$2a$12$" <> _} = Password.hash_with("testing1234", :"2a")
    end

    test "pbkdf2-sha512" do
      assert {:ok, "$pbkdf2-sha512$i=10000,l=32$" <> _} =
               Password.hash_with("testing1234", :"pbkdf2-sha512")
    end

    test "pbkdf2-sha256" do
      assert {:ok, "$pbkdf2-sha256$i=10000,l=32$" <> _} =
               Password.hash_with("testing1234", :"pbkdf2-sha256")
    end

    test "pbkdf2-sha1" do
      assert {:ok, "$pbkdf2$i=10000,l=32$" <> _} = Password.hash_with("testing1234", :pbkdf2)
    end

    test "pbkdf2-sha256, custom" do
      assert {:ok, "$pbkdf2-sha256$i=1000,l=32$" <> _} =
               Password.hash_with("testing1234", :"pbkdf2-sha256", %{"i" => 1000})
    end
  end

  describe "roundtrip" do
    test "argon2" do
      {:ok, hash} = Password.hash_with("testing1234", :argon2id)
      assert :ok == Password.verify("testing1234", hash)
      assert {:error, "invalid password"} == Password.verify("testtest", hash)
    end

    test "scrypt" do
      {:ok, hash} = Password.hash_with("testing1234", :scrypt)
      assert :ok == Password.verify("testing1234", hash)
      assert {:error, "invalid password"} == Password.verify("testtest", hash)
    end

    test "bcrypt" do
      {:ok, hash} = Password.hash_with("testing1234", :"2b")
      assert :ok == Password.verify("testing1234", hash)
      assert {:error, "invalid password"} == Password.verify("testtest", hash)
    end

    test "emoji" do
      {:ok, hash} = Password.hash_with("🌲🛴✔️🚀", :argon2id)
      assert :ok == Password.verify("🌲🛴✔️🚀", hash)
    end
  end
end
