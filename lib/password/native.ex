defmodule Password.Native do
  @moduledoc """
  Documentation for `Password.Native`. Module for linking Elixir to the Rust library
  """

  version = Mix.Project.config()[:version]

  use RustlerPrecompiled,
    otp_app: :password_rs,
    crate: "password_native",
    base_url: "https://github.com/thomas9911/password-rs/releases/download/v#{version}",
    version: version,
    targets: [
      "aarch64-apple-darwin",
      "aarch64-unknown-linux-gnu",
      "aarch64-unknown-linux-musl",
      "arm-unknown-linux-gnueabihf",
      "riscv64gc-unknown-linux-gnu",
      "x86_64-apple-darwin",
      "x86_64-pc-windows-gnu",
      "x86_64-pc-windows-msvc",
      "x86_64-unknown-linux-gnu",
      "x86_64-unknown-linux-musl"
    ],
    features: [
      "argon2",
      "scrypt",
      "pbkdf2",
      "bcrypt"
    ]

  def hash(_password), do: nif_error()
  def hash_with(_password, _algorithm, _options \\ nil), do: nif_error()
  def verify(_password, _hash), do: nif_error()
  def verify_with(_password, _hash, _algorithms), do: nif_error()
  def known_algorithms, do: nif_error()
  def recommended_algorithms, do: nif_error()

  defp nif_error, do: :erlang.nif_error(:nif_not_loaded)
end
