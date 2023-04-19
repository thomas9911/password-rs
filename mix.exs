defmodule Password.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :password_rs,
      version: @version,
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:rustler, "~> 0.27.0", optional: true},
      {:rustler_precompiled, "~> 0.6"},
      {:ex_doc, "~> 0.27", only: :dev, runtime: false},
      {:dialyxir, "~> 1.1", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: :dev, runtime: false}
    ]
  end

  defp aliases do
    [
      quality: ["format", "credo", "dialyzer"],
      fmt: ["cmd --cd native/password_native cargo fmt", "format"],
      cargo: "cmd --cd native/password_native cargo"
    ]
  end
end
