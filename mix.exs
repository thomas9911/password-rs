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
      aliases: aliases(),
      description: "Hashes and verifies passwords using Rust in Elixir",
      package: package()
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"Github" => "https://github.com/thomas9911"}
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
      {:credo, "~> 1.7", only: :dev, runtime: false},
      {:stream_data, "~> 0.5", only: :test},
      {:mix_readme, "~> 0.2.1", only: :dev, runtime: false}
    ]
  end

  defp aliases do
    [
      quality: ["fmt", "credo", "dialyzer"],
      fmt: ["cmd --cd native/password_native cargo fmt", "format"],
      cargo: "cmd --cd native/password_native cargo",
      "test.rust": "cargo test --all-features",
      readme: &readme/1
    ]
  end

  defp readme(_) do
    readme =
      ExUnit.CaptureIO.capture_io(fn -> Mix.Task.run(:readme, ["--module", "Password"]) end)

    File.write!("README.md", readme)
  end
end
