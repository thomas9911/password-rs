import Config

config :rustler_precompiled, :force_build,
  password_rs: System.get_env("RUSTLER_PRECOMPILATION_PASSWORD_RS_BUILD") in ["1", "true", nil]
