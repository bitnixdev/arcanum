{
  lib,
  rustPlatform,
}: let
  cargoToml = lib.importTOML ../../Cargo.toml;
in
  rustPlatform.buildRustPackage {
    pname = cargoToml.package.name;
    version = cargoToml.package.version;
    src = lib.sourceByRegex ../../. [
      "Cargo\.(toml|lock)$"
      "src.*"
    ];
    cargoLock.lockFile = ../../Cargo.lock;

    # Signal self-kill unit test is unreliable under the Nix build sandbox.
    doCheck = false;

    meta = {
      homepage = "https://github.com/bitnixdev/arcanum";
      description = "File encryption tool with age encryption and Nix integration";
      license = lib.licenses.mit;
      mainProgram = "arcanum";
    };
  }
