{
  lib,
  pkgs,
  config,
  ...
}:
with lib; let
  cfg = config.arcanum;

  decryptSecret = pkgs.writeShellScript "decrypt" ''
    set -o errexit -o nounset -o pipefail
    if [ ! -f ${cfg.identity} ]; then
      echo "Missing identity file: ${cfg.identity}" >&2
      exit 0
    fi

    if [ ! -f "$1" ]; then
      echo "Encrypted Secret Not Found: $1" >&2
      exit 0
    fi

    DECRYPTED_DIR=$(dirname "$2")
    if [[ ! -d "$DECRYPTED_DIR" ]]; then
      mkdir -p "$DECRYPTED_DIR"
    fi

    if ! ${pkgs.rage}/bin/rage -d -i ${cfg.identity} -o "$2" "$1"; then
      echo "Failed to decrypt $1, skipping" >&2
      rm -f "$2"
      exit 0
    fi
    chmod 600 "$2"
  '';

  filesWithDest = filterAttrs (n: secret: secret.dest != null) cfg.files;
in {
  imports = [../shared/default.nix];

  options = with types; {};

  config = {
    home.activation = {
      arcanum = lib.hm.dag.entryAfter ["writeBoundary"] (
        concatStringsSep "\n" (
          mapAttrsToList (
            name: secret: "${decryptSecret} ${cfg.relativeRoot}/${escapeShellArg secret.source} ${escapeShellArg secret.dest}"
          )
          filesWithDest
        )
      );
    };
  };
}
