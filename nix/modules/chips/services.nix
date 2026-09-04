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

    src="$1"
    dest="$2"

    if [ ! -f "$src" ]; then
      echo "Encrypted Secret Not Found: $src" >&2
      exit 0
    fi

    decrypted_dir=$(dirname "$dest")
    if [ ! -d "$decrypted_dir" ]; then
      mkdir -p "$decrypted_dir"
    fi

    tmp="$dest.tmp.$$"
    trap 'rm -f "$tmp"' EXIT
    ${pkgs.rage}/bin/rage -d -i ${cfg.identity} -o "$tmp" "$src"
    chmod 600 "$tmp"

    if [ -f "$dest" ] && cmp -s "$tmp" "$dest"; then
      rm -f "$tmp"
    else
      mv -f "$tmp" "$dest"
    fi
    trap - EXIT
  '';
in {
  imports = [];

  options = {};

  config = {
    devShell = let
      filesWithDest = filterAttrs (n: secret: secret.dest != null) cfg.files;
    in {
      # nix-chips runs setup hooks once per cache generation, so every
      # `direnv reload` re-decrypts; an unchanged destination is left untouched.
      shellHooks = mkOrder 750 (
        concatStringsSep "\n" (
          mapAttrsToList (
            name: secret:
              escapeShellArgs [
                decryptSecret
                "${cfg.relativeRoot}/${secret.source}"
                secret.dest
              ]
          )
          filesWithDest
        )
      );
    };
  };
}
