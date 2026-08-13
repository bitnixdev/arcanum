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
    stamp="$3"

    if [ ! -f "$src" ]; then
      echo "Encrypted Secret Not Found: $src" >&2
      exit 0
    fi

    # The source is a store path, so its name changes whenever the
    # encrypted content changes; a matching stamp means dest is current.
    if [ -n "$stamp" ] && [ -z "''${ARCANUM_FORCE:-}" ] && [ -f "$dest" ] && [ "$(cat "$stamp" 2>/dev/null)" = "$src" ]; then
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

    if [ -n "$stamp" ]; then
      mkdir -p "$(dirname "$stamp")"
      printf '%s\n' "$src" > "$stamp"
    fi
  '';
in {
  imports = [];

  options = {};

  config = {
    devShell = let
      filesWithDest = filterAttrs (n: secret: secret.dest != null) cfg.files;
    in {
      shellHooks = mkOrder 750 (
        concatStringsSep "\n" (
          mapAttrsToList (
            name: secret: let
              stamp =
                if config.dir.project != "/dev/null"
                then "${config.dir.data}/.arcanum/${name}"
                else "";
            in
              escapeShellArgs [
                decryptSecret
                "${cfg.relativeRoot}/${secret.source}"
                secret.dest
                stamp
              ]
          )
          filesWithDest
        )
      );
    };
  };
}
