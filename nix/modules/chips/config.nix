{
  pkgs,
  config,
  lib,
  ...
}:
with lib; let
  cfg = config.arcanum;
  filesWithDest = filterAttrs (n: secret: secret.dest != null) cfg.files;
  secretEnvFiles = filterAttrs (n: secret: secret.dest != null && secret.isEnvFile == true) cfg.files;
  editFiles =
    mapAttrsToList (name: secret: {
      inherit (secret) source dest;
    })
    filesWithDest;
in {
  config = mkIf cfg.enable {
    devShell.contents = [pkgs.arcanum];
    devShell.environment = optional (editFiles != []) "ARCANUM_EDIT_FILES=${escapeShellArg (builtins.toJSON editFiles)}";

    devShell.activationHooks = mkOrder 751 (
      optionalString (secretEnvFiles != {}) ''
        # Source env files in a child shell so a malformed file (or one that
        # calls exit, changes shell options, etc.) cannot abort the dev shell.
        # Successful files emit their resulting exported environment as
        # NUL-delimited records, which are then safely applied here.
        __chips_source_env_file() {
          local __chips_env_file="$1"
          local __chips_env_dump __chips_env_entry __chips_env_name __chips_env_value

          if ! __chips_env_dump="$(${pkgs.coreutils}/bin/mktemp "''${TMPDIR:-/tmp}/nix-chips-env.XXXXXX")"; then
            echo "Warning: Failed to create temporary file for $__chips_env_file" >&2
            return 0
          fi

          if ${pkgs.bash}/bin/bash -e -c '
            set -o allexport
            source "$1"
            ${pkgs.coreutils}/bin/env -0 >&3
          ' nix-chips-source-env "$__chips_env_file" 3>"$__chips_env_dump"; then
            if [ -s "$__chips_env_dump" ]; then
              while IFS= read -r -d "" __chips_env_entry; do
                __chips_env_name="''${__chips_env_entry%%=*}"
                __chips_env_value="''${__chips_env_entry#*=}"
                case "$__chips_env_name" in
                  ""|[!a-zA-Z_]*|*[!a-zA-Z0-9_]*) continue ;;
                esac
                if printf -v "$__chips_env_name" "%s" "$__chips_env_value" 2>/dev/null; then
                  export "$__chips_env_name" 2>/dev/null || true
                fi
              done < "$__chips_env_dump"
              echo "Loaded secret env file $__chips_env_file"
            else
              echo "Warning: Secret env file exited before producing an environment: $__chips_env_file" >&2
            fi
          else
            echo "Warning: Failed to source secret env file $__chips_env_file" >&2
          fi

          ${pkgs.coreutils}/bin/rm -f "$__chips_env_dump"
          return 0
        }

        ${concatStringsSep "\n" (
          mapAttrsToList (name: secret: ''
            if [ -f "${secret.dest}" ]; then
              __chips_source_env_file "${secret.dest}"
            else
              echo "Skipped missing secret env file ${secret.dest}"
            fi
          '')
          secretEnvFiles
        )}
        unset -f __chips_source_env_file
      ''
    );
  };
}
