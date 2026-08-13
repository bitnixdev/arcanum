{
  config,
  lib,
  ...
}:
with lib;
with types; let
  cfg = config.arcanum;

  secretFile = submodule {
    options = {
      # TODO: remember why this can't be a path or in-store path?
      # It might be that the arcanum edit/encrypy/decrypt commands need it relative like this?
      source = mkOption {
        type = str;
        description = "path to encrypted secret relative to relativeRoot";
      };

      recipients = mkOption {
        type = listOf str;
        default = cfg.defaultRecipients;
        description = "public keys to encrypt the secret for";
      };

      dest = mkOption {
        type = nullOr str;
        default = null;
        description = "where to write the decrypted secret to..";
      };

      owner = mkOption {
        default = "root";
        type = str;
        description = "who should own the secret";
      };

      group = mkOption {
        default = "root";
        type = str;
        description = "what group should own the secret";
      };

      permissions = mkOption {
        default = "0400";
        type = str;
        description = "Permissions expressed as octal.";
      };

      makeDirectory = mkOption {
        default = false;
        type = bool;
        description = "Whether to create the directory if it doesn't exist.";
      };

      directoryPermissions = mkOption {
        default = "0555";
        type = nullOr str;
        description = "Permissions expressed as octal.";
      };

      before = mkOption {
        type = listOf str;
        default = [];
        description = "Ensure this secret is decrypted before these services are started.";
      };

      isEnvFile = mkOption {
        default = false;
        type = bool;
        description = "Whether to load this secret as an environment file in a devShell. The file is evaluated in an isolated shell so failures warn without aborting shell activation.";
      };
    };
  };
in {
  options = with types; {
    arcanum = {
      enable = mkEnableOption "Enable arcanum encrypted secret management";

      relativeRoot = mkOption {
        type = oneOf [
          path
          str
        ];
        description = "relative path to use for file sources";
        default = "$PWD";
      };
      adminRecipients = mkOption {
        type = listOf str;
        description = "public keys to include as recipients for all secrets";
        default = [];
      };
      defaultRecipients = mkOption {
        type = listOf str;
        description = "default recipients for a secret";
        default = [];
      };
      wellKnownRecipients = mkOption {
        type = attrsOf str;
        description = "public keys of well known recipients";
        default = {};
      };
      files = mkOption {
        type = attrsOf secretFile;
        description = "secret configuration";
        default = {};
      };
      hostPublicKey = mkOption {
        type = nullOr str;
        default = null;
        description = "Host public key";
      };
      identity = mkOption {
        default = "/etc/ssh/ssh_host_ed25519_key";
        type = oneOf [
          str
          path
        ];
        description = "Identity file to use for decryption.";
      };
    };
  };
  config = {
    arcanum.enable = mkDefault (cfg.files != {});
  };
}
