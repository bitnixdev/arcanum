{
  config,
  pkgs,
  lib,
  ...
}: {
  imports = [
    ./default.nix
  ];

  config = {
    dir.project = "$PWD";

    arcanum.defaultRecipients = [
      # Add output from `cat ~/.ssh/id_ed25519.pub` here
      # or `curl https://github.com/<username>.keys | grep -E (ssh-ed25519|ssh-rsa)`
      # Note: ecdsa-sha2-nistp256 keys via https://github.com/FiloSottile/yubikey-agent are unfortunately not supported
    ];
  };
}
