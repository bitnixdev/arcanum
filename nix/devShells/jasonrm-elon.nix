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
    dir.project = "/Users/jasonrm/repos/github.com/bitnixdev/arcanum";

    arcanum.defaultRecipients = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII5gspOWcPeO/Qol7NbmvKIN8iQtGBYqhtPWwJMLSpYo jasonrm@elon"
    ];
  };
}
