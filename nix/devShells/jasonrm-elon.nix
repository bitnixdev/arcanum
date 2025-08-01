{ ... }:
{
  imports = [ ./default.nix ];

  config = {
    dir.project = "/Users/jasonrm/repos/github.com/bitnixdev/arcanum";

    arcanum.defaultRecipients = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII5gspOWcPeO/Qol7NbmvKIN8iQtGBYqhtPWwJMLSpYo jasonrm@elon"
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ3k6zKT97l8vlxcmH5hekHEvnSDXpL6j8FFW/ZL3CXT jasonrm@raskin"
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJcDcoR4lSYQcbbR4eVUjUJ56dqk9xE4FVC5/vB2E8Wv jasonrm@hertzfeld"
    ];
  };
}
