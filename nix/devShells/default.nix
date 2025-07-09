{
  config,
  pkgs,
  lib,
  ...
}:
{
  config = {
    arcanum = {
      identity = "~/.ssh/id_ed25519";
      relativeRoot = toString ../../.;
    };

    arcanum.files.project-env = {
      source = "secrets/project.env.age";
      dest = "${config.dir.data}/.env.project";
    };

    programs.rust = {
      enable = true;
    };
    devShell = {
      contents = with pkgs; [
        clippy
        cargo-flamegraph
        flamegraph
      ];
    };
  };
}
