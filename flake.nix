{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    nixpkgs-staging.url = "github:jasonrm/nixpkgs-staging";

    chips = {
      url = "github:jasonrm/nix-chips";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.nixpkgs-staging.follows = "nixpkgs-staging";
    };

    flake-utils = {
      url = "github:numtide/flake-utils";
    };
  };

  outputs = { chips, ... }: chips.lib.use { devShellsDir = ./nix/devShells; };
}
