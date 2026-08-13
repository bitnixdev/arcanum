{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
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

  outputs = inputs @ {chips, ...}:
    chips.lib.mkFlake {
      inherit inputs;
      sources = {
        devShells = ./nix/devShells;
        nixosModules = ./nix/modules/nixos;
        packages = ./nix/packages;
      };
      modules.chips = [./nix/modules/chips/default.nix];
      outputs = {
        chipsModules.default = import ./nix/modules/chips/default.nix;
        darwinModules.default = import ./nix/modules/nix-darwin/default.nix;
        homeManagerModules.default = import ./nix/modules/home-manager/default.nix;
      };
    };
}
