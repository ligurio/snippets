{
  description = "Tux, of Math Command - educational math game";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        packages = {
          tuxmath = pkgs.callPackage ./package.nix { };
          default = self.packages.${system}.tuxmath;
        };
      }
    );
}
