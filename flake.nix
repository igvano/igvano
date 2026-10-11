{
  description = "igvano development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    zig-overlay = {
      url = "github:mitchellh/zig-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, zig-overlay, ... }: {
    devShells = nixpkgs.lib.genAttrs [
      "aarch64-darwin"
      "x86_64-linux"
      "aarch64-linux"
    ] (system: {
      default = nixpkgs.legacyPackages.${system}.mkShell {
        packages = [ zig-overlay.packages.${system}."0.16.0" ];
      };
    });
  };
}
