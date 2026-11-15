{
  description = "igvano development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    zig-overlay = {
      url = "github:mitchellh/zig-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, zig-overlay, ... }:
    let
      # moznion/cccc (cognitive/cyclomatic complexity). Not the unrelated
      # nixpkgs `cccc` (C and C++ Code Counter); pinned release binaries.
      cccc = {
        version = "1.8.3";
        targets = {
          aarch64-darwin = { target = "aarch64-apple-darwin"; sha256 = "838c487bd646b8223f89b22d2d6da34ee8972bf4d17d4abfe8726b30f3fdae89"; };
          x86_64-linux = { target = "x86_64-unknown-linux-musl"; sha256 = "9596a70e920ca9fd22ea541b773c2ddc6a63af4390da8864ebdfbcdc5949aa97"; };
          aarch64-linux = { target = "aarch64-unknown-linux-musl"; sha256 = "8aad9b34f398f32cafb2825dc2e7d68ab2dea51bd00e1bec1d2fb8370c8506f2"; };
        };
      };
    in
    {
      devShells = nixpkgs.lib.genAttrs [
        "aarch64-darwin"
        "x86_64-linux"
        "aarch64-linux"
      ] (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          ccccTarget = cccc.targets.${system};
          ccccBin = pkgs.stdenvNoCC.mkDerivation {
            pname = "cccc";
            inherit (cccc) version;
            src = pkgs.fetchurl {
              url = "https://github.com/moznion/cccc/releases/download/v${cccc.version}/cccc-v${cccc.version}-${ccccTarget.target}.tar.gz";
              inherit (ccccTarget) sha256;
            };
            sourceRoot = ".";
            installPhase = "install -Dm755 cccc $out/bin/cccc";
          };
        in
        {
          default = pkgs.mkShell {
            packages = [
              zig-overlay.packages.${system}."0.16.0"
              pkgs.prek
              pkgs.mdbook
              ccccBin
            ];
          };
        });
    };
}
