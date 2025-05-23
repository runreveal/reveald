{
  inputs = {
    nixpkgs.url = "nixpkgs";
    flake-utils.url = "flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        inherit (pkgs.lib.attrsets) getOutput isDerivation;
        inherit (pkgs.lib.strings) concatStringsSep makeIncludePath makeLibraryPath;

        cIncludePath = [
          pkgs.linuxHeaders
          pkgs.libbpf
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.clang.cc
            pkgs.go_1_24
            pkgs.libllvm
          ];

          shellHook = ''
            export C_INCLUDE_PATH='${makeIncludePath cIncludePath}'
            export LIBRARY_PATH='${makeLibraryPath [pkgs.libbpf]}'
          '';
        };
      }
    );
}
