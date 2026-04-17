{
  description = "sshenv: SSH-key-backed encrypted vault for environment variables";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            rustToolchain
            pkgs.pkg-config
          ];

          RUST_BACKTRACE = "1";
        };

        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "sshenv";
          version = "0.0.1-alpha.0";
          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
            allowBuiltinFetchGit = true;
          };

          nativeBuildInputs = [ pkgs.pkg-config ];

          # Skip tests that require a live ssh-agent with a specific key.
          doCheck = false;

          meta = with pkgs.lib; {
            description = "SSH-key-backed encrypted env-var vault";
            homepage = "https://github.com/BSteffaniak/sshenv";
            license = licenses.mpl20;
            mainProgram = "sshenv";
          };
        };

        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/sshenv";
        };
      }
    );
}
