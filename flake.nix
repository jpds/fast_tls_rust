{
  description = "Rust NIF TLS implementation using rustls for ejabberd";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    crane.url = "github:ipetkov/crane";
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
      crane,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        appName = "fast_tls_rust";
        version = "0.1.0";

        nif = craneLib.buildPackage {
          src = craneLib.cleanCargoSource ./native/fast_tls_rust;
        };

        app = pkgs.beamPackages.buildRebar3 {
          name = appName;
          inherit version;
          src = ./.;
          beamDeps = [ ];
          # Nix builds the NIF hermetically above; drop rebar3_cargo (it would
          # try to invoke cargo/network during rebar3's own build) and place
          # the prebuilt .so where fast_tls_rust:init/0 expects it.
          postPatch = ''
            cat > rebar.config <<'EOF'
            {erl_opts, [debug_info]}.
            EOF
            mkdir -p priv/crates/fast_tls_rust
            cp ${nif}/lib/libfast_tls_rust.so priv/crates/fast_tls_rust/fast_tls_rust.so
          '';
        };
      in
      {
        packages.default = app;

        checks.eunit = pkgs.stdenv.mkDerivation {
          name = "fast_tls_rust-eunit";
          src = ./.;
          buildInputs = [ pkgs.erlang ];
          # app already has a proper .app file; a raw erlc build wouldn't produce one.
          buildPhase = ''
            ebin_dir=$(echo ${app}/lib/erlang/lib/*/ebin)
            mkdir -p test_ebin
            erlc -pa "$ebin_dir" -o test_ebin test/*.erl
          '';
          checkPhase = ''
            ebin_dir=$(echo ${app}/lib/erlang/lib/*/ebin)
            erl -pa "$ebin_dir" -pa test_ebin -noshell -eval 'case eunit:test(fast_tls_rust_test, [verbose]) of ok -> init:stop(0); _ -> init:stop(1) end.'
          '';
          doCheck = true;
          installPhase = "touch $out";
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            rustToolchain
            pkgs.erlang
            pkgs.rebar3
          ];
        };
      }
    );
}
