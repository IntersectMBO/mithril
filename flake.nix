{
  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs:
    inputs.flake-parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux" "aarch64-linux" "aarch64-darwin"];

      imports = [inputs.treefmt-nix.flakeModule];

      flake.hydraJobs = builtins.removeAttrs inputs.self.packages ["aarch64-linux"];

      perSystem = {
        pkgs,
        config,
        system,
        self',
        ...
      }: let
        inherit (inputs.nixpkgs) lib;
        
      pkgsRustOverlay = import inputs.nixpkgs {
        inherit system;
        overlays = [ (import inputs.rust-overlay) ];
      };

      pkgsMusl =
        if system == "x86_64-linux"
        then pkgsRustOverlay.pkgsCross.musl64
        else null;

      pkgsWindows =
        if system == "x86_64-linux"
        then pkgsRustOverlay.pkgsCross.mingwW64
        else null;

      craneLib = inputs.crane.mkLib pkgsRustOverlay;

      workspaceVersion = (craneLib.crateNameFromCargoToml { cargoToml = ./mithril-common/Cargo.toml; }).version;

      craneLibMusl =
        if pkgsMusl != null then
          (inputs.crane.mkLib pkgsMusl).overrideToolchain (p:
            p.rust-bin.stable.latest.default.override {
              targets = [ "x86_64-unknown-linux-musl" ];
            }
          )
        else
          null;

      craneLibWindows =
        if pkgsWindows != null then
          (inputs.crane.mkLib pkgsWindows).overrideToolchain (p:
            p.rust-bin.stable.latest.default.override {
              targets = [ "x86_64-pc-windows-gnu" ];
            }
          )
        else
          null;

        sourceFilter = orig_path: type: let
          path = builtins.toString orig_path;
          base = builtins.baseNameOf path;
          parentDir = builtins.baseNameOf (builtins.dirOf path);
          matchesSuffix = lib.any (suffix: lib.hasSuffix suffix base) [".rs" ".toml" ".md"];
          isCargoFile = base == "Cargo.lock";
          isCargoConfig = parentDir == ".cargo" && base == "config";
          isOpenApiYaml = base == "openapi.yaml";
          isFakeAggregatorDefaultData = lib.hasInfix "/mithril-aggregator-fake/default_data/" path;
          isTestDataAsset = lib.hasInfix "/test_data/" path;
          isGoldenVector = lib.hasInfix "/golden_vectors/" path;
        in
          type == "directory" || matchesSuffix || isCargoFile || isCargoConfig || isOpenApiYaml
                || isFakeAggregatorDefaultData || isTestDataAsset || isGoldenVector;

        clean = root:
          lib.cleanSourceWith {
            src = lib.cleanSource (craneLib.path root);
            filter = sourceFilter;
          };

        cleanMusl = root:
          lib.cleanSourceWith {
            src = lib.cleanSource (craneLibMusl.path root);
            filter = sourceFilter;
          };

        cleanWindows = root:
          lib.cleanSourceWith {
            src = lib.cleanSource (craneLibWindows.path root);
            filter = sourceFilter;
          };

        buildInputs =
          [
            pkgsRustOverlay.pkg-config
            pkgsRustOverlay.gnum4
            pkgsRustOverlay.cacert
          ]
          ++ lib.optionals (pkgsRustOverlay.stdenv.isDarwin) [
            pkgsRustOverlay.libiconv
          ];

        nativeBuildInputsMusl =
          if pkgsMusl != null then [
            pkgsMusl.stdenv.cc
            pkgsMusl.pkg-config
            pkgsMusl.gnum4
          ]
          else [];

        nativeBuildInputsWindows =
          if pkgsWindows != null then [
            pkgsWindows.stdenv.cc
          ]
          else [];

        buildInputsWindows =
          if pkgsWindows != null then [
            pkgsWindows.windows.pthreads
          ]
          else [];


        commonsArgs = {
          pname = "mithril";
          version = workspaceVersion;
          src = clean ./.;
          inherit buildInputs;
          CARGO_TERM_VERBOSE = "true";
          SSL_CERT_FILE = "${pkgsRustOverlay.cacert}/etc/ssl/certs/ca-bundle.crt";
        };

        commonsArgsMusl =
          if pkgsMusl != null then {
            pname = "mithril";
            version = workspaceVersion;
            src = cleanMusl ./.;
            nativeBuildInputs = nativeBuildInputsMusl;
            CARGO_TERM_VERBOSE = "true";
            SSL_CERT_FILE = "${pkgsRustOverlay.cacert}/etc/ssl/certs/ca-bundle.crt";
          }
          else {};

        commonsArgsWindows =
          if pkgsWindows != null then {
            pname = "mithril";
            version = workspaceVersion;
            src = cleanWindows ./.;
            nativeBuildInputs = nativeBuildInputsWindows;
            buildInputs = buildInputsWindows;
            CARGO_TERM_VERBOSE = "true";
            SSL_CERT_FILE = "${pkgsRustOverlay.cacert}/etc/ssl/certs/ca-bundle.crt";
          }
          else {};

        preInstallScript = let
          localLibs = "dummy|mithril|stm|multi_sig|size_benches|digester";
        in ''
          shopt -s extglob
          TARGET_DIR="''${CARGO_TARGET_DIR:-target}"
          if [ -n "$CARGO_BUILD_TARGET" ]; then
            PROFILE_DIR="$TARGET_DIR/$CARGO_BUILD_TARGET/release"
          else
            PROFILE_DIR="$TARGET_DIR/release"
          fi

          rm "$PROFILE_DIR/deps/"*@(${localLibs})*
          rm -r "$PROFILE_DIR/"*@(${localLibs})*
          rm -r "$PROFILE_DIR/build/"*@(${localLibs})*
          rm -r "$PROFILE_DIR/.fingerprint/"*@(${localLibs})*
        '';

        buildDeps = craneLibFor: commonArgs: cargoToml: cargoArtifacts:
          (craneLibFor.buildDepsOnly (commonArgs
            // lib.optionalAttrs (cargoToml != null) rec {
              inherit (craneLibFor.crateNameFromCargoToml {inherit cargoToml;}) pname version;
              cargoExtraArgs = "-p ${pname}";
            }))
          .overrideAttrs (_: {
            inherit cargoArtifacts;
            preInstall = preInstallScript;
          });

        buildPackage = cargoToml: baseCargoArtifacts: args:
          craneLib.buildPackage (commonsArgs
            // lib.optionalAttrs (cargoToml != null) rec {
              inherit (craneLib.crateNameFromCargoToml {inherit cargoToml;}) pname version;
              cargoExtraArgs = "-p ${pname}";
              cargoTestExtraArgs = "-- --skip slow::";
            }
            // {
              cargoArtifacts = buildDeps craneLib commonsArgs cargoToml baseCargoArtifacts;
            }
            // {
              cargoTestCommand = "RUST_BACKTRACE=1 cargo test --profile release";
            }
            // args);

        buildPackageMusl = cargoToml: baseCargoArtifacts: args:
          craneLibMusl.buildPackage (commonsArgsMusl
            // lib.optionalAttrs (cargoToml != null) rec {
              inherit (craneLibMusl.crateNameFromCargoToml {inherit cargoToml;}) pname version;
              cargoExtraArgs = "-p ${pname}";
              cargoTestExtraArgs = "-- --skip slow::";
            }
            // {
              cargoArtifacts = buildDeps craneLibMusl commonsArgsMusl cargoToml baseCargoArtifacts;
              RUSTFLAGS = "-C target-feature=+crt-static";
            }
            // args);

        buildPackageWindows = cargoToml: baseCargoArtifacts: args:
          craneLibWindows.buildPackage (commonsArgsWindows
            // lib.optionalAttrs (cargoToml != null) rec {
              inherit (craneLibWindows.crateNameFromCargoToml {inherit cargoToml;}) pname version;
              cargoExtraArgs = "-p ${pname}";
              cargoTestExtraArgs = "-- --skip slow::";
            }
            // {
              cargoArtifacts = buildDeps craneLibWindows commonsArgsWindows cargoToml baseCargoArtifacts;
              RUSTFLAGS = "-C target-feature=+crt-static";
              doCheck = false;
            }
            // args);

        # Standard (glibc) builds
        mithril-stm = buildPackage ./mithril-stm/Cargo.toml null {};
        mithril-common = buildPackage ./mithril-common/Cargo.toml mithril-stm.cargoArtifacts { cargoExtraArgs = "-p mithril-common"; };
        mithril = buildPackage null mithril-common.cargoArtifacts {
          doCheck = false;
        };

        # Static (musl) base dependencies
        mithril-stm-musl = if pkgsMusl != null then buildPackageMusl ./mithril-stm/Cargo.toml null {} else null;
        mithril-common-musl = if pkgsMusl != null then buildPackageMusl ./mithril-common/Cargo.toml mithril-stm-musl.cargoArtifacts { cargoExtraArgs = "-p mithril-common"; } else null;

        # Windows (mingw64) base dependencies
        mithril-stm-windows = if pkgsWindows != null then buildPackageWindows ./mithril-stm/Cargo.toml null {} else null;
        mithril-common-windows = if pkgsWindows != null then buildPackageWindows ./mithril-common/Cargo.toml mithril-stm-windows.cargoArtifacts { cargoExtraArgs = "-p mithril-common"; } else null;
      in {
        packages = {
          default = mithril;
          inherit mithril mithril-stm mithril-common;
          mithril-client = buildPackage ./mithril-client/Cargo.toml mithril.cargoArtifacts { cargoExtraArgs = "-p mithril-client --features rustls,full"; };
          mithril-end-to-end = buildPackage ./mithril-test-lab/mithril-end-to-end/Cargo.toml null {};

        } // lib.optionalAttrs (pkgsMusl != null) {

          mithril-aggregator =
            buildPackageMusl ./mithril-aggregator/Cargo.toml mithril-common-musl.cargoArtifacts {};
          mithril-signer =
            buildPackageMusl ./mithril-signer/Cargo.toml mithril-common-musl.cargoArtifacts {};
          mithril-setup =
            buildPackageMusl ./mithril-setup/Cargo.toml mithril-common-musl.cargoArtifacts {};
          mithril-client-cli =
            buildPackageMusl ./mithril-client-cli/Cargo.toml mithril-common-musl.cargoArtifacts {
              pname = "mithril-client";
            };

        } // lib.optionalAttrs (pkgsWindows != null) {

          mithril-client-cli-windows =
            buildPackageWindows ./mithril-client-cli/Cargo.toml mithril-common-windows.cargoArtifacts {
              pname = "mithril-client";
            };

        } // lib.optionalAttrs (pkgsMusl == null) {

          mithril-client-cli =
            buildPackage ./mithril-client-cli/Cargo.toml mithril.cargoArtifacts {
              pname = "mithril-client";
            };

        };

        devShells.default = pkgsRustOverlay.mkShell {
          inputsFrom = [self'.packages.mithril-client-cli];

          # _FORTIFY_SOURCE=2 (injected by Nix fortify hardening) requires at least -O1;
          # the ci-tests cargo profile uses -O0, which causes jemalloc's autoconf configure
          # step to fail. Disable fortify in the dev shell to avoid this interaction.
          hardeningDisable = ["fortify"];

          nativeBuildInputs = [
            pkgsRustOverlay.cargo
            pkgsRustOverlay.rustc
            pkgsRustOverlay.libiconv
            config.treefmt.package
            pkgsRustOverlay.gnumake
            pkgsRustOverlay.cargo-edit
          ];

          shellHook = ''
            export RUST_BACKTRACE=1
            ln -sf ${config.treefmt.build.configFile} treefmt.toml
          '';
        };

        formatter = pkgsRustOverlay.writeShellApplication {
          name = "treefmt";
          text = "exec ${config.treefmt.package}/bin/treefmt";
        };

        treefmt = {
          programs.alejandra.enable = true;
          programs.rustfmt.enable = true;
          projectRootFile = "flake.nix";
        };
      };
    };
}
