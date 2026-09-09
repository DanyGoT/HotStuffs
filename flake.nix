{
  description = "Chained HotStuff on Gorums";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      forEach = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forEach (pkgs: {
        default = pkgs.mkShell {
          # protoc only; protoc-gen-go and protoc-gen-gorums come from go.mod
          # tool directives, so they stay pinned to the library they generate for.
          packages = [ pkgs.go pkgs.protobuf pkgs.gnumake ];
        };
      });
    };
}
