{ pkgs ? import <nixpkgs> {}
  , fetchgit ? pkgs.fetchgit
}:

pkgs.mkShell {
  buildInputs = [
    pkgs.gnumake
    pkgs.python39
    pkgs.gcc-arm-embedded
    pkgs.poetry
    pkgs.cacert
    #(pkgs.callPackage analog_openocd.nix { })
    pkgs.minicom
  ];

  msdk = builtins.fetchGit {
    url = "https://github.com/Analog-Devices-MSDK/msdk.git";
    ref = "refs/tags/v2023_06";
  };
  shellHook =
    ''
      cp -r $msdk $PWD/msdk
      chmod -R u+rwX,go+rX,go-w $PWD/msdk
      export MAXIM_PATH=$PWD/msdk
    '';
}