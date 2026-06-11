{
  lib,
  stdenv,
  fetchurl,
  autoreconfHook,
  pkg-config,
  gettext,
  SDL,
  SDL_image,
  SDL_mixer,
  SDL_net,
  librsvg,
  libxml2,
  t4kcommon,
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "tuxmath";
  version = "2.0.3";

  src = fetchurl {
    url = "https://github.com/tux4kids/tuxmath/archive/refs/tags/upstream/${finalAttrs.version}.tar.gz";
    sha256 = "ab91bd6df17eb9377e5608701030bd32110a3588933bf0e4c26b5697fb2a4698";
    name = "${finalAttrs.pname}-${finalAttrs.version}.tar.gz";
  };

  NIX_CFLAGS_COMPILE = [ "-fcommon" "-std=gnu17" ];

  nativeBuildInputs = [
    autoreconfHook
    pkg-config
    gettext
  ];

  buildInputs = [
    SDL
    SDL_image
    SDL_mixer
    SDL_net
    librsvg
    libxml2
    t4kcommon
  ];

  postPatch = ''
    patchShebangs data/scripts/sed-linux.sh

    # fix PKG_CHECK_MODULES variable name (same bug as tuxtype)
    substituteInPlace configure.ac \
      --replace-fail 'CFLAGS="$CFLAGS $SDL_IMAGE"' 'CFLAGS="$CFLAGS $SDL_IMAGE_CFLAGS"'
  '';

  postInstall = ''
    install -Dm644 tuxmath.desktop -t $out/share/applications/
    install -Dm644 data/images/icons/icon.png $out/share/icons/hicolor/48x48/apps/tuxmath.png
    install -Dm644 data/images/icons/tuxmath.svg -t $out/share/icons/hicolor/scalable/apps/
  '';

  meta = {
    description = "Educational math game starring Tux the Linux penguin";
    longDescription = ''
      "Tux, of Math Command" ("TuxMath," for short) is an educational arcade
      game starring Tux, the Linux mascot! Based on the classic arcade game
      "Missile Command," Tux must defend his cities. In this case, though, he
      must do it by solving math problems.
    '';
    mainProgram = "tuxmath";
    homepage = "https://github.com/tux4kids/tuxmath";
    license = lib.licenses.gpl3Plus;
    platforms = lib.platforms.linux;
  };
})
