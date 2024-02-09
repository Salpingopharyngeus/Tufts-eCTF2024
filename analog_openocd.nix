{ stdenv
, lib
, pkg-config
, hidapi
, jimtcl
, libjaylink
, libusb1
, libgpiod
, gcc
, gnumake
, coreutils
, autoconf
, automake
, texinfo
, git
, libtool
, which
, libftdi1
}:

stdenv.mkDerivation {
  pname = "openocd-analog";
  version = "0.12.0";

  src = builtins.fetchGit {
    url = "https://github.com/analogdevicesinc/openocd.git";
    ref = "release";
    submodules = true;
  };

  nativeBuiltInputs = [ pkg-config ];

  buildInputs = [
    hidapi
    gcc
    gnumake
    coreutils
    pkg-config
    autoconf
    automake
    texinfo
    git
    jimtcl
    libusb1
    libjaylink
    libftdi1
    libtool
    which
  ];

  postPatch = ''
    substituteInPlace src/jtag/drivers/libjaylink/autogen.sh --replace "LIBTOOLIZE=glibtoolize" "LIBTOOLIZE=libtoolize"
  '';

  enableParallelBuilding = true;

  configurePhase = ''
    SKIP_SUBMODULE=1 ./bootstrap
    ./configure --prefix=$out --disable-werror
  '';

   meta = with lib; {
    description = "OpenOCD fork for Analog Devices microcontrollers";
    longDescription = ''
      This is a fork of OpenOCD by ADI,
      which brings support to MAXIM MCUs microcontroller.
    '';
    homepage = "https://github.com/analogdevicesinc/openocd.git";
    license = licenses.gpl2Plus;
    maintainers = with maintainers; [ eCTF ];
  };
}