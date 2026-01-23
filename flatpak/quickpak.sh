#!/bin/env sh
# just to script to help me not have to ctrl + r the command lol
set -x
FPBUILD=
if command -v flatpak-builder; then
  FPBUILD=$(command -v flatpak-builder)
else
  FPBUILD="flatpak run org.flatpak.Builder"
fi

$FPBUILD --force-clean build --install-deps-from=flathub --repo=repo hytaleSP.yaml --user
