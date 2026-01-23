#!/bin/sh

make -C Aurora
go build .

cd flatpak
./quickpak.sh
cd ..
