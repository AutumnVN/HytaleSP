#!/bin/sh

flatpak install org.freedesktop.Sdk//25.08 org.flatpak.Builder --system -y

cd flatpak || exit
./buildpak.sh
