
Debian
====================
This directory contains files used to package tpfcoind/tpfcoin-qt
for Debian-based Linux systems. If you compile tpfcoind/tpfcoin-qt yourself, there are some useful files here.

## tpfcoin: URI support ##


tpfcoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install tpfcoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your tpfcoinqt binary to `/usr/bin`
and the `../../share/pixmaps/tpfcoin128.png` to `/usr/share/pixmaps`

tpfcoin-qt.protocol (KDE)

