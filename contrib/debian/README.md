
Debian
====================
This directory contains files used to package raned/rane-qt
for Debian-based Linux systems. If you compile raned/rane-qt yourself, there are some useful files here.

## rane: URI support ##


rane-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install rane-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your rane-qt binary to `/usr/bin`
and the `../../share/pixmaps/rane128.png` to `/usr/share/pixmaps`

rane-qt.protocol (KDE)

