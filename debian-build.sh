cd dist
cp /usr/lib/apache2/modules/mod_evasive.so libapache2-mod-evasive/usr/lib/apache2/modules/mod_evasive.so
dpkg-deb --build libapache2-mod-evasive
