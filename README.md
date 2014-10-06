Pantz-PFlog-Stats
=================

OpenBSD PFLog stats perl script script from http://www.pantz.org/software/pf/pantzpfblockstats.html

Now has the beginnings of GeoIP support.

Getting the Maxmind GeoLite DB
------------------------------

On OpenBSD, after installing the geoip-* package, the tools by default expect files to be in `/usr/local/share/examples/GeoIP`:

	cd /usr/local/share/examples/GeoIP
	wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz
	for i in *.gz; do gunzip -f $i; done

Acknowledgements
----------------

This product includes GeoLite data created by MaxMind, available from
<a href="http://www.maxmind.com">http://www.maxmind.com</a>.

Also includes flags from http://www.famfamfam.com/lab/icons/flags/
