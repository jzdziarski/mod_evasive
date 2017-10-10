#!/usr/bin/perl

# test.pl: small script to test mod_evasive's effectiveness
# - requires virtualhosts a.site and b.site to be setup, each with their own mod_evasive config
# - requires a.site and b.site to be added to hosts file (probably)

use IO::Socket;
use strict;

sub request {
	my($address,$i) = @_;
  my($response);
  my($SOCKET) = new IO::Socket::INET( Proto   => "tcp",
                                      PeerAddr=> "127.0.0.1:80");
  if (! defined $SOCKET) { die $!; }
  print $SOCKET "GET /?$i HTTP/1.1\r\n";
  print $SOCKET "Host: $address\r\n\r\n";
  $response = <$SOCKET>;
  print $address . ": " . $response;
  close($SOCKET);
}

for(0..100) {
	request "a.site", $_;
}
for(0..50) {
	request "b.site", $_;
}
