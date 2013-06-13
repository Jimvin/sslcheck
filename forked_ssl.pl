#!/usr/bin/perl
use Socket;
use Parallel::ForkManager;
use POSIX qw/strftime/;

#$/ = undef; 
$port = 443;
$maxprocs = 5;
$pm = new Parallel::ForkManager($maxprocs);

while (<>) {
  $host = $_;
  chomp($host);
  $wwwhost = "www.$host";

  my $pid = $pm->start and next; 
  # send to subroutine  
  &lookup($host);
  &lookup("www." . $host);
  $pm->finish;
  $pm->wait_all_children;
}

sub lookup {
  my $host = shift;
  my $date =  strftime("%b %e %H:%m:%S %Y\n",localtime);
  chomp $date;
  my @addresses = gethostbyname($host);
  @addresses = map { inet_ntoa($_) } @addresses[4 .. $#addresses];

  foreach $address (@addresses) {
  $input = `/bin/echo QUIT | ./timeout 2 /usr/bin/openssl s_client -showcerts -connect $host:$port 2>/dev/null`;

  if ($input !~ /^CONNECTED/) {
    print STDERR "Failed to connect to $host\n";
    #die("Failed to connect\n");
  }

  #print "date\thost\taddress\tport\tindex\tsubject\tissuer\tstartdate\tenddate\tfingerprint\n";

  $input =~ /Certificate chain\n(.*?)\n---\n/s;
  my $chain = $1;
  $i = 0;
  while ($chain) {
    $chain =~ /(.*?-----END CERTIFICATE-----)\n*/s;
    $cert = $1;
  
    # Get certificate index
    $cert =~ /^\s*([0-9]*)/s;
    $index = $1;
    
    # Get certificate subject
    $cert =~ /s:(.*?)\n/s;
    $subject = $1;
  
    # Get certificate issuer
    $cert =~ /i:(.*?)\n/s;
    $issuer = $1;
  
    # Get fingerprint
    $data =  `/bin/echo "$cert" | openssl x509 -fingerprint -dates -out /dev/null`;
    $data =~ /SHA1 Fingerprint=(.*?)\n/m;
    $fingerprint = $1;
    $fingerprint =~ s/://g;
    $data =~ /notBefore=(.*?)\n/m;
    $startdate = $1;
    $data =~ /notAfter=(.*?)\n/m;
    $enddate = $1;
  
    #$certs[$i] = $1;
  
    print "$date\t$host\t$address\t$port\t$index\t$subject\t$issuer\t$startdate\t$enddate\t$fingerprint\n";

  
    $chain =~ s/.*?-----END CERTIFICATE-----\n*//s;
    $i++;
    }
  }
}
