#!/usr/bin/perl
use Socket;
use Parallel::ForkManager;
use POSIX qw/strftime/;
use NetAddr::IP;

#$/ = undef; 
$port = 443;
$maxprocs = 10;
$pm = new Parallel::ForkManager($maxprocs);

$iprange = $ARGV[0];
unless ($iprange) { &usage; }

$ip = NetAddr::IP->new($iprange);
unless ($ip) { &usage; }


foreach $address (@{$ip->hostenumref}) {
  $address =~ s/(.*)\/.*/$1/;
  #print "$address\n"; exit;
  my $pid = $pm->start and next; 

  # send to subroutine  
  &lookup($address);
  $pm->finish;
  $pm->wait_all_children;
}

sub lookup {
  my $address = shift;
  #print "Address = $address\n"; 
  my $date =  strftime("%b %e %H:%m:%S %Y\n",localtime);
  chomp $date;
  my $host = gethostbyaddr(inet_aton($address),AF_INET);
  #print "Host = $host\n";

  #print STDERR "/bin/echo QUIT | ./timeout 2 /usr/bin/openssl s_client -showcerts -connect $address:$port 2>/dev/null\n";
  $input = `/bin/echo QUIT | ./timeout 2 /usr/bin/openssl s_client -showcerts -connect $address:$port 2>/dev/null`;

  if ($input !~ /^CONNECTED/) {
    print STDERR "Failed to connect to $address\n";
    exit;
    #die("Failed to connect $address\n");
  }

  #print "date\thost\taddress\tport\tindex\tsubject\tissuer\tstartdate\tenddate\tfingerprint\n";
  #print STDERR "$input";

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

sub usage {
  die "Usage: $0 <network>/<prefix>\n";
}
