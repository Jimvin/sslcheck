#!/usr/bin/perl
use warnings;
use Socket;
use Parallel::ForkManager;
use POSIX qw/strftime/;
use FileHandle;
use IPC::Open2;

#$/ = undef; 
$port = 443;
$maxprocs = 10;
$pm = new Parallel::ForkManager($maxprocs);

while (<>) {
  $host = $_;
  chomp($host);
  #$wwwhost = "www.$host";

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
  $input = `/bin/echo QUIT | /usr/bin/timeout 2 /usr/bin/openssl s_client -showcerts -connect $host:$port 2>/dev/null`;

  if ($input !~ /^CONNECTED/) {
    print STDERR "Failed to connect to $host\n";
    #die("Failed to connect\n");
  }

  $input =~ /Certificate chain\n(.*?)\n---\n/s;
  my $chain = $1;
  $i = 0;
  while ($chain) {
    my ($cert, $index, $subject, $issuer,$startdate,$enddate,$data) = "";
    $chain =~ /(.*?-----END CERTIFICATE-----)\n*/s;
    $cert = $1;
    if (!$cert) {
      print STDERR "No certificate found for $host:$port\n";
      last;
    }
  
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
    #open OUT, "/usr/bin/openssl x509 -fingerprint -dates -out /dev/null<";
    $cmd = "/usr/bin/openssl x509 -fingerprint -dates -out /dev/null";
    open2(*IN, *OUT, $cmd);

    print OUT "$cert\n";
    while (<IN>) {
      $data .= $_;
    }
    close(IN);
    close(OUT);

    $data =~ /SHA1 Fingerprint=(.*?)\n/m;
    $fingerprint = $1;
    $fingerprint =~ s/://g;
    $data =~ /notBefore=(.*?)\n/m;
    $startdate = $1;
    $data =~ /notAfter=(.*?)\n/m;
    $enddate = $1;
  
    #$certs[$i] = $1;
  
    #$separator = chr(0x1);
    $separator = "\t";
    @data = ($date,$host,$address,$port,$index,$subject,$issuer,$startdate,$enddate,$fingerprint);
    print join($separator,@data) . "\n";
    #print "$date$separator$host$separator$address$separator$port$separator$index$separator$subject$separator$issuer$separator$startdate$separator$enddate$separator$fingerprint\n";

  
    $chain =~ s/.*?-----END CERTIFICATE-----\n*//s;
    $i++;
    }
  }
}
