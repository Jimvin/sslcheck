#!/usr/bin/perl
use DBI;

# MySQL CONFIG VARIABLES
$host = "dbhost";
$database = "dbname";
$user = "dbuser";
$pw = "dbpass";
$datefmt = "%b %e %H:%i:%s %Y"; #Jun 27 13:58:30 2012 GMT

$dbh = DBI->connect("DBI:mysql:$database;host=$host", "$user", "$pw") || die "Could not connect to database: $DBI::errstr";


while(<>) {
  chomp($_);
  my ($rundate,$host,$address,$port,$index,$subject,$issuer,$startdate,$enddate,$fingerprint) = split("\t",$_);
  $sql = "insert into certificate values (null,str_to_date(?,'$datefmt'),?,inet_aton(?),?,?,?,?,str_to_date(?,'$datefmt'),str_to_date(?,'$datefmt'),?)";
  
  my $sth = $dbh->prepare($sql);
  $sth->execute($rundate,$host,$address,$port,$index,$subject,$issuer,$startdate,$enddate,$fingerprint);
}

$dbh->disconnect();

#Nov 21 22:11:12 2012	google.com	173.194.41.168	443	0	/C=US/ST=California/L=Mountain View/O=Google Inc/CN=*.google.com	/C=US/O=Google Inc/CN=Google Internet Authority	Oct 24 17:33:33 2012 GMT	Jun  7 19:43:27 2013 GMT	0191C523251E5A6F73391931AD394C8FEF1E9DB7

#+-------------+----------+------+-----+---------+----------------+
#| Field       | Type     | Null | Key | Default | Extra          |
#+-------------+----------+------+-----+---------+----------------+
#| id          | int(11)  | NO   | PRI | NULL    | auto_increment | 
#| date_added  | date     | NO   |     | NULL    |                | 
#| hostname    | text     | NO   |     | NULL    |                | 
#| address     | int(11)  | NO   |     | NULL    |                | 
#| port        | int(11)  | NO   |     | NULL    |                | 
#| depth       | int(11)  | NO   |     | NULL    |                | 
#| subject     | text     | NO   |     | NULL    |                | 
#| issuer      | text     | NO   |     | NULL    |                | 
#| startdate   | date     | NO   |     | NULL    |                | 
#| enddate     | date     | NO   |     | NULL    |                | 
#| fingerprint | tinytext | NO   |     | NULL    |                | 
#+-------------+----------+------+-----+---------+----------------+

