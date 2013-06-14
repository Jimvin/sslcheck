sslcheck
========

Perl script to scrape SSL certificate data from web sites. There are two scripts to gather the data:

* forked_ssl.pl - takes a list of domain names and checks the SSL certificate on <domain> and www.<domain>
* iprange_ssl.pl -  takes a CIDR address range and scans it for SSL web servers

Output from both scripts is a tab-delimited list of values pertaining to any SSL certificates found.
Below is a list of the fields

1. date - date the SSL server was scanned
2. host - hostname scanned
3. address - IP address scanned
4. port - the TCP port
5. depth - depth in certificate validity chain
6. subject - subject line of the SSL certificate
7. start date - valid from date on certificate
8. end date - valid until date on certificate
9. fingerprint - certificate fingerprint

Additionally there are script from creating a table and loading this data into MySQL.
