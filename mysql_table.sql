create table certificate (
  id int not null auto_increment,
  primary key(id),
  date_added datetime not null,
  hostname text not null,
  address int unsigned not null,
  port int not null,
  depth int not null,
  subject text not null,
  issuer text not null,
  startdate datetime not null,
  enddate datetime not null,
  fingerprint text(40) not null
) ENGINE MyISAM;
