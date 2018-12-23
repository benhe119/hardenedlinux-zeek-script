@load /usr/local/bro/lib/bro/plugins/APACHE_KAFKA/scripts/Apache/Kafka
redef Kafka::topic_name = "";
redef Kafka::tag_json = T;

@load ./protocols/



event bro_init() &priority=-10
  {

  
  ##protocols-stats-resp
  local protocols_resp: Log::Filter = [
$name = "protocols-r",
  $writer = Log::WRITER_KAFKAWRITER,
  $config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "protocols-resp"
];
Log::add_filter(ProtocolStats::RESP, protocols_resp);

##protocols-stats-orig
local protocols_orig: Log::Filter = [
$name = "protocols-o",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "protocols-orig"
];
Log::add_filter(ProtocolStats::ORIG, protocols_orig);
##ssl_ciphers
local ssl_ciphers: Log::Filter = [
$name = "ssl-ciphers",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "ssl-ciphers"
];
Log::add_filter(SSLCiphers::LOG, ssl_ciphers );

#UniqueMacs::LOG
local conn-macs: Log::Filter = [
$name = "UniqueMacs",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "unique-macs"
];
Log::add_filter(UniqueMacs::LOG,conn-macs );



# handles HTTP
local http_filter: Log::Filter = [
$name = "kafka-http",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "http"
];
Log::add_filter(HTTP::LOG, http_filter);

#handles software
local software_filter: Log::Filter = [
$name = "kafka-software",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "software"
];
Log::add_filter(Software::LOG, software_filter);

#SMTP
local smtp_filter: Log::Filter = [
$name = "kafka-smtp",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "smtp"
];
Log::add_filter(SMTP::LOG,smtp_filter );

#IRC
local irc_filter: Log::Filter = [
$name = "kafka-irc",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "irc"
];
Log::add_filter(IRC::LOG, irc_filter );

#handles pe
local pe_filter: Log::Filter = [
$name = "kafka-pe",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "pe"
];
Log::add_filter(PE::LOG, pe_filter );

#handles dhcp
local dhcp_filter: Log::Filter = [
$name = "kafka-dhcp",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "dhcp"
];
Log::add_filter(DHCP::LOG, dhcp_filter);

#handles ssh
local ssh_filter: Log::Filter = [
$name = "kafka-ssh",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "ssh"
];
Log::add_filter(SSH::LOG, ssh_filter );

# handles conn
local Conn_filter: Log::Filter = [
$name = "kafka-conn",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "conn"
];
Log::add_filter(Conn::LOG, Conn_filter );

# handles Notice
local Notice_filter: Log::Filter = [
$name = "kafka-Notice",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "notice"
];
Log::add_filter(Notice::LOG, Notice_filter);
# handles DNS
local dns_filter: Log::Filter = [
$name = "kafka-dns",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "dns"
];
Log::add_filter(DNS::LOG, dns_filter);


# MOCYBER::UNIQDNS_LOG
local dns_knowdomain: Log::Filter = [
$name = "known_domains",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "known_domains"
];
Log::add_filter(MOCYBER::UNIQDNS_LOG, dns_knowdomain);

# top-metrics url

local conn_top_urls: Log::Filter = [
$name = "conn_top_urls",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "top_urls"
];
Log::add_filter(TopMetrics::URLS, conn_top_urls);

# top-metrics url-talkes
local conn_top_talkers: Log::Filter = [
$name = "conn_top_talkers",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "top_talkers"
];
Log::add_filter(TopMetrics::TALKERS, conn_top_talkers);


#UniqueHosts::LOG

local conn_unique_host: Log::Filter = [
$name = "conn_host",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "unique-host"
];
Log::add_filter(UniqueHosts::LOG, conn_unique_host);

}
