@load /usr/local/bro/lib/bro/plugins/APACHE_KAFKA/scripts/Apache/Kafka
@load /usr/local/bro/lib/bro/plugins/mitrecnd_HTTP2/scripts/http2
@load /usr/local/bro/lib/bro/plugins/CBro_MQTT/scripts/
@load ./protocols/
@load policy/misc/stats.bro
@load policy/protocols/conn/known-services.bro
@load ./files
redef Kafka::topic_name = "";
redef Kafka::tag_json = T;


redef Kafka::kafka_conf = table(
["metadata.broker.list"] = "localhost:9200"
);

event zeek_init() &priority=-10
{

#VirusTotal::LOG
local filter_virus_total: Log::Filter = [
  $name = "virustotal",
  $writer = Log::WRITER_KAFKAWRITER,
  $path = "virustotal"
];
Log::add_filter (VirusTotal::LOG, filter_virus_total);   
# Known::hash
local filter_known_hash: Log::Filter = [
  $name = "known_hash",
  $writer = Log::WRITER_KAFKAWRITER,
  $path = "known_hash"
];
Log::add_filter (Known::HASH_LOG, filter_known_hash);

# Known::hosts
local filter_known_hosts: Log::Filter = [
    $name = "known_hosts",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "known_hosts"
];
Log::add_filter (Known::HOSTS_LOG, filter_known_hosts);

# Known::domains
local filter_known_domains: Log::Filter = [
    $name = "known_domains",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "known_domains"
];
Log::add_filter (Known::DOMAIN_LOG, filter_known_domains);

#smb_mapping
local filter_smb_mapping: Log::Filter = [
    $name = "filter_smb_mapping",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "smb_mapping"
];
Log::add_filter(SMB::MAPPING_LOG, filter_smb_mapping);
#smb_files
local filter_smb_files: Log::Filter = [
    $name = "filter_smb_files",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "smb_files"
];
Log::add_filter(SMB::FILES_LOG, filter_smb_files );
#files_identified
local filter_files: Log::Filter = [
    $name = "filter_files",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "files_identified"
];
Log::add_filter(Files::LOG, filter_files );
#known_services
local filter_known_services: Log::Filter = [
    $name = "filter_known_services",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "known_services"
];
Log::add_filter(Known::SERVICES_LOG, filter_known_services );
#SOCKS
local filter_socks: Log::Filter = [
    $name = "kafka-socks",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "socks"
];
Log::add_filter(SOCKS::LOG, filter_socks );
#	SNMP
local filter_SNMP: Log::Filter = [
    $name = "kafka_snmp",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "snmp"
];
Log::add_filter(SNMP::LOG, filter_SNMP );
#DNP3
local filter_dnp3: Log::Filter = [
    $name = "dnp3",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "dnp3"
];
Log::add_filter(DNP3::LOG, filter_dnp3 );
#FTP
local filter_FTP: Log::Filter = [
    $name = "kafka-ftp",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "ftp"
];
Log::add_filter(FTP::LOG, filter_FTP );
#MySQL
local filter_mysql: Log::Filter = [
    $name = "kafka-mysql",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "mysql"
];
Log::add_filter(mysql::LOG,filter_mysql );
#Status
local filter_stats: Log::Filter = [
    $name = "kafka-status",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "stats"
];
Log::add_filter(Stats::LOG, filter_stats );
#Broker
local filter_broker: Log::Filter = [
    $name = "broker",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "broker"
];
Log::add_filter(Broker::LOG, filter_broker );
#intel
local filter_intel: Log::Filter = [
    $name = "kafka-intel",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "intel"
];
Log::add_filter(Intel::LOG, filter_intel);
##x509
local filter_x509: Log::Filter = [
    $name = "kafka-x509",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "x509"
];
Log::add_filter(X509::LOG, filter_x509 );
##ssl
local filter_ssl: Log::Filter = [
    $name = "kafka_ssl",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "ssl"
];
Log::add_filter(SSL::LOG, filter_ssl );
##ssh-status
local filter_ssh: Log::Filter = [
    $name = "ssh-status",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "auth_ssh"
];
Log::add_filter(HSSH::LOG, filter_ssh );
##Hash-fuzzing
##top_dns
local filter_top_dns: Log::Filter = [
    $name = "top-dns",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "top_dns"
];
Log::add_filter(TopDNS::LOG,filter_top_dns );
## mqtt
local filter_mqtt : Log::Filter = [
    $name = "mqtt",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "mqtt"
];
Log::add_filter(MQTT::LOG, filter_mqtt);
## Http2
local filter_http2: Log::Filter = [
    $name = "http2",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "http2"
];
Log::add_filter(HTTP2::LOG, filter_http2 );
##protocols-stats-resp
local protocols_resp: Log::Filter = [
    $name = "protocols-resp",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "protocols-resp"
];
Log::add_filter(ProtocolStats::RESP, protocols_resp);

##protocols-stats-orig
local protocols_orig: Log::Filter = [
    $name = "protocols-o",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "protocols-orig"
];
Log::add_filter(ProtocolStats::ORIG, protocols_orig);

##ssl_ciphers
local ssl_ciphers: Log::Filter = [
    $name = "ssl-ciphers",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "ssl-ciphers"
];
Log::add_filter(SSLCiphers::LOG, ssl_ciphers );

#UniqueMacs::LOG
local conn_macs: Log::Filter = [
    $name = "conn_macs",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "unique-macs"
];
Log::add_filter(UniqueMacs::LOG,conn_macs );
# handles HTTP
local http_filter: Log::Filter = [
    $name = "kafka-http",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "http"
];
Log::add_filter(HTTP::LOG, http_filter);

#handles software
local software_filter: Log::Filter = [
    $name = "kafka-software",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "software"
];
Log::add_filter(Software::LOG, software_filter);

#SMTP
local smtp_filter: Log::Filter = [
    $name = "kafka-smtp",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "smtp"
];
Log::add_filter(SMTP::LOG,smtp_filter );

#IRC
local irc_filter: Log::Filter = [
    $name = "kafka-irc",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "irc"
];
Log::add_filter(IRC::LOG, irc_filter );

#handles pe
local pe_filter: Log::Filter = [
    $name = "kafka-pe",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "pe"
];
Log::add_filter(PE::LOG, pe_filter );
#handles dhcp
local dhcp_filter: Log::Filter = [
    $name = "kafka-dhcp",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "dhcp"
];
Log::add_filter(DHCP::LOG, dhcp_filter);

#handles ssh
local ssh_filter: Log::Filter = [
    $name = "kafka-ssh",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "ssh"
];
Log::add_filter(SSH::LOG, ssh_filter );

# handles conn
local Conn_filter: Log::Filter = [
    $name = "kafka-conn",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "conn"
];
Log::add_filter(Conn::LOG, Conn_filter );

# handles Notice
local Notice_filter: Log::Filter = [
    $name = "kafka-Notice",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "notice"
];
Log::add_filter(Notice::LOG, Notice_filter);

# handles DNS
local dns_filter: Log::Filter = [
    $name = "kafka-dns",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "dns"
];
Log::add_filter(DNS::LOG, dns_filter);


# top-metrics url
local conn_top_urls: Log::Filter = [
    $name = "conn_top_urls",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "top_urls"
];
Log::add_filter(TopMetrics::URLS, conn_top_urls);

# top-metrics url-talkes
local conn_top_talkers: Log::Filter = [
    $name = "conn_top_talkers",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "top_talkers"
];
Log::add_filter(TopMetrics::TALKERS, conn_top_talkers);

#UniqueHosts::LOG
local conn_host: Log::Filter = [
    $name = "conn_host",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "unique-host"
];
Log::add_filter(UniqueHosts::LOG, conn_host);
}
