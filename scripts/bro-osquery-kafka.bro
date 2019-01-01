@load /usr/local/bro/lib/bro/plugins/APACHE_KAFKA/scripts/Apache/Kafka
@load packages/bro-osquery-test
@load packages/bro-osquery-test/logging/tables/mounts.bro
@load packages/bro-osquery-test/logging/tables/listening_ports.bro

redef Kafka::topic_name = "";
redef Kafka::tag_json = T;

event bro_init() &priority=-10
  {

  ##osquery
  local filter_osquery: Log::Filter = [
$name = "osquery",
  $writer = Log::WRITER_KAFKAWRITER,
  $config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "osquery"
];
Log::add_filter(osquery::LOG, filter_osquery);

##osquery_hosts
local filter_osquery_hosts: Log::Filter = [
$name = "osquery_hosts",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "osquery_hosts"
];
Log::add_filter(osquery::hosts::LOG_SEND, filter_osquery_hosts);

##osquery_bros
local filter_osquery_bros: Log::Filter = [
$name = "osquery_bros",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "osquery_bros"
];
Log::add_filter (osquery::bros::LOG_SEND, filter_osquery_bros);

##osq-process_connections
local filter_osq_process_connections: Log::Filter = [
$name = "osq-process_connections",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "osq-process_connections"
];
Log::add_filter(osquery::process_connections::LOG, filter_osq_process_connections);

##osq-host_info
local filter_osq_host_info: Log::Filter = [
$name = "osq-host_info",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "osq-host_info"
];
Log::add_filter(osquery::host_info::LOG, filter_osq_host_info);

##osq-users
local filter_osq_users: Log::Filter = [
$name = "osq-users",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "osq-users"
];
Log::add_filter(osquery::logging::users::LOG, filter_osq_users);

##osq-socket_events
local filter_osq_socket_events: Log::Filter = [
$name = "osq-socket_events",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "osq-socket_events"
];
Log::add_filter(osquery::logging::socket_events::LOG, filter_osq_socket_events);

##osq-processes
local filter_osq_processes: Log::Filter = [
$name = "osq-processes",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "osq-processes"
];
Log::add_filter(osquery::logging::processes::LOG, filter_osq_processes);

##osq-process_open_sockets
local filter_osq_process_open_sockets: Log::Filter = [
$name = "osq-process_open_sockets",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "osq-process_open_sockets"
];
Log::add_filter(osquery::logging::process_open_sockets::LOG,filter_osq_process_open_sockets );

##osq-process_events
local filter_osq_process_events: Log::Filter = [
$name = "osq-process_events",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "osq-process_events"
];
Log::add_filter(osquery::logging::process_events::LOG,filter_osq_process_events );


##osq-mounts
local filter_osq_mounts: Log::Filter = [
$name = "osq-mounts",
$writer = Log::WRITER_KAFKAWRITER,
$config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "osq-mounts"
];
Log::add_filter(osquery::mount::LOG, filter_osq_mounts );

## listening_ports
local filter_listening_ports: Log::Filter = [
$name = "listening_ports",
  $writer = Log::WRITER_KAFKAWRITER,
  $config = table(
["metadata.broker.list"] = "localhost:9092"
),
$path = "osq-listening_ports"
];
Log::add_filter(osquery::listening::LOG, filter_listening_ports);

}