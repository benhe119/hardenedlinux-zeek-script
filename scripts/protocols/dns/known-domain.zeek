
##! logging.

@load base/utils/directions-and-hosts
@load base/frameworks/cluster

module Known;

export {
   	redef enum Log::ID += { DOMAIN_LOG };
	
	type DomainsInfo: record {

		ts:             time   &log;

		host:           addr   &log;

	    domain: string &log &optional;

	    # not_in_alexa :bool &log;
	    # found_dynamic :bool &log;
	};
	
	## The certificates whose existence should be logged and tracked.
	## Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS.
	option domain_tracking = ALL_HOSTS;

	## Toggles between different implementations of this script.
	## When true, use a Broker data store, else use a regular Zeek set
	## with keys uniformly distributed over proxy nodes in cluster
	## operation.
	const use_domain_store = T &redef;
	

	global domain_store: Cluster::StoreInfo;

	## The Broker topic name to use for :zeek:see:`Known::domain_store`.
	const domain_store_name = "zeek/known/domains" &redef;

	## The expiry interval of new entries in :zeek:see:`Known::domain_store`.
	## This also changes the interval at which domains get logged.
	option domain_store_expiry = 1day;

	## The timeout interval to use for operations against
	## :zeek:see:`Known::domain_store`.
	option domain_store_timeout = 15sec;

	## The set of all known certificates to store for preventing duplicate 
	## logging. It can also be used from other scripts to 
	## inspect if a certificate has been seen in use. The string value 
	## in the set is for storing the DER formatted certificate' SHA1 domain.
	##
	## In cluster operation, this set is uniformly distributed across
	## proxy nodes.
	global domains: set[addr] &create_expire=1day &redef;
	
	## Event that can be handled to access the loggable record as it is sent
	## on to the logging framework.
	global log_known_domains: event(rec: DomainsInfo);
}

event zeek_init()
	{
	if ( ! Known::use_domain_store )
		return;

	Known::domain_store = Cluster::create_store(Known::domain_store_name);
	}

event Known::domain_found(info: DomainsInfo)
    {
	if ( ! Known::use_domain_store )
		return;

	

	when ( local r = Broker::put_unique(Known::domain_store$store, info$host,
	                                    T, Known::domain_store_expiry) )
		{
		if ( r$status == Broker::SUCCESS )
			{
			if ( r$result as bool )
				Log::write(Known::DOMAIN_LOG, info);
			}
		else
			Reporter::error(fmt("%s: data store put_unique failure",
			                    Known::domain_store_name));
		}
	timeout Known::domain_store_timeout
		{
		# Can't really tell if master store ended up inserting a key.
		Log::write(Known::DOMAIN_LOG, info);
		}
    }

event known_domain_add(info: DomainsInfo)
	{
	if ( Known::use_domain_store )
		return;

	if ( [info$host] in Known::domains )
		return;

	add Known::domains[info$host];

	@if ( ! Cluster::is_enabled() ||
	      Cluster::local_node_type() == Cluster::PROXY )
		Log::write(Known::DOMAIN_LOG, info);
	@endif
	}

event Known::domain_found(info: DomainsInfo)
	{
	if ( Known::use_domain_store )
		return;

	if ( [info$host] in Known::domains )
		return;

	Cluster::publish_hrw(Cluster::proxy_pool, info$host, known_domain_add, info);
	event known_domain_add(info);
	}

event Cluster::node_up(name: string, id: string)
	{
	if ( Known::use_domain_store )
		return;

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	Known::domains = table();
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( Known::use_domain_store )
		return;

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	Known::domains = table();
	}


event zeek_init()
	{
	Log::create_stream(Known::DOMAIN_LOG, [$columns=DomainsInfo, $ev=log_known_domains, $path="known_domain"]);
	}



event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
	if(!c$dns?$query)
	    return;

	    local host = c$id$orig_h;

    	 for (domain in set(query))
		    if (  addr_matches_host(host, domain_tracking) )
				local info = DomainsInfo($ts = network_time(), $host = host, $domain = c$dns$query);
				event Known::domain_found(info);

}
