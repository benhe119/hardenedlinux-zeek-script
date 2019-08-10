
##! Cluster::MANAGER
##! This script and concept stolen from [[https://github.com/dopheide-esnet/zeek-known-hosts-with-dns][dopheide-esnet/zeek-known-hosts-with-dns: This script expands the base known-hosts policy to include reverse DNS queries and syncs it across all workers.]]

@load base/frameworks/cluster
@load ../../frameworks/domain-tld/scripts
@load ./alexa/alexa_validation.zeek
@load ./dyndns.zeek
module Known;

export {
	redef enum Log::ID += { DOMAIN_LOG };
	
	type DomainsInfo: record {

		ts:           	 	time   		&log;

		host:           	addr   		&log;

		domain: 			string 		&log 	&optional;

		found_in_alexa:		bool 		&log;

		found_dynamic:		bool 		&log;
	};
	

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

	## The set of all known domains to store for preventing duplicate 
	## logging. It can also be used from other scripts to 
	## inspect if a certificate has been seen in use. The string value 
	## in the set is for storing the DER formatted certificate' SHA1 domain.
	##
	## In cluster operation, this set is uniformly distributed across
	## proxy nodes.
	global domains: set[string] &create_expire=1day &redef;
	global stored_domains: set[string];
	## Event that can be handled to access the loggable record as it is sent
	## on to the logging framework.
	global log_known_domains: event(rec: DomainsInfo);
	global Known::known_domain_add: event(info: DomainsInfo);

}


function known_relay_topic(): string{
	local rval = Cluster::rr_topic(Cluster::proxy_pool, "known_rr_key");

	if ( rval == "" )
		# No proxy is alive, so relay via manager instead.
		return Cluster::manager_topic;
	return rval;
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
@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )

	when ( local r = Broker::put_unique(Known::domain_store$store, info$domain,
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
		@if ( Cluster::local_node_type() == Cluster::MANAGER)
			# essentially, we're waiting for the asynchronous Broker calls to finish populating
			# the manager's Known::stored_hosts and then sending the table to the workers all at once
			schedule 30sec {Known::send_known()};
		@endif
	@endif	
    }

event known_domain_add(info: DomainsInfo)
	{
	if ( Known::use_domain_store )
		return;

	if ( [info$domain] in Known::domains )
		return;

	@if ( ! Cluster::is_enabled() ||
	Cluster::local_node_type() == Cluster::PROXY ||
	Cluster::local_node_type() == Cluster::MANAGER )
	Broker::publish(Cluster::worker_topic, Known::known_domain_add, info$domain);
	@else
		add Known::domains[info$domain];
	@endif
	}

event Known::domain_found(info: DomainsInfo)
	{
	if ( Known::use_domain_store )
		return;

	if ( [info$domain] in Known::domains )
		return;
	@if ( Cluster::local_node_type() == Cluster::WORKER )
	Broker::publish(known_relay_topic, info$domain, known_domain_add, info);
	@endif
	}



event Known::manager_to_workers(mydomains: set[string]){
	for (query in mydomains){
		add Known::domains[query];
	}
}
event Known::send_known(){
	Broker::publish(Cluster::worker_topic,Known::manager_to_workers,Known::stored_domains);
	# kill it, no longer needed
	Known::stored_domains = set();

}
event zeek_init()
	{
	Log::create_stream(Known::DOMAIN_LOG, [$columns=DomainsInfo, $ev=log_known_domains, $path="known_domain"]);
	}



# event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
# {
# 	if(!c$dns?$query)
# 	    return;

# 	local host = c$id$orig_h;

#     for (domain in set(query))
# 		if (  addr_matches_host(host, domain_tracking) )
# 			local info = DomainsInfo($ts = network_time(), $host = host, $domain = c$dns$query);
# 			event Known::domain_found(info);

# }

event DNS::log_dns(rec: DNS::Info)
{
	if (! rec?$query)
        return;
	local host = rec$id$orig_h;
	for ( domain in set(rec$query) )
	{
		if (domain !in Known::domains)
		{
		local split_domain = DomainTLD::effective_domain(domain);
		local not_ignore = T;
		for (dns in Alexa::ignore_dns)
			{
			if(split_domain == dns)
			not_ignore = F;
			}
		local dynamic = T;
		if (split_domain !in DynamicDNS::dyndns_domains)
				dynamic = F;    
		if ( !(split_domain in Alexa::alexa_table) && not_ignore)
			{
				local info = DomainsInfo($ts = network_time(), $host = host, $domain = split_domain, $found_in_alexa = F, $found_dynamic = dynamic);
				event Known::domain_found(info);
				@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER )
					Broker::publish(Cluster::manager_topic,Known::host_found,[$ts = network_time(), $host = host, $domain = split_domain, $found_in_alexa = F, $found_dynamic = dynamic]);				
				@endif
			}
			else
			{
				info = DomainsInfo($ts = network_time(), $host = host, $domain = split_domain, $found_in_alexa = T, $found_dynamic = dynamic);
				event Known::domain_found(info);
				@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER )
					Broker::publish(Cluster::manager_topic,Known::host_found,[$ts = network_time(), $host = host, $domain = split_domain, $found_in_alexa = T, $found_dynamic = dynamic]);				
				@endif
			}
		}
	}		
}