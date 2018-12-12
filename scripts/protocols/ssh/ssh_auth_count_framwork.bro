#Written by Hardenedlinux 

@load packages/bro-sumstats-counttable

export {
  const epoch_interval = 3secs &redef;

  }
redef record SSH::Info  += {
  ssh_sucessful: count &optional &log;
  ssh_failures: count &optional &log;
  };
event bro_init()
	{
	local r1 = SumStats::Reducer($stream="status.ssh", $apply=set(SumStats::COUNTTABLE));
	

	SumStats::create([$name="ssh-connect",
		$epoch=1hr, $reducers=set(r1),
		$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	{
	if ( "status.ssh" !in result )
		return;
		local counttable = result["status.ssh"]$counttable;
		print fmt("Host: %s", key$host);
		for ( i in counttable )
			print fmt("status code: %s, count: %d", i, counttable[i]);
	    
		  
		  }]);
	    }


    event ssh_auth_failed(c:connection)
  {
  local id = c$ssh$client;
  SumStats::observe("status.ssh", [$host=c$id$resp_h], [$str=id]);
  }
