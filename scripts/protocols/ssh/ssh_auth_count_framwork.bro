#Written by Hardenedlinux 


@load ../../frameworks/countabble.bro

module HSSH;
export {
  redef enum Log::ID += { LOG };

  const epoch_interval = 10min &redef;
  
  type Info: record {
    host : addr &log;
    failed_count :count &log;
    
    };

  global log_mqtt: event(rec: Info);

  }
event bro_init()
	{
	Log::create_stream(HSSH::LOG, [$columns=Info, $ev=log_mqtt, $path="status_ssh"]);

	local r1 = SumStats::Reducer($stream="status.ssh", $apply=set(SumStats::COUNTTABLE));

	SumStats::create([$name="ssh-connect",
		$epoch=epoch_interval, 
	$reducers=set(r1),
		$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	{
	if ( "status.ssh" !in result )
		return;
		local counttable = result["status.ssh"]$counttable;
		
		for ( i in counttable )
					
		  Log::write(HSSH::LOG, [$host=key$host,$failed_count=counttable[i]]);
		  }]);
		  
	    }

    event ssh_auth_failed(c:connection)
  {
  local id = c$ssh$client;
  SumStats::observe("status.ssh", [$host=c$id$resp_h], [$str=id]);
  }
