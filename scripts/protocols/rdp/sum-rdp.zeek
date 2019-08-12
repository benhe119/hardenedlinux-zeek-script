@load base/protocols/rdp
module HLRDP
export {
  redef enum Log::ID += { LOG };

  const epoch_interval = 10min &redef;

  type Info: record {
    host : addr &log;
    failed_count :count &log;
    sucess_count :count &log;
    request_count :count &log;
    };

  global log_rdp: event(rec: Info);

  }



SumStats::create([$name="sum-rdp",
		$epoch=epoch_interval,
	$reducers=set(r1,r2),
		$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	{
	if ( "failed.rdp" !in result )
		return;
		local failed_counttable = result["failed.rdp"]$counttable;
		local sucesscount = result["sucess.rdp"]$counttable;
		for ( i in counttable )
			for (k in sucesscount)
				Log::write(HLRDP::LOG, [$host=key$host,$failed_count=failed_counttable[i],$sucess_count=sucesscount[k]]);
		  }]);

	}

event rdp_connect_request: event(c: connection , cookie: string ){


}


event zeek_init()
    {
	Log::create_stream(HLRDP::LOG, [$columns=Info, $ev=log_rdp, $path="sum_ssh"]);
    local r1 = SumStats::Reducer($stream="failed.rdp", $apply=set(SumStats::COUNTTABLE));
	local r2 = SumStats::Reducer($stream="sucess.rdp", $apply=set(SumStats::COUNTTABLE));
    }

event rdp_negotiation_failure(c: connection, failure_code: count) &priority=5
	{
	set_session(c);

	c$rdp$result = failure_codes[failure_code];
    SumStats::observe("failed.rdp", [$host=c$rdp$resp_h], [$str=c$rdp$result]);

	}

event rdp_connect_request(c: connection, cookie: string) &priority=5
	{
	set_session(c);

	c$rdp$cookie = cookie;
    SumStats::observe("request.rdp", [$host=c$rdp$resp_h], [$str=c$rdp$cookie]);

	}
