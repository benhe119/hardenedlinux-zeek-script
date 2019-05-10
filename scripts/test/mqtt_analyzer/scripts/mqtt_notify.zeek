@load base/frameworks/notice
@load ./main.zeek

module MQTT;

export {
	redef enum Notice::Type += { 
		## Raised when a connect packet has protocol version
		## other than 3 and 4. 
		Invalid_protocolVersion,

		## Raised when a connect packet has protocol version
		## other than 'MQTT' and 'MQIsdp'. 
		Invalid_protocolId,

		## Raised when a subscribe packet has QoS which is not 1 
		Wrong_subscribe_header,
    };
}

event mqtt_conn(c: connection, msg_type: count, msg: MQTT::CONNECT)
{
	if ( msg$protocol_version != 3 && msg$protocol_version != 4 &&  msg$protocol_version != 5) {
	        NOTICE([$note=Invalid_protocolVersion,
                	$msg=fmt("%d is not a valid protocol version.",msg$ protocol_version),
                	$conn=c]);
        }
	
	if ( msg$protocol_name != "MQTT" && msg$protocol_name != "MQIsdp") {
	        NOTICE([$note=Invalid_protocolId,
                	$msg=fmt("%d is not a valid protocol version.", msg$protocol_name),
                	$conn=c]);
        }
}

event mqtt_sub(c: connection, msg_type: count, msg: MQTT::SUBSCRIBE)

    {
	if (msg$requested_qos != 1) {
	        NOTICE([$note=Wrong_subscribe_header,
                	$msg=fmt("%d is an invalid QoS to be requested.", msg$requested_qos),
                	$conn=c]);
        }
}
