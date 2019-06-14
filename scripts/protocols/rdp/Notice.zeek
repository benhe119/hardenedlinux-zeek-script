@load base/frameworks/notice
@load ./main.zeek
@load base/protocols/rdp

# [[https://packetstormsecurity.com/files/153133/Microsoft-Windows-Remote-Desktop-BlueKeep-Denial-Of-Service.html][Microsoft Windows Remote Desktop BlueKeep Denial Of Service ≈ Packet Storm]]
# [[https://www.cvedetails.com/cve/CVE-2019-0708/][CVE-2019-0708 : A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when an unau]]
module HLRDP;

export {
	redef enum Notice::Type += {

		Val_RDP_SSL,

            Val_RDP_Length,


		        Val_RDP_Neg,

                    Val_RDP_Build,
    };
}



event rdp_negotiation_response(c: connection, security_protocol: count) &priority=5
    {

    }


event rdp_server_certificate(c: connection, cert_type: count, permanently_issued: bool) &priority=5
    {
     NOTICE([$note=Val_RDP_SSL,
                	$msg=fmt("",),
                	$conn=c]);
    }
