
use Net::DNS;
use Net::DNS::Packet;
use Net::DNS::RR;
use Data::Dumper;
use IO::Socket::INET;

$, = "    ";
$\ = "\n";
$timeout = 2;

($ListenPort,) = @ARGV;

sub getresolvers
{
	my $r = new Net::DNS::Resolver(config_file => "/etc/resolv.conf.dnsmus");
	my @nameservers = @{$r->{'nameservers'}};
	undef $r;
	return @nameservers;
}

sub serialize
{
	my $oref = shift;
	my %hash = %$oref;
	delete $hash{'rdata'};
	return join " ", map {"$_=".$hash{$_}} sort keys %hash;
}


my @upstream;

for my $resolver_addr (getresolvers)
{
	my $res = new Net::DNS::Resolver;
	$res->udp_timeout($timeout);
	$res->tcp_timeout($timeout);
	$res->retry(0);
	$res->retrans(0);
	$res->dnsrch(0);
	$res->nameservers($resolver_addr);
	push @upstream, {'res' => $res, };
}


my $socket = IO::Socket::INET->new(LocalAddr => '0.0.0.0', LocalPort => $ListenPort, Proto => 'udp') or die $!;

QUERY:
while(1)
{
	$socket->recv($incoming_packet_data, 1024);
	my $peer_address = $socket->peerhost();
	my $peer_port = $socket->peerport();
	
	my $incoming_packet = new Net::DNS::Packet(\$incoming_packet_data);
	if(not $incoming_packet)
	{
		warn "invalid DNS packet: $!\n";
		next;
	}
	print STDERR ">>> $peer_address:$peer_port", serialize $incoming_packet->{'header'};
	print STDERR "", serialize $_ for @{$incoming_packet->{'question'}};
	#warn Dumper $incoming_packet;
	
	for $upstream (@upstream)
	{
		$upstream->{'query'} = $upstream->{'res'}->bgsend($incoming_packet);
		$upstream->{'started'} = time;
	}
	
	my $preferred_upstream = \$upstream[0];
	
	RESPONSE:
	while(1)
	{
		my $busy = 0;
		UPSTEAM:
		for $upstream (@upstream)
		{
			my $res = $upstream->{'res'};
			my $query_handle = $upstream->{'query'};
			next UPSTEAM if not defined $query_handle;
			#print Dumper $query_handle;
			
			if($res->bgisready($query_handle))
			{
				my $response = $res->bgread($query_handle);
				#$response->print;
				$upstream->{'lastresponse'} = $response;
				my $header = $response->{'header'};
				
				#warn Dumper $response->answer;
				print STDERR "+++ $response->{'answerfrom'}", serialize $header;
				print STDERR "", serialize $_ for $response->answer;
				
				close $upstream->{'query'};
				undef $upstream->{'query'};
				
				if($header->{'rcode'} eq 'NOERROR'
				   and $header->{'ancount'} > 0
				  )
				{
					$preferred_upstream = \$upstream;
					last RESPONSE;
				}
			}
			else
			{
				#$res->print;
				if($upstream->{'started'} + $timeout < time)
				{
					$upstream->{'query'} = undef;
				}
				else
				{
					$busy++;
				}
			}
		}
		last RESPONSE if $busy == 0;
		sleep 0.1;
	}
	
	my $replied = 0;
	
	for $upstream ($$preferred_upstream, @upstream)
	{
		my $response_packet = $upstream->{'lastresponse'};
		if(defined $response_packet)
		{
			my $resolver_addr = $upstream->{'res'}->{'nameservers'}->[0];
			print STDERR "<<< $resolver_addr ...";
			my $rr = Net::DNS::RR->new("upstream-resolver-address. 0 CH TXT \"$resolver_addr\"");
			$response_packet->push(additional => $rr);
			#$response_packet->print;
			$socket->send($response_packet->data);
			$replied = 1;
			last;
		}
	}
	
	if(not $replied)
	{
		my $response_packet = new Net::DNS::Packet();
		$response_packet->{'header'}->{'qr'} = 1;
		$response_packet->{'header'}->{'ra'} = 1;
		$response_packet->{'header'}->{'rcode'} = 'SERVERR';
		$response_packet->{'header'}->{'id'} = $incoming_packet->{'header'}->{'id'};;
		my $rr = Net::DNS::RR->new("upstream-resolver-error. 0 CH TXT \"none of ".(scalar@upstream)." upstreams responded\"");
		$response_packet->push(additional => $rr);
		$response_packet->push(question => $_) for $incoming_packet->question;
		#$response_packet->print;
		$socket->send($response_packet->data);
	}
}

close $socket;
