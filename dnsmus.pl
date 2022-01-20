#!/usr/bin/env perl

use Net::DNS;
use Net::DNS::Packet;
use Net::DNS::RR;
use Data::Dumper;
use IO::Socket::INET;
use threads 'exit'=>'threads_only';
use threads::shared;
use Socket qw(pack_sockaddr_in);

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

sub request_handler
{
	my $socket = shift;
	my $peer_address = shift;
	my $peer_port = shift;
	my $incoming_packet_data = shift;
	my $upstream_ref = shift;
	my @upstream = @$upstream_ref;
	
	my $incoming_packet = new Net::DNS::Packet(\$incoming_packet_data);
	if(not $incoming_packet)
	{
		warn $!;
		return;
	}
	print STDERR ">>> $peer_address:$peer_port", serialize $incoming_packet->{'header'};
	print STDERR "", serialize $_ for @{$incoming_packet->{'question'}};
	#warn Dumper $incoming_packet;
	
	my @forward;
	
	for my $upstream (@upstream)
	{
		my $forward = {};
		$forward->{'query'} = $upstream->{'res'}->bgsend($incoming_packet);
		$forward->{'started'} = time;
		$forward->{'upstream'} = $upstream;
		push @forward, $forward;
	}
	
	my $preferred = \$forward[0];
	
	RESPONSE:
	while(1)
	{
		my $busy = 0;
		UPSTEAM:
		for my $forward (@forward)
		{
			my $upstream = $forward->{'upstream'};
			my $res = $upstream->{'res'};
			my $query_handle = $forward->{'query'};
			next UPSTEAM if not defined $query_handle;
			#print Dumper $query_handle;
			
			if($res->bgisready($query_handle))
			{
				my $response = $res->bgread($query_handle);
				#$response->print;
				$forward->{'lastresponse'} = $response;
				my $header = $response->{'header'};
				
				#warn Dumper $response->answer;
				print STDERR "+++ $response->{'answerfrom'}", serialize $header;
				print STDERR "", serialize $_ for $response->answer;
				
				close $forward->{'query'};
				
				if($header->{'rcode'} eq 'NOERROR'
				   and $header->{'ancount'} > 0
				  )
				{
					$preferred = \$forward;
					last RESPONSE;
				}
			}
			else
			{
				#$res->print;
				if($forward->{'started'} + $timeout < time)
				{
					$forward->{'query'} = undef;
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
	my $dest_sock_addr = pack_sockaddr_in($peer_port, inet_aton($peer_address));
	
	for my $forward ($$preferred, @forward)
	{
		my $response_packet = $forward->{'lastresponse'};
		if(defined $response_packet)
		{
			my $upstream = $forward->{'upstream'};
			my $resolver_addr = $upstream->{'res'}->{'nameservers'}->[0];
			print STDERR "<<< $resolver_addr ...";
			my $rr = Net::DNS::RR->new("upstream-resolver-address. 0 CH TXT \"$resolver_addr\"");
			$response_packet->push(additional => $rr);
			#$response_packet->print;
			$socket->send($response_packet->data, undef, $dest_sock_addr);
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
		$socket->send($response_packet->data, undef, $dest_sock_addr);
	}
}


my @upstream;
share @upstream;

for my $resolver_addr (getresolvers)
{
	my $res = new Net::DNS::Resolver;
	$res->udp_timeout($timeout);
	$res->tcp_timeout($timeout);
	$res->retry(0);
	$res->retrans(0);
	$res->dnsrch(0);
	$res->nameservers($resolver_addr);
	push @upstream, shared_clone({'res' => $res, });
}


my $socket = IO::Socket::INET->new(
	LocalAddr => '0.0.0.0',
	LocalPort => $ListenPort,
	Proto => 'udp',
	ReuseAddr => 1,
) or die $!;

QUERY:
while(1)
{
	my $incoming_packet_data;
	$socket->recv($incoming_packet_data, 1024);
	my $peer_address = $socket->peerhost();
	my $peer_port = $socket->peerport();
	threads->create(\&request_handler, $socket, $peer_address, $peer_port, $incoming_packet_data, \@upstream);
}

close $socket;

