#
# Test send_packet function
#
# Programmed by Bastian Ballmann
# Last update: 31.01.2007

use Net::ARP;
use Test::More qw( no_plan );

BEGIN
{
    eval{ require Net::Pcap; };
              
    if($@ =~ /^Can\'t\slocate/)
    {
        $dev = "eth0";
    }
    else
    {
   	import Net::Pcap;
        $dev = Net::Pcap::lookupdev(\$errbuf);
    }
}

print "Using device $dev to test send_packet()\n";

$ret = Net::ARP::send_packet("strange_dev",   # network interface
	      	      '127.0.0.1',            # source ip
	              '127.0.0.1',            # destination ip
		      'aa:bb:cc:aa:bb:cc',    # source mac
	              'ff:ff:ff:ff:ff:ff',    # destination mac
	              'reply');               # ARP operation 

ok( $ret == 0, "abort on strange dev value -> $ret" );


$ret = Net::ARP::send_packet($dev,            # network interface
	      	      'strange_src_ip',       # source ip
	              '127.0.0.1',            # destination ip
		      'aa:bb:cc:aa:bb:cc',    # source mac
	              'ff:ff:ff:ff:ff:ff',    # destination mac
	              'reply');               # ARP operation 

ok( $ret == 0, "abort on strange source ip value -> $ret" );


$ret = Net::ARP::send_packet($dev,            # network interface
	      	      '127.0.0.1',            # source ip
	              'strange_dst_ip',       # destination ip
		      'aa:bb:cc:aa:bb:cc',    # source mac
	              'ff:ff:ff:ff:ff:ff',    # destination mac
	              'reply');               # ARP operation 

ok( $ret == 0, "abort on strange destination ip value -> $ret" );


$ret = Net::ARP::send_packet($dev,            # network interface
	      	      '127.0.0.1',            # source ip
	              '127.0.0.1',            # destination ip
		      'strange_src_mac',      # source mac
	              'ff:ff:ff:ff:ff:ff',    # destination mac
	              'reply');               # ARP operation 

ok( $ret == 0, "abort on strange source mac value -> $ret" );


$ret = Net::ARP::send_packet($dev,            # network interface
	      	      '127.0.0.1',            # source ip
	              '127.0.0.1',            # destination ip
		      'aa:bb:cc:aa:bb:cc',    # source mac
	              'strange_dst_mac',      # destination mac
	              'reply');               # ARP operation 

ok( $ret == 0, "abort on strange destination mac value -> $ret" );

$ret = Net::ARP::send_packet($dev,            # network interface
		      '127.0.0.1',            # source ip
	              '127.0.0.1',            # destination ip
		      'aa:bb:cc:aa:bb:cc',    # source mac
	              'ff:ff:ff:ff:ff:ff',    # destination mac
	              'my_happy_arp_opcode'); # ARP operation 

ok( $ret == 1, "do not abort on strange arp op value -> $ret" );


