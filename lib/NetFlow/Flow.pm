package NetFlow::Flow;

# Copyright (c) 2014 Sean Malloy. All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#    - Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    - Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials provided
#      with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# ABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# Only works with Netflow V5.

use Moose;
use English qw( -no_match_vars );

our $VERSION = '0.01';

use Moose::Util::TypeConstraints;

subtype 'UnsignedInt'
    => as 'Int'
    => where { $_ > -1 }
    => message { "Number ($_) is not greater than -1" };

subtype 'UnsignedInt32Bit'
    => as 'UnsignedInt'
    => where { $_ < 4294967296 }
    => message { "Number ($_) is not less than 4294967296" };

subtype 'UnsignedInt16Bit'
    => as 'UnsignedInt'
    => where { $_ < 65536 }
    => message { "Number ($_) is not less than 65536" };

subtype 'UnsignedInt8Bit'
    => as 'UnsignedInt'
    => where { $_ < 256 }
    => message { "Number ($_) is not less than 256" };

subtype 'UnsignedInt4Bit'
    => as 'UnsignedInt'
    => where { $_ < 16 }
    => message { "Number ($_) is not less than 16" };

subtype 'IPAddress'
    => as 'Str'
    => where { $_ =~ /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/ }
    => message { "String ($_) is not a valid IP address" };

no Moose::Util::TypeConstraints;

has 'bytes'    => (isa => 'UnsignedInt32Bit', is => 'ro', required => 1); # total number of layer 3 bytes in the flow
has 'dstaddr'  => (isa => 'IPAddress',        is => 'ro', required => 1); # destination IP address
has 'dstas'    => (isa => 'UnsignedInt16Bit', is => 'ro', required => 1); # AS number of destination
has 'dstmask'  => (isa => 'UnsignedInt8Bit',  is => 'ro', required => 1); # destination address prefix mask bits
has 'dstport'  => (isa => 'UnsignedInt16Bit', is => 'ro', required => 1); # destination TCP/UDP port
has 'first'    => (isa => 'UnsignedInt32Bit', is => 'ro', required => 1); # sysuptime in milliseconds at start of flow
has 'input'    => (isa => 'UnsignedInt16Bit', is => 'ro', required => 1); # SNMP index of input interface
has 'last'     => (isa => 'UnsignedInt32Bit', is => 'ro', required => 1); # sysuptime in milliseconds at end of flow
has 'nexthop'  => (isa => 'IPAddress',        is => 'ro', required => 1); # IP address of next hop router
has 'output'   => (isa => 'UnsignedInt16Bit', is => 'ro', required => 1); # SNMP index of output interface
has 'packets'  => (isa => 'UnsignedInt32Bit', is => 'ro', required => 1); # total number of packets in the flow
has 'protocol' => (isa => 'UnsignedInt8Bit',  is => 'ro', required => 1); # IP protocol type
has 'srcaddr'  => (isa => 'IPAddress',        is => 'ro', required => 1); # source IP address
has 'srcas'    => (isa => 'UnsignedInt16Bit', is => 'ro', required => 1); # AS number of source
has 'srcmask'  => (isa => 'UnsignedInt8Bit',  is => 'ro', required => 1); # source address prefix mask bits
has 'srcport'  => (isa => 'UnsignedInt16Bit', is => 'ro', required => 1); # source TCP/UDP port
has 'tcpflags' => (isa => 'UnsignedInt8Bit',  is => 'ro', required => 1); # Cumulative OR of tcp flags
has 'tos'      => (isa => 'UnsignedInt8Bit',  is => 'ro', required => 1); # IP type of service

__PACKAGE__->meta->make_immutable;

1;

########## Pod Weaver Documentation ##########

# ABSTRACT: Perl extension for Netflow version 5 flow data

=pod

=head1 SYNOPSIS

  use NetFlow::Flow;

  # create object
  my $flow = NetFlow::Flow->new(
               bytes    => $doctets,
               dstaddr  => $dstaddr,
               dstas    => $dst_as,
               dstmask  => $dst_mask,
               dstport  => $dstport,
               first    => $first,
               input    => $input,
               last     => $last,
               nexthop  => $nexthop,
               output   => $output,
               packets  => $dpkts,
               protocol => $prot,
               srcaddr  => $srcaddr,
               srcas    => $src_as,
               srcmask  => $src_mask,
               srcport  => $srcport,
               tcpflags => $tcp_flags,
               tos      => $tos,
             );

  # access data from object
  print $flow->bytes(), "\n";
  print $flow->dstaddr(), "\n";
  print $flow->dstas(), "\n";
  print $flow->dstmask(), "\n";
  print $flow->dstport(), "\n";
  print $flow->first(), "\n";
  print $flow->input(), "\n";
  print $flow->last(), "\n";
  print $flow->nexthop(), "\n";
  print $flow->output(), "\n";
  print $flow->packets(), "\n";
  print $flow->protocol(), "\n";
  print $flow->srcaddr(), "\n";
  print $flow->srcas(), "\n";
  print $flow->srcmask(), "\n";
  print $flow->srcport(), "\n";
  print $flow->tcpflags(), "\n";
  print $flow->tos(), "\n";

=head1 DESCRIPTION

Object oriented module for storing and accessing Netflow version
5 flow data. Only provides a constructor and accessor methods. This
module is meant to be used with NetFlow::Packet and NetFlow::Parser.

=head1 SEE ALSO

Read the documentation for Perl modules
NetFlow::Packet and NetFlow::Parser.
  ...
=head1 BUGS

No known bugs at this time.

=cut

########## Pod Weaver Method Documentation ##########

=pod 

=method bytes

Returns the total number of bytes in the flow.

=method dstaddr

Returns the destination IPv4 addresss in dotted quad notation.

=method dstas

Returns the autonomous system number of the destination.

=method dstmask

Returns the destination address prefix mask bits. For example
returns 24 for 192.168.1.0/24.

=method dstport

Returns the destination TCP/UDP port number.

=method first

Returns the system up time in milliseconds at the start of the flow.

=method input

Returns the SNMP index of the input interface.

=method last

Returns the system up time in milliseconds when the last packet of the flow was received.

=method new

Returns a new NetFlow::Flow object. The parameters bytes, dstaddr, dstas, dstmask, dstport,
first, input, last, nexthop, output, packets, protocol, tcpflags, tos, srcaddr, srcas, srcmask,
and srcport are all required.

=method nexthop

Returns the IPv4 address of the next hop router in dotted quad notation.

=method output

Returns the SNMP index of the output interface.

=method packets

Returns the total number of packets in the flow.

=method protocol

Returns the IP protocol type. For example returns 6 for TCP and 17 for UDP.

=method srcaddr

Returns the source IPv4 addresss in dotted quad notation.

=method srcas

Returns the autonomous system number of the source.

=method srcmask

Returns the source address prefix mask bits. For example
returns 24 for 192.168.1.0/24.

=method srcport

Returns the source TCP/UDP port number.

=method tcpflags

Returns the cumulative OR of the TCP flags.

=method tos

Returns the IP type of service.

=cut

