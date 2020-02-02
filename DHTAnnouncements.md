% DHT Announcements

CC-BY-SA: This work is licensed under the Creative Commons 
Attribution-ShareAlike 4.0 International License. To view a copy of this 
license, visit <http://creativecommons.org/licenses/by-sa/4.0/>.

# Introduction
Currently, toxcore uses onion routing in the process of establishing 
connections between friends, with the aim of obscuring their identities from 
third parties. However, this method does not achieve this goal. This document 
describes a proposed replacement for onion routing.

This proposal is adapted from an original proposal by grayhatter
<https://wiki.cmdline.org/doku.php?id=dht:new_friend_finding>.

The aim of the DHT Announcements protocol described by this document is to 
permit friends to exchange the connection information necessary to establish a 
direct connection between them, without revealing to third parties any 
information which could be used to identify or track them. Such information 
includes their long-term encryption keys and friend networks, but is assumed 
*not* to include the IP addresses from which they connect to the tox network.

The onion routing system has similar aims, but achieves them only under the 
assumption that the DHT nodes used by the user are not conspiring. Given the 
possibility of Sybil and eclipse attacks, this is not a reasonable assumption.

See 
<https://github.com/zugz/tox-alliumSchmallium/raw/master/alliumSchmallium.pdf>
for further discussion on the motivation for replacing the onion, and 
constraints on possible replacements.

## Remark on IP addresses

As with other parts of the tox protocol (namely, finding friends by DHT 
pubkey, hole punching, and connecting to friends via a TCP server), the DHT 
Announcements system makes no attempt to prevent third parties from observing 
pairs of IP addresses being used by tox friends. An attacker with moderate 
resources could accumulate a lot of such information. To protect against this, 
users must rely on existing techniques to minimise the extent to which an IP 
address identifies a user, such as regular permutation of IP addresses within 
a large pool, mitigation of tracking techniques like http cookies, and 
anonymising relays such as Tor or VPNs.

## User-visible changes

Unlike the onion, DHT Announcements do not support friend requests. Instead, 
to add a friend, you add their ToxID and they add yours.

Alternatively, you can create an 'invite code' and send it out-of-band to a 
friend, who can then use it to add you without you having to know their ToxID.
Similarly, bots can set things up so that anyone can add them.

This system does not use any "nospam" -- the ToxID of a peer is just their 
long-term ID public key with a checksum. This makes it easy to introduce 
existing friends to each other.

There should be considerable bandwidth reductions in typical usage.

The user's system clock must be reasonably close to the correct time.

## High-level description of the system
DHT nodes permit storing small quantities of world-readable data, termed
"announcements". Using this, we "announce" ourselves by placing our connection 
info on the DHT for our friends to find. These announcements are encrypted 
such that only the intended recipient(s) can read them, and signed where 
appropriate. The DHT locations of these announcements are determined in such a 
way that the intended recipients can find them, but others can't determine our 
long-term identity based on the location. To prevent tracking us across 
sessions based on where we announce, the locations vary with time. When making 
the first connection with a new friend, the location is derived from the 
combined key based on our ID keypairs. To keep the costs of announcements 
under control, for subsequent connections to the friend we announce only to a 
"shared" announcement location which is used for all such friends.

In a separate mode intended for bots, peers can also announce at a "public" 
announcement location which is just the peers's ID public key, giving up all 
privacy guarantees in exchange for allowing arbitrary peers to find them.

# Announcements

## Overview
We add to the DHT the capacity to allow arbitrary nodes to store small amounts 
of world-readable data, called **announcements**, for a short length of time, 
keyed to a Public Key for which the storer must have the Secret Key.

## Protocol
We introduce a generic protocol for data retrieval, since we may wish to reuse 
it in the future for other purposes, but we use packets specific to the 
current application for storing announcements.

Data is indexed by a Curve25519 public key, called the Data Public Key. In the 
case of announcements, we refer to this as the Announcement Public Key, for 
which the announcer should have the corresponding Announcement Secret Key.

### Timed authenticators
The **timed authenticator** (or **Timed Auth**) of a bytestring with a certain 
timeout `timeout` is the 32-byte HMAC-SHA-512256 authenticator of the 
concatenation of `unix_time/timeout` as a `uint64_t` and the bytestring, using 
a secret key held for this exclusive purpose.

To verify a purported timed authenticator of a bytestring, a node uses their 
secret key to generate the timed authenticator for the current time and also 
that for `timeout` seconds prior, and considers the authenticator valid if it 
is equal to either of these.

### Data Search Request and Response
These packets form an RPC DHT Packet pair.

#### Data Search Request
| Length | Type       | Contents        |
|:-------|:-----------|:----------------|
| `32`   | Public Key | Data Public Key |

#### Data Search Response

| Length     | Type       | Contents                                    |
|:-----------|:-----------|:--------------------------------------------|
| `32`       | Public Key | Data public key                             |
| `1`        | Bool       | Data is stored by this node                 |
| `0 | 32`   | Bytes      | SHA256 of data if stored                    |
| `32`       | Timed Auth | Timed authenticator                         |
| `1`        | Byte       | Data types currently accepted               |
| `1`        | Int        | Number of nodes in the response (maximum 4) |
| `[0, 204]` | Node Infos | Nodes in Packed Node Format                 |

The "data types currently accepted" should have least significant bit set
if and only if a Store Announcement request received now for this data public 
key would result in the announcement being stored, whatever the size of the 
announcement (up to the maximum of 512 bytes). This does not consitute a 
promise to accept a subsequent Store Announcement request. Other bits are 
reserved for possible future types of storage request.

The Timed Auth is the timed authenticator of the concatenation of the data 
public key in the request, the requester's DHT public key, the source IP/Port, 
and, in the case that the request is received as a forwarded packet (see 
below), the sendback.

The timeout of this timed authenticator is 60s.

The nodes returned are those announce nodes (at most 4) closest to the Data 
Public Key known by the responding node (see [Finding announce nodes]).

Note: as with Nodes requests, this part of the protocol is susceptible to UDP 
amplification abuse. Including all overheads (8 bytes for RPC Packet, 72 for 
DHT Packet, 8 for UDP header, 20 for IPv4 header), the minimum size of a 
request is 140 bytes, and the maximum size of a response is 411 bytes, giving 
an amplification ratio of 2.9. Hopefully not high enough to be useful.

### Data Retrieve Request and Response
These packets form an RPC DHT Packet pair.

#### Data Retrieve Request
| Length | Type       | Contents            |
|:-------|:-----------|:--------------------|
| `32`   | Public Key | Data public key     |
| `32`   | Timed Auth | Timed Authenticator |

The Timed Auth should be set to the timed authenticator obtained from a recent 
Data Search response to a search for the same data public key, and should be 
validated by the recipient. This check is to prevent redirection of the 
response to a forged IP address, which could be used for a UDP amplification 
attack.

#### Data Retrieve Response
| Length | Type       | Contents        |
|:-------|:-----------|:----------------|
| `32`   | Public Key | Data public key |
| `1`    | Bool       | Data found      |
| `[0,]` | Bytes      | Data            |


### Store Announcement Request and Response
These packets form an RPC DHT Packet pair.

#### Store Announcement Request

| Length       | Type         | Contents                  |
|:-------------|:-------------|:--------------------------|
| `32`         | Public Key   | Announcement public key   |
| `24`         | Nonce        | Random nonce              |
| `[49,561]`   | Bytes        | Encrypted payload         |

The payload is authenticated and encrypted with the announcement secret key 
and the recipient's DHT public key and the given nonce, and consists of a Ping 
ID, a requested timeout, and an announcement:

| Length    | Type       | Contents            |
|:----------|:-----------|:--------------------|
| `32`      | Timed Auth | Timed authenticator |
| `4`       | `uint32_t` | Requested timeout   |
| `1`       | Bytes      | Announcement Type   |
| `[0-512]` | Bytes      | Announcement Data   |

The Timed Auth should be set to the timed authenticator obtained from a recent 
Data Search response to a search for the same data public key. The recipient 
checks that this is valid before responding. This check is to prevent replay 
of old announcements.

The requested timeout is the time in seconds for which it is requested that 
the announcement be stored.

The announcement type is 0 for an initial announcement or 1 for a 
reannouncement.

For an initial announcement, the announcement data is the announcement we wish 
to be stored.

For a reannouncement, the announcement data is the SHA256 hash of an 
announcement sent in a previous initial announcement. This is used to extend 
the lifetime of an announcement without wastefully resending the whole 
announcement.

#### Store Announcement Response

| Length | Type       | Contents                |
|:-------|:-----------|:------------------------|
| `32`   | Public Key | Announcement public key |
| `4`    | `uint32_t` | Stored time             |

The stored time is 0 if the announcement request was rejected, else the time 
in seconds that the announcement will be stored for.

### Storing announcements
Memory permitting, a DHT node should accept any Store Announcement request and 
store the announcement indexed by the announcement public key with the 
lifetime requested up to a maximum of 900 seconds, and then respond with it to 
any valid Data Retrieve request for it within its lifetime. After the lifetime 
has expired, the data should be deleted. A reannouncement with the hash of an 
undeleted announcement may extend the lifetime of the announcement to up to 
900 seconds. A reannouncement with an incorrect hash should lead to the 
announcement being immediately deleted.

When choosing what to store within given storage constraints, a node should 
prefer to store those announcements with public keys closest to the node's DHT 
public key. So a node should attempt to satisfy a Store Announcement request 
by deleting as necessary some stored announcements which are furthest from the 
node's key and which are further from the node's key than the announcement 
public key.

Announcements need not be handled as secure data; in particular, "deleting" an 
announcement just means that it should then not be considered to be stored for 
the purposes of the protocol, rather than that the information must be 
securely erased.

### Forwarding
For various reasons, peers differ in which DHT nodes they are able to connect 
to. In particular, the close list of a DHT node may well include nodes which 
are behind NAT and can't be accessed by most peers. So to reduce the effect 
that our position in the DHT has on which announce nodes we find, instead of 
sending a request directly to a potential announce node, we relay the request 
via a DHT node close to it.

To avoid terminological collision with TCP relays, we refer to this as 
"forwarding" rather than "relaying".

Note that this relies on there existing a reasonable density of DHT nodes who 
can be connected to by arbitrary peers (i.e. nodes behind nothing more 
restrictive than a "cone NAT"). This is also required for finding friends on 
the DHT.

We also use this mechanism to route via a TCP relay if we are in TCP-only 
mode.

Note: this protocol should also be usable for announcing DHT Group Chats, 
replacing the use of the onion there.

#### Forwarding protocol overview
If a peer wishes to send a packet to a destination via a forwarder which is a 
DHT node, they send a Forward Request packet containing the packet and the DHT 
key of the destination. The forwarder sends a Forwarding packet to the 
destination, if it's in their close list. The destination replies by sending a 
Forward Reply packet to the forwarder, and the forwarder then sends a 
Forwarding packet back to original sender. In the Forwarding packet, the 
forwarder includes a "sendback" to be included in the reply, which tells the 
forwarder how to route the reply.

A TCP relay can also act as a forwarder to its clients; in this case, the TCP 
Forward Request gives the IP/Port of the destination DHT node, which need not 
be in the relay's close list. The relay sets a sendback indicating which TCP 
client sent the request.

A Forward Request may itself be received as a forwarded packet. In this case, 
the resulting Forwarding packet should include in its sendback the source 
IP/Port and sendback of the Forwarding packet with which the Forward Request 
was delivered, and handle a Forward Reply by sending its data in another 
Forward Reply to that source. The intended use for this is to allow nodes who 
are not able to use UDP to send announce requests, by forwarding the request 
via a TCP relay and a DHT node close to the destination node. Note that 
chaining forward requests can not be used to implement onion routing, due to 
the lack of encryption.

To prevent abuse, each sendback should include a timed authenticator, and this 
should be validated before accepting a Forward Reply. The timeout for this 
timed authenticator should be reasonably long, say 3600s, since a change in 
the sendback between forwarding a Search Request and a corresponding Retrieve 
Request will cause the Retrieve Request to fail.

#### Forward Request Packet
This is sent as the payload of a Protocol packet.

| Length     | Type           | Contents          |
|:-----------|:---------------|:------------------|
| `32`       | DHT public key | Addressee pubkey  |
| `[0,1791]` | Bytes          | Data              |

On receiving a Forward Request packet, a DHT node should try to find the node 
with the given pubkey in its DHT close list, and on success send a Forwarding 
packet to that node, with data copied from that in the current packet, and 
with a sendback which indicates the IP/Port of the source of the current 
packet and, if the packet was received in a Forwarding packet, the sendback 
from that packet.

Note that a node's close list does not include the node itself.

We impose a maximum size of 1791 bytes on the data to be forwarded, which 
ensures that a Forwarding packet can't exceed the general bound in tox of 2048 
on the size of a UDP packet. If the 1791 bound is exceeded, the packet should 
be ignored.

#### Forwarding Packet
This is sent as the payload of a Protocol packet.

| Length     | Type      | Contents         |
|:-----------|:----------|:-----------------|
| `1`        | `uint8_t` | Sendback length  |
| [0,254]    | Bytes     | Sendback         |
| `[0,1791]` | Bytes     | Data             |

The first byte indicates the length in bytes of the sendback which follows. 
Any value between 0 and 254 is permissible. The value 255 is reserved for 
future extension of the protocol.

The format of the sendback is not part of the protocol; it is an opaque 
bytestring which need only be validated and understood by the sender.

The data of the forwarding packet should be interpreted as one of the packets 
which are part of the DHT Announcements protocol, or as a Forward Request 
packet. It should be processed as normal, but any reply should be sent as the 
data of a Forward Reply packet sent to the sender of the current packet, with 
sendback copied from this packet.

#### Forward Reply Packet
This is sent as the payload of a Protocol packet.

| Length     | Type      | Contents         |
|:-----------|:----------|:-----------------|
| `1`        | `uint8_t` | Sendback length  |
| [0,254]    | Bytes     | Sendback         |
| `[0,1791]` | Bytes     | Data             |

The recipient of a Forward Reply packet should examine the sendback, confirm 
that it was recently constructed by the recipient, and send the data on as 
indicated by the sendback. If the sendback indicates that it should be sent 
directly to an IP/Port, this should be done in a Forwarding packet with empty 
sendback. If it indicates that it should itself be forwarded with a sendback, 
this should be done with another Forward Reply packet. If it indicates it 
should be sent to a TCP client, this should be done with a TCP Forwarding 
packet.

#### TCP Forward Request
| Length     | Type      | Contents          |
|:-----------|:----------|:------------------|
| `1`        | `uint8_t` | 0x0a              |
| `7 | 19`   | IP/Port   | Addressee IP/Port |
| `[0,4096]` | Bytes     | Data              |

This is sent to a TCP server by a TCP client in an encrypted data packet. The 
TCP server should treat it as a Forward Request, and send a Forwarding packet 
to the addressee IP/Port, with sendback which should uniquely identify the TCP 
client to the TCP server.

If the addressee port is <1024, the packet should be ignored. This is to 
reduce the potential for abuse.

NOTE: adding a new TCP packet type like this comes with the problem that old 
TCP servers who don't recognise it will consider it an error and close the 
connection. Solution: extend the TCP relay handshake to include a protocol 
version number.

#### TCP Forwarding
| Length   | Type      | Contents       |
|:---------|:----------|:---------------|
| `1`      | `uint8_t` | 0x0b           |
| `[0,]`   | Bytes     | Data           |

This is sent to a TCP client by a TCP server in an encrypted data packet when 
the TCP server receives a Forward Reply with sendback encoding the TCP client.

# Announcing connection info
We use announcements to store our timestamped connection info on the DHT in 
places where certain intended parties can find it. Our **connection info** 
consists of our DHT pubkey, some DHT nodes we are connected to, and some TCP 
servers we are connected to. Our **timestamped connection info** consists of 
an unsigned 64-bit timestamp set to the unix time at which our connection info 
was last updated, followed by our connection info. The timestamp should change 
only when the connection info changes.

There are three kinds of announcement: individual announcements, shared 
announcements, and invite announcements. In each case, an announcement secret 
key will be obtained by combining the time of the announcement with a secret 
shared only by those the announcement is intended for, and the announcement 
public key will be that derived from the secret key. The differences are in 
the choice of secret, and in how the connection info is encrypted and/or 
signed in the announcement.

The intention is that the intended parties can be assured that what is 
announced really is our current connection info, and yet no-one else can link 
the announcement to our long-term ID, nor track changes to our DHT pubkey and 
IP address across sessions.

In fact, only individual announcements are required for core functionality, 
and a first implementation could reasonably ignore shared and invite 
announcements. The purpose of shared announcements is to keep network traffic 
requirements under control. The purpose of invite announcements is to allow 
"promiscuity", which is required for public bots and can simplify the process 
of adding friends.

## Timed hashes
Fix constants $M < P$ ("margin", and "period"), measured in seconds.

Suggested values:

    M = 1200
    P = 4096

At a given time, two **timed hashes** of a 32-byte bytestring `key` are 
defined as follows.

Let `time` be unix time as an unsigned 64 bit integer,
let `offset` be the last 8 bytes of `key` interpreted as a big-endian unsigned 
64 bit integer,
define

    a := (time + offset + n*M) / P

where n is 0 for the first timed hash and 1 for the second,
and addition is modulo $2^{64}$,
and finally define the timed hash as the HMAC-SHA-512256 authenticator of `a` 
with secret key `key`.

The two timed hashes will differ $M/P$ of the time.

Suppose A and B simultaneously compute timed hashes of the same secret.
As long as the difference between A's clock and B's clock is less than $M$, 
the timed hashes they generate will always have a hash in common.
More generally, if the difference between their clock times is $dt$, then they 
generate no common hash `max(0, min(1, (dt - M) / P))` of the time.

Note that if P is not a power of 2, the wraparound at `UINT64_MAX` would cause 
some timed hashes to have exceptionally short validity, potentially leaking 
information about `offset`. So then `offset` should be generated by hashing.

### Consequences of using the system clock
Below, we use the timed hashes of a somewhat secret key to determine the DHT 
locations at which we announce and search.

If a user's system clock is sufficiently incorrect, the system will quietly 
fail.
Note that Tor also requires a roughly accurate system clock, and this seems to 
be a somewhat common problem for users.

As with other parts of the Tox protocol, there is also the issue that by 
having our publically observable behaviour be influenced by the precise value 
of our system clock, we leak information about our clock (its error and drift 
rate) which could be used to track us across changes of IP address and DHT 
key. One way to mitigate this would be to generate a random high-precision 
"error" within some reasonable bounds, generated along with the DHT key and 
having the same period of validity, and systematically add this error to our 
system clock throughout the Tox protocol.

Clients might also be advised to check the system clock against remote clocks, 
and inform the user if the system clock appears to be significantly wrong. 
(It's tempting to do this entirely within the tox network, by having nodes 
respond with their clock time (plus error) on request, but this would allow 
nodes to be tracked by their clock drift and clock precision).

## Individual announcements
If A and B are peers, A's **individual announcement** for B consists of a 
random 24-byte nonce followed by A's timestamped connection info, 
authenticated and encrypted using that nonce and the combined key of A and B.

This is announced with announcement secret key(s) the timed hashes of the 
result of symmetrically encrypting A's ID pubkey with the combined key of A 
and B, using A's ID pubkey as the nonce.

## Shared announcements
Each peer generates a **shared signing keypair**. This is an Ed25519 signing 
keypair. It is saved across sessions, and changes only as described below.

We send our shared signing pubkey to all our friends, sending it to a 
friend whenever we establish a friend connection with them. When we delete a 
friend, we generate a new shared signing keypair, delete the old one, 
and send the new one to all currently connected friends.

Friends confirm receipt of shared signing pubkeys, and we keep track of 
which friends have confirmed that they have our current shared signing 
pubkey.

We save across sessions the latest shared signing pubkey we have received from 
each friend.

Shared signing pubkeys are to be treated as *secret* information, not to be 
shared with anyone except as described above.

Our **shared announcement** consists of a random nonce followed by our 
timestamped connection info signed with our shared signing keypair, and then 
authenticatedly encrypted with the nonce using the shared signing public key 
as a symmetric encryption key. The symmetric authenticated encryption 
algorithm for this purpose is XSalsa20Poly1305 (`crypto_secretbox` in NaCl).

The encryption prevents the node where the announcement is stored from reading 
the announcement (which may contain information, such as timestamps and our 
choice of TCP relays, which might be used to identify us), while the signature 
prevents our friends from faking an announcement for us.

Our shared announcement is announced with announcement secret key(s) the timed 
hashes of our shared signing pubkey.

We make a shared announcement as long as at least one friend is believed to 
have our current shared signing pubkey, and we make individual announcements 
for each of our other friends. We can not be certain that a friend who 
previously received our shared key will still have it subsequently, since they 
might for various exceptional reasons have reverted to an earlier save state. 
So as a precaution, we also make ``low-intensity'' individual announcements 
for such friends.

### Security notes
Our friends can interfere with our shared announcements -- either by occupying 
the neighbourhood of the announcement pubkey on the DHT and behaving 
maliciously (e.g. accepting our announce requests but not actually storing the 
announce), or simply by overwriting our announcements. The latter technique 
could be prevented at the cost of complicating the protocol, but the former is 
inevitable.

Our friends can also easily determine our other friends' IP addresses and DHT 
pubkeys by listening at the shared announcement pubkey.

## Invite announcements
An **invite code** is the public key of an Ed25519 signing keypair. A 
corresponding **invite announcement** is made exactly as in the case of a 
shared announcement, except that our ID pubkey is included along with the 
timestamped connection info in the encrypted part of the announcement.

A peer who knows the invite code proceeds as follows. They find and decrypt 
the announcement, checking the signature, to obtain our connection info. They 
then use this to send an **Invite Accept** packet to us; this is sent on the 
DHT in a DHT Request packet (i.e. routed via a DHT node we are connected to) 
and/or via TCP OOB packets on TCP relays we are connected to. The Invite 
Accept packet they send to us consists of their ID pubkey, a random nonce, 
and, authenticatedly encrypted to our ID pubkey using their ID pubkey and the 
nonce, the invite code and their connection info. On receiving an Invite 
Accept packet containing a valid invite code, we add the ID pubkey as a 
friend, and may use the connection info to connect to them.

### Usage
We generate an invite code and send it out-of-band to some limited set of 
people. A common instance of this is asking someone who does not use tox to 
install it and find you on the network. 

In terms of friend requests, an invite announcement is analogous to giving out 
a ToxID with a nospam and accepting every friend request obtained without 
checking the sender.

Invite codes can have validity limited in time and in the number of peers who 
can use it; 1 day and 1 peer might be sensible defaults. We consider an invite 
code to be used by a peer when we have connected to them and sent them our 
shared key.

One big problem with invite announcements is that it is difficult to explain 
to the user the privacy consequences of the invite code being leaked. This 
could be mitigated somewhat by warning against loose time/user limits. Another 
problem is the additional complexity in the user interface -- it requires a 
means to supply an invite code on adding a friend (while making it clear that 
supplying one might not be necessary), and a means to generate invite codes. 
Preferably there would also be an indication of any active invite codes and 
the option to cancel them or extend their validity.

### Public announcements
Public bots typically want to accept all connections. This can be implemented 
by distributing an invite code with no limit on its validity. We term as 
**public announcements** the corresponding invite announcements.

When someone connects to us via a public announcement, we do not send them our 
shared signing key; as a result, they will continue to use the public 
announcement to find us in the future, and we need make no other announcement.

Note that as discussed for shared keys, it is easy for anyone who knows the 
public invite code to prevent the public announcement and/or to determine the 
IP addresses of those searching for it.

# Announcing and searching

## Making announcements
As described above, at any given time we want to maintain various 
announcements at various announcement secret keys.

We make and maintain an announcement using forwarded Data Search and Store 
Announcement requests.

The details are similar to those of onion announcements. Some of the constants 
suggested here are based on those used in the onion, while others are based on 
intuition, and all should be fine-tuned.

For the rest of this section, whenever we talk about sending packets to a DHT 
node and receiving responses, it should be understood that if we are not 
connected to the DHT, then this is done via a TCP relay using the Forwarding 
protocol, and we nonetheless term this as "direct" communication with the DHT 
node.

For each announcement we wish to make, we maintain a list of up to 8 DHT 
nodes. This list will contain the nodes we have found closest to the 
announcement public key. We mark a node on this list as an **open** node if  
we confirm we are able to communicate with it directly, and we ensure the list 
never contains more than 4 non-open nodes. Given this proviso, the list 
contains nodes as close as possible to the target key; an attempt to add a 
node succeeds if it can be added, removing a more distant node if the list is 
full, without this resulting in too many non-open nodes.

When we talk about sending a "forwarded" request below, we mean that the 
request is sent as the payload of a Forward request sent directly to a random 
open node in the list. (Note that if we are not connected to the DHT, this 
Forward request is itself forwarded via a TCP relay).

We periodically send Data Search requests to the nodes on the list; these 
requests are sent directly to open nodes, and forwarded to non-open nodes. 
When we receive a Data Search response, we send further Data Search requests 
to any nodes given in the response which could be added as non-open nodes to 
the list. We also attempt to add the sender of the response to the list -- as 
an open node if we received the response directly, and as a non-open node if 
it was forwarded. If we do add it as a non-open node in this way, we also send 
it a direct Data Search request.

Initially, and periodically while the list is not full, we populate the list 
by sending Data Search requests to random announce nodes (see [Finding 
announce nodes]) from our DHT nodes lists if we are connected to the DHT, and 
to random bootstrap nodes otherwise.

When we receive a Data Search response from a node which is already on the 
list indicating that our current announcement is stored or that a Store 
Announcement request would be accepted, we also send a Store Announcement 
request to that node (making sure to use the Port/IP that's on the list rather 
than the source of the Data Search response, to prevent UDP amplification 
attacks, and using the same forwarders (if any) used for the Data Search 
request). In this request we put an initial announcement, or a reannouncement 
if the response indicated that our current announcement is already stored. We 
set the requested timeout to 300 seconds. If we obtain an Announcement Store 
response from a node indicating that the announcement is stored, we consider 
ourselves announced to that node, until a Data Search response or further 
Store Announcement response indicates otherwise.

The interval between sending these periodic Data Search requests to a node on 
our list is 120s if we are announced to it, and otherwise is `min(120,3n)` 
seconds where `n` is a count of the number of Data Search requests which have 
been sent to the node, set to 0 when the node is added to the list, and set to 
1 when we are informed by a Data Search response from the node that we have 
just ceased to be announced at the node.

A node on the list which fails to respond to a Data Search request is sent 
another at most 10s later. After 3 consecutive Data Search requests are sent 
to a node without a response, it is removed from the list.

We consider an announcement to be announced if it is stored on at least half 
of the nodes in the list.

We keep track of the total amount of time we have spent announcing at a given 
individual key without a connection to the corresponding friend being made, 
saving across sessions. Once this exceeds 64 hours, we switch to a 
low-intensity mode; this simply means that we reduce the size of the list from 
8 to 2, with at most 1 non-open node.

The ``low-intensity'' individual announcements made alongside a shared 
announcement use this low-intensity mode from the start, and moreover do not 
start until the shared announcement is announced.

## Searching
For each offline friend, we search for its announcements using forwarded Data 
Search and Data Retrieve requests.

We search for the friend's shared announcement if we have a shared signing key 
for it, else for its invite announcement if we have an invite code for it, 
else for the individual announcement.

We ensure we are announced for the friend before beginning to search for it.

The process of searching is as for announcing, but with different timeouts: 
the timeout between periodic requests for each of the 8 nodes is at least 15 
and at most 2400 seconds, and within these bounds is calculated as one quarter 
of the time since we began searching for the friend, or since an announcement 
for the friend was last seen.

When we first start searching for a given friend, for 17 seconds the timeout 
is set to 3 seconds.

If we receive a Search Data response indicating that an announcement is 
stored, and the hash is not the hash of either of the two most recent 
(according to the timestamps) announcements we have obtained for the friend, 
then we send a Data Retrieve request. When we receieve an announcement, we 
decrypt it and/or check the signature as appropriate, and if it is valid and 
the timestamp is greater than that on any previous announcement we obtained 
for the friend, we pass the connection info to the appropriate modules.

Because it is possible that we have an outdated shared signing key or invite 
code for the friend, when we search for a shared/invite announcement we also 
search for the individual announcement (if we know the friend's ID pubkey), 
with the same process but without the initial period of a high rate of 
requests.

## Finding announce nodes
We term as **announce nodes** those DHT nodes who implement the DHT 
Announcements protocol. We maintain an `announce_node` boolean flag on each 
node in the DHT node lists, indicating whether we consider the node to be an 
announce node. Whenever we add a node to a DHT node list, we set the flag to 
false and send the node a Data Search request, with the data key set to a 
random key amongst those we are currently searching for or announcing at (or 
if there are no such, to a random key from the whole space of possible keys). 
Whenever we receive a Data Search response, we check if the responding host is 
in a DHT node list, and if so we set its `announce_node` flag. All nodes in 
lists for announcing and searching described above are considered to be 
announce nodes. 

When responding to Data Search requests, we give the announce nodes we know 
closest to the target key (not including ourself).

# Migration
To ensure backwards compatibility, we continue to process onion packets as 
usual, and moreover we search on the onion for offline friends who might still 
be announcing on the onion. For an existing friend, we consider this to be the 
case until they send us a shared signing pubkey. When adding a friend, we 
consider it to be the case if and only if the added ID includes a nospam, and 
when it does we also send a friend request.

We don't announce via the onion, nor generate or expose any nospam.

Preferably, clients should indicate which friends are using the legacy onion 
system, and warn the user of the privacy implications of this (so the user 
will exhort their friends to upgrade).
