% DHT Announcements

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
long-term ID public key. This makes it easy to introduce existing friends to 
each other.

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
| `32`       | Ping ID    | Ping ID                                     |
| `1`        | Byte       | Data types currently accepted               |
| `1`        | Int        | Number of nodes in the response (maximum 4) |
| `[0, 204]` | Node Infos | Nodes in Packed Node Format                 |

The "data types currently accepted" should have least significant bit set
if and only if a Store Announcement request received now for this data public 
key would result in the announcement being stored, whatever the size of the 
announcement (up to the maximum of 512 bytes). This does not consitute a 
promise to accept a subsequent Store Announcement request. Other bits are 
reserved for possible future types of storage request.

The Ping ID is generated as in the onion: it is the SHA256 hash of some 
per-node secret bytes, the current time rounded to 20s, the data public key in 
the request, and the requester's DHT public key and IP/Port. In the case that 
the request is received as a relayed packet (see below), this IP/Port is the 
sender IP/Port given in the Route Deliver packet; otherwise, it is the source 
IP/Port of the request packet. The number of bytes in the representation of 
the IP/Port should not depend on the IP/Port, so that the length of the data 
to be hashed is a constant, preventing length extension attacks.

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
| Length | Type       | Contents        |
|:-------|:-----------|:----------------|
| `32`   | Public Key | Data public key |
| `32`   | Ping ID    | Ping ID         |

The Ping ID should be set to the Ping ID obtained from a recent Data Search 
response to a search for the same data public key, as above. This check is to 
prevent redirection of the response to a forged IP address, which could be 
used for a UDP amplification attack.

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

| Length      | Type       | Contents            |
|:------------|:-----------|:--------------------|
| `32`        | Ping ID    | Ping ID             |
| `4`         | `uint32_t` | Requested timeout   |
| `1`         | Bytes      | Announcement Type   |
| `[0-512]`   | Bytes      | Announcement Data   |

The Ping ID should be set to the Ping ID obtained from a recent Data Search 
response to a search for the same data public key. The recipient checks that 
this is valid before responding; that is, that it is equal to the Ping ID for 
the announcement public key with either the current rounded unix time or the 
previous rounded unix time. This check is to prevent replay of old 
announcements.

The requested timeout is the time in seconds for which the announcement is 
requested to be stored.

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

### Relaying
For various reasons, it may be that there are DHT nodes which we are not able 
to connect to though they are generally accessible, and conversely there may 
be nodes which we are able to connect to but which do not generally accept 
incoming connections. In particular, we may not be able to use UDP at all. We 
deal with these problems by relaying our announcement and search requests via 
third parties.

This is similar to the onion, but with only one hop.

Note: this protocol should also be usable for announcing DHT Group Chats, 
replacing the use of the onion there.

#### Route Request Packet
This is sent as the payload of a Protocol packet.

| Length   | Type    | Contents          |
|:---------|:--------|:------------------|
| `7 | 19` | IP/Port | Addressee IP/Port |
| `[0,]`   | Bytes   | Data              |

The IP/Port is as in packed node format.

On receiving a Route Request packet, a DHT node should send a Route Deliver 
packet to the addressee IP/Port with Sender IP/Port the source of the current 
packet, and data copied from that in the current packet.

#### Route Deliver Packet
This is sent as the payload of a Protocol packet.

| Length | Type          | Contents          |
|:-------|:--------------|:------------------|
| `32`   | Symmetric key | Symmetric key     |
| `[7,]` | Data          | Encrypted payload |

The symmetric key should be randomly generated by the sender, and the payload 
should be encrypted with this symmetric key and the zero nonce, using the 
encryption algorithm XSalsa20 (provided by `crypto_stream_xor` in NaCl and by 
`crypto_secretbox_detached` in libsodium).

The purpose of this encryption is to prevent well-crafted route requests 
causing the router to send packets which might be interpreted by other 
protocols in problematic ways.

Payload:

| Length   | Type    | Contents       |
|:---------|:--------|:---------------|
| `7 | 19` | IP/Port | Sender IP/Port |
| `[0,]`   | Data    | Data           |

On receiving a Route Deliver packet and decrypting the payload, we attempt to 
handle the data as a DHT packet containing one of the request packets 
associated with the announcement system defined above. If a response is 
generated, it should be sent via a Route request packet sent to the source of 
the current packet, addressed to the Sender IP/Port in the payload of the 
current packet.

#### TCP Route Request
| Length   | Type      | Contents          |
|:---------|:----------|:------------------|
| `1`      | `uint8_t` | 0x0a              |
| `7 | 19` | IP/Port   | Addressee IP/Port |
| `[0,]`   | Bytes     | Data              |

This is sent to a TCP server by a TCP client in an encrypted data packet. The 
TCP server should treat it as a Route request, but the information put in the 
sender IP/Port of the Deliver packet should identify the client to the server 
(as is currently done for TCP onion packets).

#### TCP Route Response
| Length | Type      | Contents |
|:-------|:----------|:---------|
| `1`    | `uint8_t` | 0x0b     |
| `[0,]` | Bytes     | Data     |

This is sent by a TCP server to a TCP client in an encrypted data packet when 
the server obtains a Route request with Addressee IP/Port referring to the 
client, according to the scheme used by that server when handling TCP Route 
requests.

# Announcing connection info
We use announcements to store our timestamped connection info on the DHT in 
places where certain intended parties can find it. Our **connection info** 
consists of our DHT pubkey, some DHT nodes we are connected to, and some TCP 
servers we are connected to. Our **timestamped connection info** consists of 
an unsigned 64-bit timestamp set to the unix time at which our connection info 
was last updated, followed by our connection info. The timestamp should change 
only when the connection info changes.

There are three kinds of announcement: individual announcements, shared 
announcements, and invite announcements. The differences are in how the 
announcement keypair is determined and in how the connection info is encrypted 
and/or signed in the announcement.

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
Fix constants $E < M < P$ ("error", "margin", and "period"), measured in 
seconds.

Suggested values:

    E = 300
    M = 1200
    P = 4096

We define **node time** to be unix time as given by our system clock plus a 
random error distributed uniformly in $[E,-E]$. The random error should 
generated along with the DHT key, and have the same period of validity.

At a given time, two **timed hashes** of a bytestring `input` (of length at 
least 8 bytes) are defined as follows.

Let `node_time` be node time as an unsigned 64 bit integer,
let `offset` be the last 8 bytes of `input` interpreted as a big-endian 
unsigned 64 bit integer,
define

    rounded_time := (node_time + offset + n*M) / P

where n is 0 for the first timed hash and 1 for the second,
and addition is modulo $2^{64}$,
and finally define the timed hash as `SHA256(input, rounded_time)`.

The two timed hashes will differ $M/P$ of the time.

Suppose A and B simultaneously compute timed hashes of the same input.
As long as the difference between A's clock and B's clock is less than $M-2E$, 
the timed hashes they generate will always have a hash in common.
More generally, if the difference between their node times is $dt$, then they 
generate no common hash `max(0, min(1, (dt - M) / P))` of the time.

Note that if P is not a power of 2, the wraparound at `UINT64_MAX` would cause 
some timed hashes to have exceptionally short validity, potentially leaking 
information about `offset`. So then `offset` should be generated by hashing.

### Consequences of using the system clock
Below, we use the timed hashes of a somewhat secret input to determine the DHT 
locations at which we announce and search. An observer who sees when we start 
and stop searching at a timed hash for which the observer has the input may 
deduce information about our node time. This may also be done less efficiently 
by an observer who doesn't have the input, by comparing our search times with 
those of others searching/announcing at the same input.

This provides some identifying information. The random error added to our 
system clock mitigates this, to an extent which decreases with the ratio 
between E and the difference of our system clock from the true time. Note that 
clock drift could potentially still be revealed this way, with extensive 
observation.

Furthermore, if a user's system clock is sufficiently incorrect, the system 
will quietly fail.
Note that Tor also requires a roughly accurate system clock, and this seems to 
be a somewhat common problem for users.

Clients might be advised to check the system clock against remote clocks, and 
inform the user if the system clock appears to be significantly wrong. (It's 
tempting to do this entirely within the tox network, by having nodes respond 
with their node time on request, but this would allow nodes to be tracked by 
their clock drift and clock precision).

## Individual announcements
If A and B are peers, A's **individual announcement** for B consists of a 
random 24-byte nonce followed by A's timestamped connection info, 
authenticated and encrypted using that nonce and the combined key of A and B.

This is announced with announcement secret key(s) the timed hashes of the 
48-byte authenticated encryption of A's ID pubkey, encrypted with the combined 
key of A and B, using A's ID pubkey as the nonce.

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
encrypted with the nonce using the shared signing public key as a symmetric 
encryption key. The symmetric encryption algorithm for this purpose is 
XSalsa20 (exposed as `crypto_stream_xor` in NaCl and as 
`crypto_secretbox_detached` in libsodium).

The encryption prevents the node where the announcement is stored from reading 
the announcement (which may contain information, such as timestamps and our 
choice of TCP relays, which might be used to identify us), while the signature 
prevents our friends from faking an announcement for us.

Our shared announcement is announced with secret key(s) the timed hashes of 
our shared signing pubkey.

We make a shared announcement as long as at least one friend is known to have 
our current shared signing pubkey, and we make individual announcements for 
each of our other friends.

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
shared announcement.

We adapt the handshake packet to allow an invite code to be included at the 
end of the encrypted part. We then add as a friend anyone who sends us a 
handshake which specifies a valid invite code.

The intention is that we generate an invite code and send it out-of-band along 
with our ID pubkey to some limited set of people. A common instance of this is 
asking someone who does not use tox to install it and find you on the network. 

In terms of friend requests, an invite announcement is analagous to giving out 
a ToxID with a nospam and accepting every friend request obtained without 
checking the sender.

Invite codes can have validity limited in time and in the number of peers who 
can use it; 1 day and 1 peer might be sensible defaults.

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

A naive implementation would mean potential users of a bot have to input both 
its ID pubkey and its invite code. However, this can be shortcut by deriving 
one public key from the other. Theoretically this could work either way round, 
but libsodium only provides functions for deriving Curve25519 keypairs from 
Ed25519 keypairs, so we consider that direction. It could work as follows.

On first run, the bot generates an Ed25519 signing keypair and derives its 
long-term Curve25519 ID keypair from it. The signing keypair is saved across 
sessions.

The public signing key can be distributed publically, with a prefix to 
distinguish it from an ordinary ToxID, say as

    p:BA155D19285AEFA10BF5D409FFCA513FDF8B356260CF98B9C1D212CAD367424A .

When a user gives such a string to a Tox client as a friend to be added, the 
client should interpret the part after the prefix as a key and deliver it to a 
new API function, which interprets it as an invite code for the Curve25519 ID 
pubkey derived from it.

In libsodium, the relevant key derivation functions are 
`crypto_sign_ed25519_sk_to_curve25519()`
and `crypto_sign_ed25519_pk_to_curve25519()`.
NaCl does not currently provide corresponding functions, so we have to either 
implement them ourselves (which is straightforward in theory) or require 
libsodium.

When someone connects to us via a public announcement, we do not send them our 
shared signing key; as a result, they will continue to use the public 
announcement to find us in the future, and we need make no other announcement.

# Announcing and searching

## Making announcements
As described above, at any time we want to maintain various announcements at 
various announcement secret keys. In fact, the typical case will be a single 
such announcement -- a shared announcement at the common timed hash of our 
shared public key.

We make and maintain an announcement using Data Search and Store Announcement 
requests, relayed via random DHT nodes / TCP servers we are connected to.

The details are similar to those of onion announcements. Some of the constants 
suggested here are based on those used in the onion, while others are based on 
intuition, and all should be fine-tuned.

For each announcement we wish to make, we maintain a list of the 8 DHT nodes 
closest to the announcement public key we have found. Initially, and whenever 
the list is not full, it is populated with random announce nodes from the DHT 
node lists (see [Finding announce nodes]).

We periodically send Data Search requests to the nodes on the list. When we 
receive a Data Search response, we try to add the sender to the list, and we 
send further Data Search requests to any nodes given in the response which 
could be added to the list. When we receive a Data Search response from a node 
which is already on the list indicating that our current announcement is 
stored or that a Store Announcement request would be accepted, we also send a 
Store Announcement request to that node (making sure to use the Port/IP that's 
on the list rather than the source of the Data Search response, to prevent UDP 
amplification attacks). In this request we put an initial announcement, or a 
reannouncement if the response indicated that our current announcement is 
already stored. We set the requested timeout to 300 seconds. If we obtain an 
Announcement Store response from a node indicating that the announcement is 
stored, we consider ourselves announced to that node, until a Data Search 
response or further Store Announcement response indicates otherwise.

The interval between sending Data Search requests to a node on our list is 120 
seconds if we are announced to it, and otherwise is `min(120,3n)` where `n` is 
a count of the number of Data Search requests which have been sent to the 
node, set to 0 when the node is added to the list, and set to 1 when we are 
informed by a Data Search response from the node that we are no longer 
announced at the node.

A node on the list which fails to respond to 3 consecutive Data Search 
requests is removed from the list.

We keep track of the total amount of time we have spent announcing at a given 
individual key without a connection to the corresponding friend being made, 
saving across sessions. Once this exceeds 64 hours, we switch to a low 
intensity mode; this simply means that we use a list of nodes of length 1 
rather than 8.

## Searching
For each offline friend, we search for its announcements using Data Search and 
Data Retrieve requests, relayed via random DHT nodes / TCP servers we are 
connected to.

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

Because it is possible that we have an outdated shared signing key for the 
friend, when we search for the shared announcement we also search for the 
individual announcement, with the same process but without the initial period 
of a high rate of requests.

## Finding announce nodes
We term as **announce nodes** those DHT nodes who implement the DHT 
Announcements protocol and who moreover are not behind a restrictive NAT, such 
that they receive requests sent from arbitrary peers. We maintain an 
`announce_node` boolean flag on each node in the DHT node lists, indicating 
whether we consider the node to be an announce node. Whenever we add a node to 
a DHT node list, we set the flag to false and send the node a Data Search 
request relayed via a random peer as above, with the data key set to a random 
key amongst those we are currently searching for or announcing at (or if there 
are no such, to a random key from the whole space of possible keys). Whenever 
we receive a Data Search response, we check if the responding host is in a DHT 
node list, and if so we set its `announce_node` flag. All nodes in lists for 
announcing and searching described above are considered to be announce nodes. 

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
