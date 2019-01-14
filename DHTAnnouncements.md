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
a large pool, mitigation of tracking techniques such as http cookies, and 
anonymising relays such as Tor or VPNs.

## User-visible changes

Unlike the onion, DHT Announcements do not support friend requests. Instead, 
to add a friend, you must add their ToxID and they must add yours.

There is an exception to this for bots, which can be added unilaterally.

This system does not use any "nospam" - the ToxID of a peer is just their 
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

| Length      | Type       | Contents                                    |
|:------------|:-----------|:--------------------------------------------|
| `32`        | Public Key | Data public key                             |
| `1`         | Bool       | Data is stored by this node                 |
| `0 | 32`    | Bytes      | SHA256 of data if stored                    |
| `32`        | Ping ID    | Ping ID                                     |
| `1`         | Bool       | Announcement would be accepted              |
| `1`         | Int        | Number of nodes in the response (maximum 4) |
| `[39, 204]` | Node Infos | Nodes in Packed Node Format                 |

The "announcement would be accepted" boolean should be set to true if and only 
if a Store Announcement request received now for this data public key would 
result in the announcement being stored, whatever the size of the announcement 
(up to the maximum of 512 bytes). This does not consitute a promise to accept 
a subsequent Store Announcement request.

The Ping ID is generated as in the onion: it is the SHA256 hash of some 

The nodes returned are those closest to the Data Public Key known by the 
responding node, as in the case of a Nodes Response.
per-node secret bytes, the current time rounded to 20s, the data public key in 
the request, and the requester's DHT public key and IP/Port. In the case that 
the request is received as a relayed packet (see below), this IP/Port is the 
sender IP/Port given in the Route Deliver packet; otherwise, it is the source 
IP/Port of the request packet. The number of bytes in the representation of 
the IP/Port should not depend on the IP/Port, so that the length of the data 
to be hashed is a constant, preventing length extension attacks.

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
announcements, and public announcements. The differences are in how the 
announcement keypair is determined and in how the connection info is encrypted 
and/or signed in the announcement.

The intention is that the intended parties can be assured that what is 
announced really is our current connection info, and yet (for non-public 
announcements) no-one else can link the announcement to our long-term ID, nor 
track changes to our DHT pubkey and IP address across sessions.

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
and finally define the timed hash as

    SHA256(input, rounded_time) .

The two timed hashes will differ $M/P$ of the time.

Suppose A and B simultaneously compute timed hashes of the same input.
As long as the difference between A's clock and B's clock is less than $M-2E$, 
the timed hashes they generate will always have a hash in common.
More generally, if the difference between their node times is $dt$, then they 
generate no common hash

    max(0, min(1, (dt - M) / P))

of the time.

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
Our friends can interfere with our shared announcements - either by occupying 
the neighbourhood of the announcement pubkey on the DHT and behaving 
maliciously (e.g. accepting our announce requests but not actually storing the 
announce), or simply by overwriting our announcements. The latter technique 
could be prevented at the cost of complicating the protocol, but the former is 
inevitable.

Our friends can also easily determine our other friends' IP addresses and DHT 
pubkeys by listening at the shared announcement pubkey.

## Public announcements and promiscuity
TODO: put this and invites in a single section, and discuss possibility of
combining them.

A Tox instance may be set (as an option at initialisation) to "promiscuous 
mode". This is intended primarily for bots.

A Tox instance P running in promiscuous mode functions as follows. On first 
run, it generates an Ed25519 signing keypair and derives (see below) its 
long-term Curve25519 ID keypair from it. The signing keypair is saved across 
sessions. P's **public announcement** consists of P's timestamped connection 
info signed with this keypair, announced with P's ID secret key as the 
announcement secret key.

The public signing key can be distributed publically, with a prefix to 
distinguish it from an ordinary ToxID, say as

    s:BA155D19285AEFA10BF5D409FFCA513FDF8B356260CF98B9C1D212CAD367424A

. When this string is given in another Tox client, B, as a friend to be added, 
B will derive P's ID pubkey from it and search for P's public announcement. 
When B finds it and confirms the signature, and so obtains P's timestamped 
connection info, as usual B will send a handshake to P. Normally, P would 
reject it as not coming from a friend; but in promiscuous mode, instead P adds 
B as a friend (after consulting a callback) and accepts the handshake.

While in promiscous mode, shared signing keys are not sent to friends by 
default (but this can be overriden with an API call). When B adds a public 
signing key for an existing friend, B deletes any shared signing key B is 
storing for the friend.

Promiscuous mode is not to be advised for ordinary users, as it negates all 
privacy properties: anyone may find the IP address and DHT pubkey of a 
promiscuous node given its ID pubkey.

### Deriving encryption keys from signing keys
In libsodium, this functionality is provided by 
`crypto_sign_ed25519_sk_to_curve25519()`
and `crypto_sign_ed25519_pk_to_curve25519()`.

NaCl does not currently provide corresponding functions, so we have to either 
implement them ourselves (which is straightforward in theory) or require 
libsodium.

# Announcing and searching

## Making announcements
As described above, at any time we want to maintain various announcements at 
various announcement secret keys. In fact, the typical case will be a single 
such announcement - a shared announcement at the common timed hash of our 
shared public key.

We make and maintain an announcement using Data Search and Store Announcement 
requests, relayed via random DHT nodes / TCP servers we are connected to.

The details are similar to those of onion announcements. For each announcement 
we wish to make, we maintain a list of the 8 DHT nodes closest to the 
announcement public key we have found. We periodically send Data Search 
requests to these. When we receive a Data Search response, we send further 
Data Search requests to the nodes given in Data Search responses if they could 
be added to the list, and add them if they respond. When we receive a Data 
Search response from a node which is already on the list indicating that our 
current announcement is not stored but that a Store Announcement request would 
be accepted, we also send a Store Announcement request to that node (making 
sure to use the Port/IP that's on the list rather than the source of the Data 
Search response, to prevent UDP amplification attacks). In this request we put 
an initial announcement, or a reannouncement if the response indicated that 
our current announcement is already stored. We set the requested timeout to 
300 seconds. If we obtain an Announcement Store response from a node 
indicating that the announcement is stored, we consider ourselves announced to 
that node, until a Data Search response or further Store Announcement response 
indicates otherwise.

We send Data Search requests once every 3 seconds to nodes on our list which 
we are not announced to, and once every 120 seconds to those we are announced 
to.

TODO: backoff; timeouts; handling rejection.

TODO: use fewer announce and search nodes for individual announcements for 
long-inactive friends? Base on how long we've unsuccessfully searched for the 
friend, rather than clock time since we last saw them. Only have two settings, 
to minimise the fingerprint.

## Searching
For each offline friend, we search for its announcements using Data Search and 
Data Retrieve requests, relayed via random DHT nodes / TCP servers we are 
connected to.

We search for the friend's shared announcement if we have a shared signing key 
for it, else for its public announcement if we have its public signing key, 
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

TODO: timeouts.


# Invites
This section discusses a system allowing a restricted kind of promiscuity, 
which could be implemented on top of the system described above.

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

A time limit on the validity of an invite code and/or the number of peers who 
can use it could be set; 1 day and 1 peer might be sensible defaults.

With no such limits, an invite announcement plays the same role as a public 
announcement, except that both the ID pubkey and the invite code have to be 
distributed.

One big problem with invite announcements is that it is difficult to explain 
to the user the privacy consequences of the invite code being leaked. This 
could be mitigated somewhat by warning against loose time/user limits. Another 
problem is the additional complexity in the user interface - it would require 
a means to supply an invite code on adding a friend (while making it clear 
that supplying one might not be necessary), and a means to generate invite 
codes. Preferably there would also be an indication of any active invite codes 
and the option to cancel them or extend their validity.

# Migration
We could aim to transition from the onion system to this new friend finding 
system either smoothly or sharply.

## Smooth
Search for pre-existing friends both as above and with the legacy onion 
system, until they send us a shared signing pubkey.

When adding a friend, use legacy onion method if and only if there's a nospam, 
sending a friend request then searching using the onion.

Don't announce via the onion at all. Don't generate or expose any nospam.

Make onion a compile-time option, which we can eventually switch off by 
default, and a client option, which can be disabled at the cost of rendering 
friends using the legacy system uncontactable.

To avoid breaking the onion, we would have to continue to honour onion 
requests.

We might also have to maintain a separate close list consisting only of peers 
using the new system, to be used when answering Data Search requests.
TODO: details. Note we can combine this with "hardening", i.e. ensuring we 
only respond to data search requests with nodes which appear to be accepting 
incoming connections from arbitrary hosts.

## Sharp
Maybe better just to make a clean break - set up a new onionless network 
disconnected from the existing one, to be used only by devs and the 
adventurous at first while we experiment. Old network will persist 
independently, dying slowly as users upgrade.

The problem of course is that network effects may lead many current users to 
avoid upgrading, because they have friends who haven't upgraded. Tricky.
