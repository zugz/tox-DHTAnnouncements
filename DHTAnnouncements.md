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

## Summary for end-users
*   The tox address used to make friend requests now looks like this:
    `tox:FMZVriPO5aiZaQWmA4CQrog2msqt6y6j_fOxPUw-4CE?uvuNcPsjJOvlfODpC-dUEQ`.
    Anyone who has your tox address can look up your IP address and send you a 
    friend request.

    You can change your address at any time; this sets the part after the 
    question mark to a new random value, invalidating the previous address.

    The part before the question mark, 
    `tox:FMZVriPO5aiZaQWmA4CQrog2msqt6y6j_fOxPUw-4CE`, is your permanent tox 
    public key.
    You may wish to publicise this public key, so friends can be sure of who 
    they are talking to.
    On its own, a public key is not enough to find its owner's IP address or send 
    them a friend request.
    However, if you add the public key of someone who has also added your own 
    public key, you will connect to them without a friend request.

*   Data usage should be much less than with the old system.

*   Your public key does not change when upgrading to this new system, it's 
    just printed differently. You do not need to re-add existing friends.

*   You can add new friends who are using an old client which still uses 
    hex-encoded addresses, but they can not add you.

## High-level description of the system
DHT nodes permit storing small quantities of world-readable data, termed
"announcements". Using this, we "announce" ourselves by placing our connection 
info on the DHT for our friends to find. These announcements are encrypted 
such that only the intended recipient(s) can read them, and signed where 
appropriate. The DHT locations of these announcements are determined in such a 
way that the intended recipients can find them, but others can't determine our 
long-term identity based on the location. To prevent tracking us across 
sessions based on where we announce, the locations vary with time.

Our tox address specifies one such announce location. Using this, those who 
know our address can find us and send us a friend request. This location is 
also used by existing friends to find us, and we make individual announcements 
for friends who may not have our latest tox address.

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

## API changes
### Invitations and invite codes
In the API, the new addresses are termed as `invitations`, and the variable 
second part (the analogue of nospam) is termed the `invite_code`. The API 
functions and constants to handle these are mostly parallel to those in the 
old API:

* `tox_friend_add_invitation` is the analogue of `tox_friend_add`; it takes an 
  invitation of length `TOX_INVITATION_SIZE` and a friend request message.

* `tox_self_get_invitation`, and respectively `tox_self_get_invite_code`, 
  writes our current invitation of length `TOX_INVITATION_SIZE`, respectively 
  `TOX_INVITE_CODE_SIZE`.

* `tox_self_new_invite_code` generates a new random invite code.

* `tox_self_get_invite_private_key` obtains the private key from which the 
  current invite code is derived, and `tox_self_set_invite_private_key` sets 
  the private key and hence the invite code. These functions are provided 
  primarily to allow clients to offer to undo a call to 
  `tox_self_new_invite_code`.

* The existing `address` and `nospam` API functions are deprecated.

* The old `tox_friend_add` function is deprecated, but can be called by the 
  non-deprecated identifier `tox_friend_add_legacy_address`, with 
  `TOX_LEGACY_ADDRESS_SIZE` in place of `TOX_ADDRESS_SIZE`.

The use of the term `invitation` rather than "address" in the API is just to 
avoid conflict with the legacy API; they should be described to the user as 
addresses. It is probably best to avoid referring specifically to the 
`invite_code` part of the address, but when necessary it can be called the 
"invite code" (or even the "nospam", for those familiar with the old system). 
Generating a new invite code can be referred to as "changing address".

### Encoding and decoding URIs
As a convenience, new API functions are provided to perform the 
encoding/decoding for the URI form of the invitation and public key.
(The data encoding scheme is base64url with the 64 characters `0-9a-zA-Z_-`.)

* `tox_self_encode64_invitation` returns an ASCII string of length 
  `TOX_INVITATION_URI64_SIZE` of the form
```
tox:FMZVriPO5aiZaQWmA4CQrog2msqt6y6j_fOxPUw-4CE?uvuNcPsjJOvlfODpC-dUEQ .
```

* `tox_self_encode64_public_key` returns an ASCII string of length 
  `TOX_PUBLIC_KEY_URI64_SIZE` of the form
```
tox:FMZVriPO5aiZaQWmA4CQrog2msqt6y6j_fOxPUw-4CE .
```

* Conversely, `tox_friend_decode_invitation` takes a string and its length, 
  and writes an address. The `tox:` URI scheme prefix may be omitted in the 
  string. `tox_friend_decode_public_key` is similar.
  `tox_friend_decode_legacy_address` similarly decodes a legacy hex-encoded 
  address. 

* Although this base64 form is recommended as the default, there are also 
  base32 and hex versions of the encoding functions, 
  `tox_self_encode32_invitation` and `tox_self_encode16_invitation` etc, and 
  the decode functions also accept the output of these.

    The base32 alphabet uses all upper case alphanumeric characters except 
    ILOU ("Crockford's base 32"),
    and the hex alphabet is 0-9A-F. Examples:
```
tox:JPRFWSKAD3KVB4J60X2KCEJTCB13Q9A73KKN4854071TRRH8A6TJA9Q?4243ZAVDEQD39TH6EKGYNDGCX1W2E
tox:55C7F52E4C32B956474037191C1DD00B643543B2216AB6450DE09F8245828A9DBCDC?8E83D9EA49C3A170C5598A74481B81BFEC05
```

Intended behaviour when the user provides a string (perhaps in a qr code) to 
be added as a friend is to use the above decode functions to interpret the 
string as an invitation or a legacy address or a public key, and 
correspondingly call
`tox_friend_add_invitation` or `tox_friend_add_legacy_address` or
`tox_friend_add_norequest` if decoding is successful (perhaps after prompting 
for a friend request message in the first two cases).

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

### External unix time
We try to avoid revealing specifics of a user's system clock which could be 
used to track the user across sessions. Call the *error* of a clock its 
difference from true time, and call its *drift* the rate of change of error.
The **external unix time** of a node is the 64-bit monotonically increasing 
unix time as reported by their system clock, but with extra per-session random 
error and drift; this is defined precisely below. As long as the true error 
and drift are well within the range of the random additions, measuring the 
error and drift of the external unix time will give little information on the 
true error and drift.

The external unix time is to be used throughout the tox protocol whenever 
behaviour depends on time. This applies in particular to timeouts: for the 
purpose of such timeouts, one time is considered to be at least `n` seconds 
after another if the external unix time at the former is at least `n` greater 
than that at the latter.

The external unix time is calculated using some constants which are set when 
the tox object is initialised:
`u0` is unix time according to the system clock at initialisation;
`d` is a real number generated uniformly randomly in the range 
`[0.9999,1.0001]`;
`e` is a real number generated uniformly in the range `[-30,30]`.
The external unix time is then calculated at a particular time as
`external_unix_time = e + d*t + u0`
rounded to an integer, where `t` is time in seconds since initialisation 
according to the system clock, as a real number. So `e` and `d` act as extra 
error and drift respectively. High-accuracy time (say nearest-microsecond 
accuracy) should be used for `t`; if nearest-second accuracy were used, an 
attacker could probe to estimate when the system clock rolls over to the next 
second, and so get information on the true clock error and drift.

For bootstrap nodes, the concerns about tracking do not apply, and bootstrap 
nodes should set `e=0` and `d=1`.

### Data Search Request and Response
These packets form an RPC DHT Packet pair.

#### Data Search Request
| Length   | Type       | Contents                    |
|:---------|:-----------|:----------------------------|
| `32`     | Public Key | Data Public Key             |
| `0 | 32` | Bytes      | SHA256 of previous response |

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
Public Key known by the responding node (see [Announce nodes]).

Note: as with Nodes requests, this part of the protocol is susceptible to UDP 
amplification abuse. Including all overheads (8 bytes for RPC Packet, 72 for 
DHT Packet, 8 for UDP header, 20 for IPv4 header), the minimum size of a 
request is 140 bytes, and the maximum size of a response is 411 bytes, giving 
an amplification ratio of 2.9. Hopefully not high enough to be useful.

If a request contains a SHA256 which is equal to the SHA256 of the response 
(i.e. of the bytes detailed in the table above) which would otherwise be sent 
to the request, the following abbreviated version of the response is sent 
instead.

| Length | Type       | Contents        |
|:-------|:-----------|:----------------|
| `32`   | Public Key | Data public key |

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
| `[53,565]`   | Bytes        | Encrypted payload         |

The payload is authenticated and encrypted with the announcement secret key 
and the recipient's DHT public key and the given nonce, and consists of a Ping 
ID, a requested timeout, and an announcement:

| Length    | Type       | Contents            |
|:----------|:-----------|:--------------------|
| `32`      | Timed Auth | Timed authenticator |
| `4`       | `uint32_t` | Requested timeout   |
| `1`       | Bytes      | Announcement Type   |
| `[0,512]` | Bytes      | Announcement Data   |

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

| Length  | Type       | Contents                |
|:--------|:-----------|:------------------------|
| `32`    | Public Key | Announcement public key |
| `4`     | `uint32_t` | Stored time             |
| `0 | 8` | `uint64_t` | Unix time               |

The stored time is 0 if the announcement request was rejected, else the time 
in seconds that the announcement will be stored for. Unix time is included 
only if the announcement request was accepted, and is then the external unix 
time of the sender at the time that the packet is constructed, adjusted by the 
synchronisation offset of the sender (see [Clock synchronisation]).

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
destination, if it's in their DHT node lists. The destination replies by 
sending a Forward Reply packet to the forwarder, and the forwarder then sends 
a Forwarding packet back to original sender. In the Forwarding packet, the 
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
via a TCP relay and a DHT node close to the destination node. The only bound 
on the length of such a chain is that the sendback grows with each step and 
has bounded size; the protocol requires the sendbacks to grow slowly enough 
that chains involving a TCP relay and 4 DHT forwarders will work. Note that 
chaining forward requests can not be used to implement onion routing, due to 
the lack of encryption at intermediate steps.

To prevent abuse, each sendback should include a timed authenticator, and this 
should be validated before accepting a Forward Reply. The timeout for this 
timed authenticator should be reasonably long, say 3600s, since a change in 
the sendback between forwarding a Search Request and a corresponding Retrieve 
Request will cause the Retrieve Request to fail.

```
    (TCP) Forward Request   Forwarding           Forwarding
          [FR+Req]         [SB1+FR+Req]        [SB2+SB1+Req]
    A ---------------> F1 ---------------> F2 ---------------> B


      (TCP) Forwarding      Forwarding         Forward Reply
           [Resp]           [SB1+Resp]         [SB2+SB1+Resp]
    A <--------------- F1 <--------------- F2 <--------------- B
```

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
from that packet. The total length of the sendback should be at most 52 bytes 
plus the size of any existing sendback.

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
to the addressee IP/Port, with a sendback which should uniquely identify the 
TCP client to the TCP server. The sendback should be at most 46 bytes.

If the addressee port is <1024, or if the addressee IP address is not 
publically routable, the packet should be ignored. This is to reduce the 
potential for abuse.

Note that TCP servers running older versions of toxcore will close the 
connection to the client on receiving this packet. TODO: probably we should 
deal with this by adding versioning in the TCP relay handshake.

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

There are two kinds of announcement: individual announcements and invite 
announcements. In each case, an announcement secret key will be obtained by 
combining the time of the announcement with a secret shared only by those the 
announcement is intended for, and the announcement public key will be that 
derived from the secret key. The differences are in the choice of secret, and 
in how the connection info is encrypted and/or signed in the announcement.

The intention is that the intended parties can be assured that what is 
announced really is our current connection info, and yet no-one else can link 
the announcement to our long-term ID, nor track changes to our DHT pubkey and 
IP address across sessions.

In fact, only individual announcements are required for core functionality. 
The purpose of invite announcements is to keep network traffic requirements 
under control, and to allow certain peers to send us friend requests, which is 
required for public bots and can simplify the process of adding friends.

## Timed hashes
Fix constants $M < P$ ("margin", and "period"), measured in seconds.

Suggested values:

    M = 1200
    P = 4096

At a given time, two **timed hashes** of a 32-byte bytestring `key` are 
defined as follows.

Let `time` be external unix time as an unsigned 64 bit integer,
let `key_offset` be the last 8 bytes of `key` interpreted as a big-endian 
unsigned 64 bit integer,
let `synch_offset` be the current synchronisation offset (see [Clock 
synchronisation]),
and define

    a := (time + key_offset + synch_offset + n*M) / P

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
information about `key_offset`. So then `key_offset` should be generated by 
hashing.

## Individual announcements
If A and B are peers, A's **individual announcement** for B consists of a 
random 24-byte nonce followed by A's timestamped connection info, 
authenticated and encrypted using that nonce and the combined key of A and B.

This is announced with announcement secret key(s) the timed hashes of the 
result of symmetrically encrypting A's ID pubkey with the combined key of A 
and B, using A's ID pubkey as the nonce.

## Invite announcements
An **invite code** is the first 16 bytes of the SHA256 hash of the public key 
of an Ed25519 signing keypair, called the **invite keypair**.

Our corresponding **invite announcement** consists of a random nonce and then 
the XSalsa20Poly1305 authenticated encryption, using the nonce and the SHA256 
hash of the invite code as an symmetric encryption key, of the following:
the public key of the invite keypair and the following signed with the invite 
keypair:
our ID pubkey and our timestamped connection info.

The encryption prevents the node where the announcement is stored from reading 
the announcement (which may contain information, such as timestamps and our 
choice of TCP relays, which might be used to identify us), while the signature 
prevents those who know the invite code from faking an announcement for us.

The invite announcement is announced with announcement secret key(s) the timed 
hashes of the invite code.

A peer who knows the invite code can use it to send us a friend request, as 
follows. They find and decrypt the announcement, checking the signature, to 
obtain our ID pubkey and connection info. They then use this to send a 
**Friend Request** packet to us; this is sent on the DHT in a DHT Request 
packet (i.e. routed via a DHT node we are connected to) and/or via TCP OOB 
packets on TCP relays we are connected to. The Friend Request packet they send 
to us consists of a UTF8 encoded friend request message prepended by a length 
(which may be 0), their ID pubkey, a random nonce, and, authenticatedly 
encrypted to our ID pubkey using their ID pubkey and the nonce, the invite 
code. A Friend Request packet containing a valid invite code triggers a 
callback, as in the current system.

For subsequent connections, friends also look for our invite announcement to 
obtain our current connection info. To enable this, we send our current invite 
code to a friend whenever we establish a friend connection with them.
We keep track of which friends we have sent our current invite code to.
We save across sessions the latest invite code we have received from each 
friend.

### Security notes
Anyone who knows our invite code can interfere with the invite announcement -- 
either by occupying the neighbourhood of the announcement pubkey on the DHT 
and behaving maliciously (e.g. accepting our announce requests but not 
actually storing the announce), or simply by overwriting our announcements. 
The latter technique could be prevented at the cost of complicating the 
protocol, but the former is inevitable.

They can also easily determine our IP address and the IP address of anyone 
searching for the announcement, by listening at the announcement pubkey.

# Announcing and searching

We maintain an invite announcement at all times.
We also maintain an individual announcement for each friend to whom we have 
not sent our current invite code.
We keep track of the total amount of time we have spent making an individual 
announcement to such a friend without a connection to the friend being made, 
saving across sessions. Once this exceeds 64 hours, we use low-intensity 
lookups (defined below) for the individual announcement.

We can expect our other friends to be able to find our invite announcement; 
however, we can not be certain that such a friend will still have the invite 
code we sent, even if they did receive it, since they might for various 
exceptional reasons have reverted to an earlier save state. There is also the 
possibility that our invite announcement could fail due e.g. to a DoS attack. 
So as a precaution, we also make low-intensity individual announcements for 
such friends.

We also search for the announcements of our offline friends.
If an offline friend was added with an invite code and we have not yet 
connected to the friend (see `FRIEND_CONFIRMED` in `Messenger.h`), we search 
for its invite announcement.
Otherwise, we search for the friend's invite announcement if we have an invite 
code for it, else for the individual announcement.

Because it is possible that we have an outdated invite code for the friend, 
when we search for a invite announcement we also make a low-intensity search 
for the individual announcement.

We ensure we are announced for the friend before beginning to search for it.

The remainder of this section describes in detail a procedure for using Data 
Search and Data Announcement packets to maintain and search for announcements.

## Background: NAT and the Tox DHT
```
               A
       |FCo|ARs|PRs|Sym
    ---+---+---+---+---
    FCo| > | > | > | >
    ---+---+---+---+---
    ARs| + | + | + | +
  B ---+---+---+---+---
    PRs| + | + | + | X
    ---+---+---+---+---
    Sym| + | + | X | X

FCo: Full Cone or less restrictive
ARs: Address Restricted cone
PRs: Port Restricted cone
Sym: Symmetric

 > : A can connect to B
 + : A can connect to B if B is also trying to connect to A
 X : active hole-punching required for connection
```

Here, "A can connect to B" means that B receives packets sent by A to the 
external address reported for B by a third-party connected to B. Because the 
Tox DHT uses an eviction strategy which prefers closest nodes in a given 
bucket (this is not standard Kademlia behaviour), the close list of a node 
will tend to acquire the closest possible nodes in each bucket for which the 
corresponding entry in the above table is not 'X'.

Figure 13 in <https://arxiv.org/abs/1605.05606> gives us rough estimates for 
the proportion of each kind of NAT we can expect to see, depending on the 
extent to which we expect mobile devices to form part of the DHT. In 
particular, it suggests that we shouldn't expect more than around 10% of nodes 
to be full cone or better, and that port restricted is the typical case. 

(Terminological note: RFC 4787 deprecates the terminology for NAT types used 
here; in the terminology it defines, symmetric means endpoint-dependent 
mapping, and full cone resp. address restricted resp. port restricted means 
endpoint-independent mapping with endpoint-independent filtering resp. 
address-dependent filtering resp. address+port-dependent filtering.)

NAT is relevant only to IPv4, but IPv6 may be deployed with stateful firewalls 
with similar effects.

## Lookups
### Overview
For each announcement at an announcement secret key we make, and for each 
search for such an announcement, we perform a *lookup* of the key which aims 
to find the `k` closest nodes to the key on the DHT network. The parameter `k` 
is the *width* of the lookup; usually the width is `k=8`, but a 
**low-intensity** lookup is a lookup with width `k=2`. 

Given NAT, we can not expect to connect directly to these closest nodes (even 
if they are invited to attempt to connect to us) nor can we rely on being able 
to connect directly to nodes which can connect directly to them. So for 
reliable operation, it is not sufficient to use forward requests only once, 
and we must allow chains of forwarding.

More concretely: suppose we are behind symmetric NAT, and the neighbourhood of 
the target consists entirely of nodes behind port-restricted or worse, and 
mostly port-restricted. Since the neighbourhood is mostly port-restricted, 
they will successfully connect to each other, so the radius of the closest 
buckets in their close lists will be small. So it might be that all the nodes 
which are `<=1` steps from the target nodes are port-restricted or worse, 
meaning that even if we used introductions we wouldn't be able to connect 
directly to them. So we must use longer chains.

### Details
A **forward chain** is a list of 0-4 DHT nodes. Sending a packet to a node via 
a forward chain means sending the packet within nested Forward Request packets 
addressed to the nodes in the chain. If we are not connected to the DHT, this 
is furtherly wrapped in a Forward Request sent to a TCP relay. If `N` is a 
node, we write `[N]` for the forward chain consisting of N alone, and if `C` 
is a forward chain, we write `C:N` for the chain resulting from appending `N` 
to `C`. We write `[]` for the empty forward chain.

For each announcement we wish to make or find, we maintain a **lookup list** 
of up to `k` DHT nodes. This list contains nodes as close as possible to the 
target key; an attempt to add a node to a full list succeeds if the node is 
closer than the furthest node on the list, which is removed to make room. For 
each node `N` on the list we maintain a forward chain `c(N)`. Whenever we 
receive a response to a request (including a forward request) sent to `N` 
along a forward chain `C`, we set `c(N)` to `C` if this does not increase the 
chain length.

To prevent exponential growth in traffic during the search process, we also 
maintain an associated "pending response set" consisting of up to `k` 
requests; whenever the algorithm below talks of sending a Data Search request 
to a node `N`, we in fact first try to add a corresponding entry to this set. 
This fails if the set is full of requests to nodes at least as close to the 
target as `N`, and then no request is actually sent. Otherwise, the request is 
added with a timestamp, with the oldest request to a node furthest from the 
target being deleted to make room if necessary, and the request is sent. The 
node is deleted from the set when a response is received or after 3 seconds. 

Initially, and periodically while the lookup list is not full, we populate the 
list by sending Data Search requests via `[]` to random announce nodes (see 
[Announce nodes]) from our DHT nodes lists if we are connected to the DHT, and 
to random bootstrap nodes otherwise.

When we receive a Data Search response to a request sent via forward chain `C` 
to a node `N`, after possibly updating `c(N)` as described above, we send a 
Data Search request to each node given in the response which could be added to 
the list, as follows:
If `N` is not on the list, we attempt to add `N` to the list with forward 
chain `C`, and any such requests are sent via `[N]`. Otherwise, if the length 
of `c(N)` is less than 4, these requests are sent via `c(N):N`. Otherwise, 
each request is sent via `c(N'):N'` where `N'` is a random node on the list 
among those such that `c(N')` has minimal length, if this minimal length is 
less than 4. Otherwise, `N` is removed from the list, and the requests are 
sent via `[]`.

If `N` is added to the list in the above and `c(N)` is non-empty but none of 
the nodes in the response could be added to the list, we send a Data Search 
request to `N` via `[]`.

A node on the list which fails to respond to a Data Search request is sent 
another at most 3s later. After 3 consecutive Data Search requests are sent to 
a node without a response, it is removed from the list.

To reduce wasteful traffic, we store with each node on the list the last 
response obtained from it, if any, and include its SHA256 in Data Search 
requests to the node. When we receive a Data Search response indicating that 
the hash in the request is that of the response which would have been sent, we 
process the stored response as if it had been sent in this response.

### Rationale
This procedure leads to us efficiently probing nodes to see if we can connect 
to them directly (i.e. via `[]`), using forward chains of length greater than 
1 only when necessary. In the unfortunate eventuality that we end up with a 
list full of nodes with forward chains of maximal length, deleting a node 
gives the opportunity for another node, perhaps a random dht node, to take its 
place; this might lead us to query a new part of the network where we may find 
more directly accessible nodes.

## Making announcements
To announce at a given announcement secret key, we perform a lookup for the 
key as above, along with the following additional behaviour.

When we receive a Data Search response from a node `N` which is already on the 
lookup list of an announcement we wish to make: after the processing described 
above, if the response indicates that our current announcement is stored or 
that a Store Announcement request would be accepted, we also send a Store 
Announcement request to `N` via `c(N)`. In this request we put an initial 
announcement, or a reannouncement if the response indicated that our current 
announcement is already stored. We set the requested timeout to 300 seconds. 

If we obtain an Announcement Store response from a node on the list indicating 
that the announcement is stored, we consider the announcement to be stored on 
the node until a Data Search response or further Store Announcement response 
indicates otherwise.

We consider an announcement to be announced if it is stored on at least half 
of the nodes in the list.

For each node `N` on the lookup list, we periodically send Data Search 
requests to `N` via `c(N)`. The interval between sending these periodic Data 
Search requests to a node at which we are not announced is `min(120,3n)` 
seconds where `n` is a count of the number of Data Search requests which have 
been sent to `N`, set to 1 whenever `N` is added to the list, and reset to 1 
when we are informed by a Data Search response from `N` that we have just 
ceased to be announced at `N`.
After we receive a Data Announcement response indicating that we are announced 
at a node, we send a Data Search request to it 3 seconds before the 
announcement is due to expire, or after 120s if this is sooner (which it will 
be if the node accepted our requested announcement timeout of 300s).

The low-intensity individual announcements used as a back-up alongside the 
invite announcement do not start until the invite announcement is announced.

## Finding announcements
To search for an announcement at a given announcement secret key, we perform a 
lookup for the key as above, along with the following additional behaviour.

During a search lookup, if we receive a Data Search response indicating that 
an announcement is stored, and the hash is not the hash of either of the two 
most recent (according to the timestamps) announcements we have obtained for 
the friend, then we send a Data Retrieve request. When we receieve an 
announcement in a Data Retrieve response, we decrypt it and/or check the 
signature as appropriate, and if it is valid and the timestamp is greater than 
that on any previous announcement we obtained for the friend, we pass the 
connection info to the appropriate modules; this will usually result in the 
search being deleted soon thereafter.

We also make periodic Data Search requests as for an announcement, but with 
different timeouts: the timeout between periodic requests for each of the `k` 
nodes is at least 15 and at most 600 seconds, and within these bounds is 
calculated as one quarter of the time since we began searching for the friend, 
or since an announcement for the friend was last seen.

When we first start searching for a given friend, and the search is not a 
low-intensity search, for 17 seconds the timeout is set to 3 seconds.


## Announce nodes
We term as **announce nodes** those DHT nodes which implement the DHT 
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

## Clock synchronisation
It is important that there is a consensus across the network on the time used 
to create timed hashes, and hence to choose announce and search locations. To 
achieve this, nodes maintain an integer **synchronisation offset**, 
initialised to 0.

Once we are announced at some key, whenever we receive an Announce response 
with a unix time, we examine the unix times most recently reported in Announce 
responses by the announce nodes for all the keys at which we are announcing, 
each incremented by the (external) time since we received the corresponding 
response, and our own external unix time. We set the synchronisation offset to 
the mean of the these times, after discarding the most extreme third (1/6 on 
each side) as outliers. If the (external) time since initialisation is less 
than 100000s, or if we are a bootstrap node, our own external unix time is not 
discounted as an outlier even if it is in the most extreme third.

Since the time sent in Announce responses is adjusted by the synchronisation 
offset, the network will tend to establish a consensus time used for Announce 
responses and timed hashes. Due to the error and drift in the external unix 
times of the nodes involved, this consensus may differ somewhat from true 
time, and a sustained attack could pull it far away -- but it will tend to 
revert to true time due to bootstrap nodes and nodes which have recently 
joined the network, whose external unix times will typically be approximately 
correct. Having consensus time close to real time is a useful but not 
essential property -- it means that a node joining the network can expect that 
their initial announces will not have to be repeated with different timed 
hashes once they set the synchronisation offset.

# Migration
To ensure backwards compatibility, we continue to process onion packets as 
usual, and moreover we search on the onion for offline friends who might still 
be announcing on the onion. For an existing friend, we consider this to be the 
case until they send us an invite code. When adding a friend, we consider it 
to be the case if and only if the added ID includes a nospam, and when it does 
we also send a friend request via the onion.

We don't announce via the onion, nor generate or expose any nospam.
To make up for not announcing, we impose a higher minimum than usual on the 
rate of searches, say at least one onion request per 30s per friend.

Preferably, clients should indicate which friends are using the legacy onion 
system, and warn the user of the privacy implications of this (so the user 
will exhort their friends to upgrade).

# Traffic estimates
Typical IPv4 UDP = 28 + data
DHT packet = 28 + 80 + payload = 108 + payload
Initial Data Search request = 108 + 32 = 140
Initial Data Search response <= 108 + 303 = 411
Subsequent Data Search request = 108 + 32 + 32 = 172
Subsequent unchanged Data Search response <= 108 + 32 = 140
Announcement <= 386
Store initial announcement = 108 + 56 + 53 + Announcement <= 603
Store reannouncement = 108 + 56 + 53 + 32 = 249
Store response = 108 + 36 = 144

Forward packet overheads: negligible, so in the below we simply multiply costs 
by 2 to account for the forwarding, assuming an average forward chain length 
of 1. This is averaging over the whole network; in fact TCP-only leeches 
forward nothing, nodes behind restrictive NAT do some forwarding, and nodes 
behind full cone or no NAT (bless them) do a lot.

The numbers below are very rough estimates, with wholly spurious precision.

Initial lookup:
Takes say 5 steps with 8 searches in each.
(5 steps is a rough estimate derived from observing DHT lookups on the tox 
network as it exists at the time of writing; the number of steps required 
increases logarithmically with the size of the network.)
Each step comprises a search and response, forwarded, so the lookup costs
`5 * 8 * 2 * (140 + 411) = 44080`.

Announcing:
Storing the announcement on 8 nodes costs another
`8 * 2 * (603+144) = 11952`. So initial cost estimate is
`44080 + 11952 = 56032`.

Once we are announced to all 8 nodes, assuming no churn, each 120s we send a 
Data Search request and then a reannouncement, at a cost of
`8 * 2 * (172+140+249+144) = 11280` per 120s, so 94Bps.

Searching:
`<=9` searches per node in first 60s;
`9 + \log_{5/4}(t/60)` searches per node in first t seconds.
Averaging over first 1800 seconds: `8*2*(172+140) * 24/1800 = 66Bps`.
Rate at 1800 seconds: `8*2*(172+140) * 4/1800 = 11Bps`.

Churn:
A very rough estimate of the effect of churn could be that it causes traffic 
equivalent to the initial costs of lookup and announcement once per 900s. (I 
have no data to back this estimate up, it may be way off.)
That would lead to a churn cost of 62Bps for an announcement and 49Bps for a 
search.

Total costs:
Suppose we have `n` offline friends, each of which has our current invite 
code. Then we make an invite announcement, `n` low-intensity individual 
announcements, `n` searches for invite keys, and `n` low-intensity searches 
for individual keys. Each low-intensity search/announcement has `1/4` of the 
usual cost, so the effective total is `1+n/4` announcements and `n*(5/4)` 
searches. So the above estimates give a total rate of
`((1+n/4)*(94+62) + n*(5/4)*(66+49)) = (156 + n*183)Bps`
averaged over the first 1800s, and
`((1+n/4)*(94+62) + n*(5/4)*(11+49)) = (156 + n*114)Bps`
at 1800s.
Each offline friend who does not know our invite key adds another 156Bps for 
an individual announcement (reduced to 39Bps after 64 hours).

Corresponding estimates for the onion:
An onion request and response generates `403+395+387+354+416+357+298+238=2848` 
bytes of traffic (packet kinds 80-83,8c-8e,84). We can generously estimate 
that during a lookup, half of requests will be to nodes which do not receive 
them (due to NAT), each such failed request costing `403+395+387+354=1539` 
bytes. If for the purposes of a fair comparison we pretend the onion uses the 
efficient lookup and maintenance procedure described above (the current 
implementation is much more expensive), and make the same estimates for churn, 
the cost of maintaining an established announcement and searches to `n` 
offline friends is
`((1+n)*5*8/900)*(2848+1539) + (8/120 + n*(8*24/1800))*2848 =
(384 + n*499)Bps`.
averaged over the first 1800s, and
`((1+n)*5*8/900)*(2848+1539) + (8/120 + n*(8*4/1800))*2848 =
(384 + n*246)Bps`.
at 1800s.
