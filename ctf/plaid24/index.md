# PlaidCTF 2024

Over the weekend I played in PPP's [PlaidCTF](https://plaidctf.com/), and managed to solve all the cryptography challenges!

Going in, I expected the difficulty to be slightly above my current skill level, so I'm quite pleased with this result. Overall I spent about 6 hours on each challenge, with 12 hours on the first day for `DHCPPP` and `Paranormial Commmitment Scheme`, and then another 6 hours on the second day to solve `MMORPG`. 

This was definitely one of my favourite CTFs this year. Massive thank you to [Plaid Parliament of Pwning](https://pwning.net/) for hosting.

@def maxtoclevel=2

\toc



## DHCPPP
In this challenge we are given access to two servers: a DHCP server which
simulates assigning IP addresses and DNS parameters to clients using the DHCP protocol, and a flag server which receives
leases from the DHCP server and uses the provided parameters to make HTTP requests.
```python
import time, zlib
import secrets
import hashlib
import requests
from Crypto.Cipher import ChaCha20_Poly1305
import dns.resolver

CHACHA_KEY = secrets.token_bytes(32)
TIMEOUT = 1e-1

def encrypt_msg(msg, nonce):
    # In case our RNG nonce is repeated, we also hash
    # the message in. This means the worst-case scenario
    # is that our nonce reflects a hash of the message
    # but saves the chance of a nonce being reused across
    # different messages
    nonce = sha256(msg[:32] + nonce[:32])[:12]

    cipher = ChaCha20_Poly1305.new(key=CHACHA_KEY, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg)

    return ct+tag+nonce

def decrypt_msg(msg):
    ct = msg[:-28]
    tag = msg[-28:-12]
    nonce = msg[-12:]

    cipher = ChaCha20_Poly1305.new(key=CHACHA_KEY, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)

    return pt

def calc_crc(msg):
    return zlib.crc32(msg).to_bytes(4, "little")

def sha256(msg):
    return hashlib.sha256(msg).digest()

RNG_INIT = secrets.token_bytes(512)

class DHCPServer:
    def __init__(self):
        self.leases = []
        self.ips = [f"192.168.1.{i}" for i in range(3, 64)]
        self.mac = bytes.fromhex("1b 7d 6f 49 37 c9")
        self.gateway_ip = "192.168.1.1"

        self.leases.append(("192.168.1.2", b"rngserver_0", time.time(), []))

    def get_lease(self, dev_name):
        if len(self.ips) != 0:
            ip = self.ips.pop(0)
            self.leases.append((ip, dev_name, time.time(), []))
        else:
            # relinquish the oldest lease
            old_lease = self.leases.pop(0)
            ip = old_lease[0]
            self.leases.append((ip, dev_name, time.time(), []))

        pkt = bytearray(
            bytes([int(x) for x in ip.split(".")]) +
            bytes([int(x) for x in self.gateway_ip.split(".")]) +
            bytes([255, 255, 255, 0]) +
            bytes([8, 8, 8, 8]) +
            bytes([8, 8, 4, 4]) +
            dev_name +
            b"\x00"
        )

        pkt = b"\x02" + encrypt_msg(pkt, self.get_entropy_from_lavalamps()) + calc_crc(pkt)

        return pkt

    def get_entropy_from_lavalamps(self):
        # Get entropy from all available lava-lamp RNG servers
        # Falling back to local RNG if necessary
        entropy_pool = RNG_INIT

        for ip, name, ts, tags in self.leases:
            if b"rngserver" in name:
                try:
                    # get entropy from the server
                    output = requests.get(f"http://{ip}/get_rng", timeout=TIMEOUT).text
                    entropy_pool += sha256(output.encode())
                except:
                    # if the server is broken, get randomness from local RNG instead
                    entropy_pool += sha256(secrets.token_bytes(512))

        return sha256(entropy_pool)

    def process_pkt(self, pkt):
        assert pkt is not None

        src_mac = pkt[:6]
        dst_mac = pkt[6:12]
        msg = pkt[12:]

        if dst_mac != self.mac:
            return None

        if src_mac == self.mac:
            return None

        if len(msg) and msg.startswith(b"\x01"):
            # lease request
            dev_name = msg[1:]
            lease_resp = self.get_lease(dev_name)
            return (
                self.mac +
                src_mac + # dest mac
                lease_resp
            )
        else:
            return None

class FlagServer:
    def __init__(self, dhcp):
        self.mac = bytes.fromhex("53 79 82 b5 97 eb")
        self.dns = dns.resolver.Resolver()
        self.process_pkt(dhcp.process_pkt(self.mac+dhcp.mac+b"\x01"+b"flag_server"))

    def send_flag(self):
        with open("flag.txt", "r") as f:
            flag = f.read().strip()
        curl("example.com", f"/{flag}", self.dns)

    def process_pkt(self, pkt):
        assert pkt is not None

        src_mac = pkt[:6]
        dst_mac = pkt[6:12]
        msg = pkt[12:]

        if dst_mac != self.mac:
            return None

        if src_mac == self.mac:
            return None

        if len(msg) and msg.startswith(b"\x02"):
            # lease response
            pkt = msg[1:-4]
            pkt = decrypt_msg(pkt)
            crc = msg[-4:]
            assert crc == calc_crc(pkt)

            self.ip = ".".join(str(x) for x in pkt[0:4])
            self.gateway_ip = ".".join(str(x) for x in pkt[4:8])
            self.subnet_mask = ".".join(str(x) for x in pkt[8:12])
            self.dns1 = ".".join(str(x) for x in pkt[12:16])
            self.dns2 = ".".join(str(x) for x in pkt[16:20])
            self.dns.nameservers = [self.dns1, self.dns2]
            assert pkt.endswith(b"\x00")

            print("[FLAG SERVER] [DEBUG] Got DHCP lease", self.ip, self.gateway_ip, self.subnet_mask, self.dns1, self.dns2)

            return None

        elif len(msg) and msg.startswith(b"\x03"):
            # FREE FLAGES!!!!!!!
            self.send_flag()
            return None

        else:
            return None

def curl(url, path, dns):
    ip = str(dns.resolve(url).response.resolve_chaining().answer).strip().split(" ")[-1]
    url = "http://" + ip
    print(f"Sending flage to {url}")
    requests.get(url + path)

if __name__ == "__main__":
    dhcp = DHCPServer()
    flagserver = FlagServer(dhcp)

    while True:
        pkt = bytes.fromhex(input("> ").replace(" ", "").strip())

        out = dhcp.process_pkt(pkt)
        if out is not None:
            print(out.hex())

        out = flagserver.process_pkt(pkt)
        if out is not None:
            print(out.hex())
```
At any time, can ask the flag server to make a request containing the flag to `example.com` by sending it a message beginning with `0x03`. The goal then, is to provide the flag server with a forged DHCP lease which contains a DNS server controlled by us. Then, when the flag server attempts to resolve `example.com` we can reply with an address we control, and intercept the following HTTP request.

The DHCP leases are protected using [ChaCha20Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305), which combines the ChaCha20 stream cipher with Poly1305 for authentication.

@@invert_image
![ChaCha20Poly1305](https://upload.wikimedia.org/wikipedia/commons/5/55/ChaCha20-Poly1305_Encryption.svg)
@@
Since the encryption key remains constant throughout each session, we can forge messages if we can find two different ciphertexts encrypted using the same nonce. To protect against nonce reuse, the server employs two tactics. The first is the `get_entropy_from_lavalamps()` function, which repeatedly extends and then hashes a persistent entropy pool.
```python
def get_entropy_from_lavalamps(self):
    # Get entropy from all available lava-lamp RNG servers
    # Falling back to local RNG if necessary
    entropy_pool = RNG_INIT

    for ip, name, ts, tags in self.leases:
        if b"rngserver" in name:
            try:
                # get entropy from the server
                output = requests.get(f"http://{ip}/get_rng", timeout=TIMEOUT).text
                entropy_pool += sha256(output.encode())
            except:
                # if the server is broken, get randomness from local RNG instead
                entropy_pool += sha256(secrets.token_bytes(512))

    return sha256(entropy_pool)
```
The request made to the RNG server is never successful, and so the server will default back to Python's `secrets` module for randomness. Note however that the entropy pool only gets updated if there is an active lease containing the string `"rngserver"` in its device name. If no such lease exists, the entropy pool will remain constant across encryptions, opening up the potential for nonce reuse. Since the RNG server is the first client to receive a lease from the server, all we have to do is keep requesting additional leases until the server runs out of IP addresses and the RNG server's lease is relinquished.

The second nonce-reuse mitigation comes from the `encrypt_msg()` function, which hashes a portion of the message into the nonce. Here,
`nonce` is the value obtained from the `get_entropy_from_lavalamps()` function.

```python
def encrypt_msg(msg, nonce):
    # In case our RNG nonce is repeated, we also hash
    # the message in. This means the worst-case scenario
    # is that our nonce reflects a hash of the message
    # but saves the chance of a nonce being reused across
    # different messages
    nonce = sha256(msg[:32] + nonce[:32])[:12]

    cipher = ChaCha20_Poly1305.new(key=CHACHA_KEY, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg)

    return ct+tag+nonce
```
This means that to pull off our forgery attack, we must obtain two distinct ciphertexts for which the corresponding plaintexts are identical in the first 32 bytes. Fortunately this is fairly easy to do. The only information in the plaintext which changes across leases is the leased IP and the first twelve bytes of the device name. We can control the former by continuing to request leases until we are assigned the same IP again, and we can choose the latter at will.

Now that we have a ciphertext pair $C_1, C_2$ encrypted with a shared nonce $N$ and key $K$, we can begin to forge messages. First, we have to replace the default DNS parameter `8.8.8.8` with the address of a server we control. Suppose $C_{D}$ is the ciphertext of the DNS parameter. Since the keystream $E(N, K)$ depends only on the nonce and the key, we know that (up to some offset in counter value), we have

\begin{equation*}
E(N, K) \oplus \mathrm{8.8.8.8} = C_D 
\end{equation*}
and so
\begin{equation*}
C_D \oplus \mathrm{8.8.8.8} \oplus \text{(chosen DNS)} = E(N, K) \oplus \text{(chosen DNS)}. 
\end{equation*} Hence replacing $C_D$ in the packet with $C_D \oplus \mathrm{8.8.8.8} \oplus \text{(chosen DNS)}$ will cause the DNS parameter to decrypt to a server of our choosing.

Finally, we have to recompute the Poly1305 tag so that our forged message authenticates as a genuine lease sent by the DHCP server. To do this, we must recover the Poly1305 keys used in the original authentication of $C_1$ and $C_2$. 

In the general case, suppose $C$ is a ciphertext composed of $n$ 16-byte blocks $m_1, \ldots, m_m$ and let $m_{\mathrm{meta}}$ be a fixed metadata block containing ciphertext length information. Let $r$ and $s$ be the secret Poly1305 keys. Then the authentication tag is calculated as

\begin{equation*}
T = \mathrm{Poly1305}(C, r, s) = \left[s + \left[m_{\mathrm{meta}} + \sum_{k = 1}^n \mathrm{pad}(m_k) r^k \right]_p\right]_{2^{128}}
\end{equation*} where $p$ is the prime $2^{130} - 5$ and the notation $\left[ \quad\right]_q$ denotes reduction modulo $q$. Since the authentication tag is calculated as a polynomial in $r$ and $s$ with coefficients given by the ciphertext bytes, then given two distinct authentication tags $T_1$ and $T_2$ we can calculate 
\begin{equation*}
T_1 - T_2 = \mathrm{Poly1305}(C_1, r, s) - \mathrm{Poly1305}(C_2, r, s) 
\end{equation*} which is a polynomial in $r$ only. Finding the roots of this polynomial modulo $p$ yields possible values of $r$ (and hence $s$), up to a multiple of $2^{128}$. We can then narrow these possibilities down to a smaller subset containing the genuine values of $r$ and $s$ by considering only values which satisfy the [clamping requirements](https://datatracker.ietf.org/doc/html/rfc7539#section-2.5) and which can correctly authenticate other genuine ciphertexts.


In practice, the messages we were forging only differed in the last message block (corresponding to a difference in device name). Hence the resulting polynomial $T_1 - T_2$ was quadratic, and easily solvable over $p$ using only Python built-ins. Since we only had one chance to forge a lease, the low degree was also beneficial in that it reduced the number of roots, and so we were more likely to find the correct value of $r$ on our first attempt.

Once we have forged a DHCP lease, all that remains is to open a fake DNS server on port 53 which will resolve all requests back to ourselves, and then a listener on port 80 for the incoming HTTP request. For the DNS server I used Patryk Hes's [fakedns](https://github.com/pathes/fakedns/tree/master) and for the listener I used `nc -lvnp 80`.

Below is an implementation of the above solution in Python.
```python
#!/usr/bin/env python3

import time, zlib
import secrets
import hashlib
import requests
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Util.strxor import strxor
from Crypto.Util.number import *
import dns.resolver
from pwn import *

CHACHA_KEY = secrets.token_bytes(32)
TIMEOUT = 1e-1

context.log_level = "debug"
conn = connect("dhcppp.chal.pwni.ng", 1337)


def encrypt_msg(msg, nonce):
    # In case our RNG nonce is repeated, we also hash
    # the message in. This means the worst-case scenario
    # is that our nonce reflects a hash of the message
    # but saves the chance of a nonce being reused across
    # different messages
    # print(f"DEBUG: encrypt_msg on nonce[:32] = {nonce[:32]} and msg[:32] = {msg[:32]}")
    nonce = sha256(msg[:32] + nonce[:32])[:12]
    cipher = ChaCha20_Poly1305.new(key=CHACHA_KEY, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg)

    return ct+tag+nonce

def decrypt_msg(msg):
    ct = msg[:-28]
    tag = msg[-28:-12]
    nonce = msg[-12:]

    cipher = ChaCha20_Poly1305.new(key=CHACHA_KEY, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)

    return pt

def calc_crc(msg):
    return zlib.crc32(msg).to_bytes(4, "little")

def sha256(msg):
    return hashlib.sha256(msg).digest()

RNG_INIT = secrets.token_bytes(512)

class DHCPServer:
    # -- same as in challenge script --

class FlagServer:
    # -- same as in challenge script --

def curl(url, path, dns):
    ip = str(dns.resolve(url).response.resolve_chaining().answer).strip().split(" ")[-1]
    url = "http://" + ip
    print(f"Sending flage to {url}")
    requests.get(url + path)


def get_flag(dhcp, flagserver):
    pkt = (
        dhcp.mac +              # src_mac
        flagserver.mac +        # dst_mac
        b"\x03"                 # msg: get flag
    )

    conn.sendlineafter(b"> ", pkt.hex().encode("utf-8"))


def get_lease(dhcp, flagserver, dev_name):
    pkt = (
        flagserver.mac +              # src_mac
        dhcp.mac +                    # dst_mac
        b"\x01" +                     # msg: lease_request
        dev_name                      # dev_name
    )

    conn.recvuntil("> ")
    conn.sendline(pkt.hex().encode("utf-8"))
    response = bytes.fromhex(conn.recvline().strip().decode())
    return response

def parse_dhcp_lease(pkt):
    src_mac = pkt[:6]
    dst_mac = pkt[6:12]
    msg = pkt[12:]

    assert len(msg) and msg.startswith(b"\x02")
    dhcp_type = msg[:1]

    # CRC
    crc = msg[-4:]
    # assert crc == calc_crc(pkt) # flag server will check crc against decrypted packet

    # Encrypted portion
    pkt = msg[1:-4]
    ct = pkt[:-28]
    tag = pkt[-28:-12]
    nonce = pkt[-12:]


    ip = ct[0:4]
    gateway_ip = ct[4:8]
    subnet_mask = ct[8:12]
    dns1 = ct[12:16]
    dns2 = ct[16:20]
    dev_name = ct[20:-1]
    null_byte = ct[-1:]

    parsed = {
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "dhcp_type": dhcp_type,
        "ip": ip,
        "gateway_ip": gateway_ip,
        "subnet_mask": subnet_mask,
        "dns1": dns1,
        "dns2": dns2,
        "dev_name": dev_name,
        "null_byte": null_byte,
        "ct": ct,
        "tag": tag,
        "nonce": nonce,
        "crc": crc
    }

    return parsed

def serialise_dhcp_lease(lease):
    return (
        lease["src_mac"] +
        lease["dst_mac"] +
        lease["dhcp_type"] +
        lease["ip"] +
        lease["gateway_ip"] +
        lease["subnet_mask"] +
        lease["dns1"] +
        lease["dns2"] +
        lease["dev_name"] +
        lease["null_byte"] +
        lease["tag"] +
        lease["nonce"] +
        lease["crc"]
    )

def serialise_dhcp_lease_ct(lease):
    ct = (
        lease["ip"] +
        lease["gateway_ip"] +
        lease["subnet_mask"] +
        lease["dns1"] +
        lease["dns2"] +
        lease["dev_name"] +
        lease["null_byte"]
    )
    return ct


def serialise_ip(ip):
    return bytes([int(x) for x in ip.split(".")])

def parse_ip(ip):
    return ".".join(str(x) for x in ip)

def get_plaintext(ip, gateway_ip, dns1, dev_name):
    pkt = bytearray(
        bytes([int(x) for x in ip.split(".")]) + # ip
        bytes([int(x) for x in gateway_ip.split(".")]) + # gateway_ip
        bytes([255, 255, 255, 0]) +                      # subnet mask
        serialise_ip(dns1) +                             # nameserver 1
        bytes([8, 8, 4, 4]) +                            # nameserver 2
        dev_name +
        b"\x00"
    )

    return bytes(pkt)

def grouper(iterable, n, *, incomplete='fill', fillvalue=None):
    "Collect data into non-overlapping fixed-length chunks or blocks."
    # grouper('ABCDEFG', 3, fillvalue='x') → ABC DEF Gxx
    # grouper('ABCDEFG', 3, incomplete='strict') → ABC DEF ValueError
    # grouper('ABCDEFG', 3, incomplete='ignore') → ABC DEF
    iterators = [iter(iterable)] * n
    match incomplete:
        case 'fill':
            return zip_longest(*iterators, fillvalue=fillvalue)
        case 'strict':
            return zip(*iterators, strict=True)
        case 'ignore':
            return zip(*iterators)
        case _:
            raise ValueError('Expected fill, strict, or ignore')

def aead_chacha20_poly1305_message_construct(ciphertext, aad):
    padding1 = b"\x00" * (-len(aad) % 16)
    padding2 = b"\x00" * (-len(ciphertext) % 16)
    aad_length = p64(len(aad))
    ciphertext_length = p64(len(ciphertext))

    return aad + padding1 + ciphertext + padding2 + aad_length + ciphertext_length


p = pow(2, 130) - 5
def poly1305_poly(message):
    groups = grouper(bytearray(message), 16, incomplete = "strict")
    coeffs = []

    for m in groups:
        m = bytes(m)
        coeff = int.from_bytes(m + b"\x01",'little') % p
        coeffs.append(coeff)
    return coeffs

def evalpoly(point, coeffs, modulus = p):
    # Coeffs from big to small
    acc = 0
    for coeff in coeffs:
        acc += coeff
        acc *= point
        acc = acc % p
    return acc

def forge_dhcp(flagserver, lease, new_lease_dns, r, s, device_name, new_lease_dns_pt):
    new_lease = lease | {'dns1': new_lease_dns}

    # New ChaChaPoly1305 tag
    new_lease_ct = serialise_dhcp_lease_ct(new_lease)
    message = aead_chacha20_poly1305_message_construct(new_lease_ct, b"")
    tag = (evalpoly(r, poly1305_poly(message)) + s) % pow(2, 128)
    new_lease['tag'] = int.to_bytes(tag, 16, 'little')

    # New CRC
    new_lease_pt = get_plaintext("192.168.1.3", "192.168.1.1", new_lease_dns_pt, device_name)
    new_lease['crc'] = calc_crc(new_lease_pt)

    pkt = serialise_dhcp_lease(new_lease)

    conn.recvuntil("> ")
    conn.sendline(pkt.hex().encode("utf-8"))

def solve():
    dhcp = DHCPServer()
    flagserver = FlagServer(dhcp)

    # Keep acquiring leases until the rng server's lease is expired.
    device_name = b"X" * 13
    for i in range(len(dhcp.ips) + 1):
        get_lease(dhcp, flagserver, device_name)

    # Now our entropy source is expired.
    # Acquire a lease. Any other lease with this ip will have a reused ChaCha20Poly1305 nonce.
    lease = parse_dhcp_lease(get_lease(dhcp, flagserver, device_name))
    lease_ip = lease["ip"]
    lease_dns = lease["dns1"]

    # We know that: keystream + "8.8.8.8" = lease_dns
    # lease_dns + "8.8.8.8" + "our dns server" = keystream + "our dns server"
    new_lease_dns_pt = CISCOS_IP
    our_dns_server = serialise_ip(new_lease_dns_pt)
    google_dns_server = serialise_ip("8.8.8.8")
    new_lease_dns = strxor(strxor(lease_dns, google_dns_server), our_dns_server)

    # Now that we have our new dns server, we need to recompute the CRC and the authentication tag.
    # First, get another encryption using the same nonce
    device_name2 = b"X" * 12 + b"Y" * 1
    while True:
        lease2 = parse_dhcp_lease(get_lease(dhcp, flagserver, device_name2))
        if lease2["nonce"] == lease["nonce"]:
            break

    # Ciphertexts
    ct1 = lease["ct"]
    ct2 = lease2["ct"]

    # Tags
    tag1 = int.from_bytes(lease["tag"], 'little')
    tag2 = int.from_bytes(lease2["tag"], 'little')

    # Poly1305 inputs
    message1 = aead_chacha20_poly1305_message_construct(ct1, b"")
    message2 = aead_chacha20_poly1305_message_construct(ct2, b"")

    # Construct the corresponding Poly1305 
    poly1 = poly1305_poly(message1)
    poly2 = poly1305_poly(message2)

    coeff1 = poly1[-2]
    coeff2 = poly2[-2]
    for i in range(len(poly1)):
        if i != len(poly1) - 2:
            assert poly1[i] == poly2[i]

    # (coeff1 - coeff2)r^2 = (tag1 - tag2) % pow(2, 128)
    rs = []
    ss = []
    for tag1_index in range(5):
        tag1_s = (tag1 + pow(2, 128) * tag1_index) % p
        for tag2_index in range(5):
            tag2_s = (tag2 + pow(2, 128) * tag2_index) % p
            r_squared = ((inverse(coeff2 - coeff1, p) * (tag2_s - tag1_s)) % p)
            for r in [pow(r_squared, (p + 1) // 4, p), -pow(r_squared, (p + 1) // 4, p) % p]:
                s1 = (tag1_s - evalpoly(r, poly1)) % p
                s2 = (tag2_s - evalpoly(r, poly2)) % p
                if s1 == s2:
                    rs.append(r)
                    ss.append(s1)

    ss = [s for r, s in zip(rs, ss) if (0x0ffffffc0ffffffc0ffffffc0fffffff & r) == r]
    rs = [r for r in rs if (0x0ffffffc0ffffffc0ffffffc0fffffff & r) == r]

    # Request a new lease and check if our keys can verify the message
    for _ in range(2):
        char = long_to_bytes(0x61 + i)
        for _ in range(100):
            dummy_lease = parse_dhcp_lease(get_lease(dhcp, flagserver, b"X" * 12 + char))
            if dummy_lease['nonce'] == lease['nonce']:
                break
        dummy_lease_ct = serialise_dhcp_lease_ct(dummy_lease)
        message = aead_chacha20_poly1305_message_construct(dummy_lease_ct, b"")

        for r, s in zip(rs, ss):
            tag = (evalpoly(r, poly1305_poly(message)) + s) % pow(2, 128)
            tag = int.to_bytes(tag, 16, 'little')
            if tag != dummy_lease['tag']:
                rs.remove(r)
                ss.remove(s)

    for r, s in zip(rs, ss):
        forge_dhcp(flagserver, lease, new_lease_dns, r, s, device_name, new_lease_dns_pt)
        break

    get_flag(dhcp, flagserver)
    conn.recvall()
```
### Flag
```plaintext
PCTF{d0nt_r3u5e_th3_n0nc3_d4839ed727736624}
```
## Paranormial Commitment Scheme
This challenge is based on the [KZG commitment scheme](https://en.wikipedia.org/wiki/Commitment_scheme#KZG_commitment) over [BLS12-381](https://github.com/zkcrypto/bls12_381), a pairing-friendly elliptic curve construction which trades-off pairing efficiency with security.

In the following, let $K$ and $E$ be the field and elliptic curve defined by the BLS12-381 parameters, and let $\mathbb{G}_1$ and $\mathbb{G}_2$ be two additive cyclic subgroups of $E(\overline{K})$ of equal prime order, such that there exists a non-degenerate bilinear pairing $e: \mathbb{G}_1 \times \mathbb{G}_2 \longrightarrow \mathbb{G}_T$ into a third multiplicative cyclic group $\mathbb{G}_T$. More details of this construction can be found in [the crate documentation](https://github.com/zkcrypto/bls12_381).

For the KZG commitment, we follow the notation of the [Wikipedia article](https://en.wikipedia.org/wiki/Commitment_scheme#KZG_commitment). Let $G$ and $H$ be the generators of $\mathbb{G}_1$ and $\mathbb{G}_2$ respectively. Let $t \in K$ be a trapdoor value which is unknown and discarded after use, and assume that $G \cdot t^i$ and $H \cdot t^i$ are known and shared for arbitrarily many positive integer values of $i$.

The challenge program begins by first generating a random polynomial $p'(x)$ over $K$. It then augments $p'(x)$ using the integer representation of the flag value $F$ by calculating the polynomial
\begin{equation*}
p(x) = p'(x) + F - p'(\alpha)
\end{equation*} where $\alpha \in K$ is a fixed large constant. The challenge program then proceeds to perform a KZG commitment using the polynomial $p$, revealing to us the commitment value
\begin{equation*}
C = \sum_{i = 0}^{255} p_iGt^i
\end{equation*} where the $p_i$ are the coefficients of $p$ in ascending degree. The challenge program also provides us with 512 alleged proofs of the commitment's authenticity
\begin{equation*}
\pi_z = \sum_{i = 0}^{255}q_{i,z}Gt^i
\end{equation*} where $0 \leq z < 512$ and $q_{i,z}$ are the coefficients of the polynomial
\begin{equation*}
q_{z}(x) = \left\lfloor \frac{p(x)}{x - z}\right\rfloor.
\end{equation*}
Here $\lfloor \quad \rfloor$ is used to denote the quotient after Euclidean division. Of the provided proofs, roughly two-thirds are genuine, and one third are have been obscured by "paranomial activity" and are just randomly generated values of $K$ and $E(K)$. 
```rust
use pairing_ce::{
    bls12_381::{Fr, G1Affine},
    ff::{Field, PrimeField}, CurveAffine, GenericCurveProjective,
};
use paranormial::{Polynomial, Setup};
use primitive_types::U256;
use rand::{OsRng, Rng};
use std::{
    fs::File,
    io::Read,
};

const DEGREE: usize = 256;
const ALPHA: &str = "1337133713371337133713371337133713371337133713371337133713371337133713371337";

const NUM_POINTS: usize = 512;
const PARANOMIAL_RATE: u32 = 3;

fn main() {
    let setup_path = std::env::args().nth(1).expect("no output file given");
    let flag_path = std::env::args().nth(2).expect("no flag file given");
    let output_path = std::env::args().nth(3).expect("no output file given");

    let f = File::open(setup_path).unwrap();
    let setup: Setup = serde_json::from_reader(f).expect("error deserializing setup");
    let mut poly = Polynomial::rand(DEGREE);

    let mut f = File::open(flag_path).unwrap();
    let mut flag = [0u8; 32];
    f.read(&mut flag).expect("error reading flag file");

    let flag = U256::from_big_endian(&flag);
    let mut offset = Fr::from_str(&flag.to_string()).unwrap();

    let alpha = Fr::from_str(ALPHA).unwrap();
    offset.sub_assign(&poly.evaluate(alpha));
    poly.add_scalar(offset);

    let com = poly.commit(&setup);
    let f = File::create(output_path).unwrap();

    let mut values = Vec::with_capacity(NUM_POINTS);
    for i in 0..NUM_POINTS {
        let z = Fr::from_str(&i.to_string()).unwrap();
        let (mut y, mut proof) = poly.prove(&setup, z);

        let mut rng = OsRng::new().unwrap();
        if rng.gen_weighted_bool(PARANOMIAL_RATE) {
            println!("paranormial activity occured");
            y = rng.gen::<Fr>();
            proof = G1Affine::one().mul(rng.gen::<Fr>()).into_affine();
        }
        values.push((y, proof));
    }

    serde_json::to_writer(f, &(com, values)).expect("serialization failed");
}
```
To solve this challenge, we first observe that 
\begin{equation*}
p(\alpha) = p'(\alpha) + F - p'(\alpha) = F, 
\end{equation*} and so we can recover the flag if we can recover the polynomial $p$ and evaluate the point $\alpha$ on it. The values of $y_z$ revealed by the commitment scheme provide us with interpolation points for recoving the polynomial $p$. For a 256-degree polynomial, 512 points with distinct abscissas should be more than sufficient to recover the polynomial. However approximately one third of the revealed $y_z$'s will be bogus randomly generated points which will throw off our interpolation, so we first need a way to distinguish genuine ordinates from randomly generated ones.

Luckily, this is what the KZG commitment scheme was designed for. Let $y_z$ be the revealed value of $p(z)$. Following the [protocol](https://en.wikipedia.org/wiki/Commitment_scheme#Verify), we compute the pairings
\begin{equation*}
e(\pi_z, H \cdot t - H \cdot z),\\
e(C - G \cdot y_z, H).
\end{equation*} If the revealed value is genuine, then these two pairings should be equal in $\mathbb{G}_T$. Once we have isolated the genuine interpolation points, we can then use Lagrange interpolation to reconstruct the polynomial $p$, and evaluate $F = p(\alpha)$ to obtain the flag.

Note the challenge implementation differs from the protocol on the Wikipedia page somewhat in that provides
\begin{equation*}
q_{z}(x) = \left\lfloor \frac{p(x)}{x - z}\right\rfloor
\end{equation*} as the proof rather than
\begin{equation*}
q_{z}(x) = \left\lfloor \frac{p(x) - y_z}{x - z}\right\rfloor.
\end{equation*} But both these quotients are in fact equal since $y_z$ is a constant, and hence has degree less than the divisor.

Below is an implementation in Rust.
```rust
use std::{fs::File, io::Read};

use indicatif::ProgressIterator;
use pairing_ce::{
    bls12_381::{Fr, FrRepr, G1Affine, G2Affine},
    ff::{Field, PrimeField},
    CurveAffine, CurveProjective,
};
use paranormial::Setup;
use primitive_types::U256;

const ALPHA: &str = "1337133713371337133713371337133713371337133713371337133713371337133713371337";

fn verify(comm: &G1Affine, y: &Fr, proof: &G1Affine, setup: &Setup, z: Fr) -> bool {
    let ht = setup.g2_base;
    let hz = G2Affine::one().mul(z).into_affine();

    // LHS = e(pi, Ht - Hi)
    let mut lhs = proof.pairing_with(&ht);
    let pi_hz = proof.pairing_with(&hz).inverse().unwrap();
    lhs.mul_assign(&pi_hz);

    // RHS = e(C - Gy, H)
    let h = G2Affine::one();
    let gy = G1Affine::one().mul(*y).into_affine();
    let mut rhs = comm.pairing_with(&h);
    let gy_h = gy.pairing_with(&h).inverse().unwrap();
    rhs.mul_assign(&gy_h);

    lhs.eq(&rhs)
}

fn lagrange_interpolation(points: Vec<(usize, &(Fr, G1Affine))>, eval: Fr) -> Fr {
    let mut res = Fr::zero();
    let n: usize = points.len();

    for i in 0..n {
        if let Some((x_i, (y_i, _))) = points.get(i) {
            let mut prod_res = Fr::one();

            for j in (0..n)
                .enumerate()
                .filter(|&(pos, _)| (pos != i))
                .map(|(_, e)| e)
            {
                // alpha - x_j
                let mut numerator = eval.clone();
                let x_j = points.get(j).unwrap().0;
                let x_j = Fr::from_str(&x_j.to_string()).unwrap();
                numerator.sub_assign(&x_j);

                // x_i - x_j
                let mut denominator = Fr::from_str(&x_i.to_string()).unwrap();
                denominator.sub_assign(&x_j);
                denominator = denominator.inverse().unwrap();

                numerator.mul_assign(&denominator);
                prod_res.mul_assign(&numerator);
            }

            prod_res.mul_assign(&y_i);
            res.add_assign(&prod_res);
        }
    }
    res
}

fn main() {
    // program args
    let setup_path = std::env::args().nth(1).expect("no output file given");
    let output_path = std::env::args().nth(2).expect("no output file given");

    // setup
    let f = File::open(setup_path).unwrap();
    let setup: Setup = serde_json::from_reader(f).expect("error deserializing setup");

    // points / output
    let f = File::open(output_path).unwrap();
    let (comm, values): (G1Affine, Vec<(Fr, G1Affine)>) =
        serde_json::from_reader(f).expect("error deserializing output");

    let valid_points: Vec<(usize, &(Fr, G1Affine))> = values
        .iter()
        .enumerate()
        .progress()
        .filter(|(z, (y, proof))| {
            let z = Fr::from_str(&z.to_string()).unwrap();
            verify(&comm, y, proof, &setup, z)
        })
        .collect();

    dbg!(&valid_points.len());

    let f = File::create("valid_points.json").unwrap();
    serde_json::to_writer(f, &valid_points).expect("serialization failed");

    let alpha = Fr::from_str(ALPHA).unwrap();
    let computed_flag = lagrange_interpolation(valid_points, alpha);

    dbg!(computed_flag);
}
```

### Flag
```plaintext
PCTF{k4t3_d3t3cts_paran0rm1als}
```
## MMORPG 
In this challenge we are placed in a restricted Python environment where we are
only permitted to evaluate a small subset of "safe" expressions. In particular,
evaluating the `get_flag()` function is deemed unsafe. Once the safety of an
expression is determined, its hash is stored in a cache and future expressions
exhibiting the same hash are not checked again for safety.

The goal then, is to pull off a second-preimage attack, where given an "unsafe" expression
$x$ containing a call to `get_flag()`, we wish to find a "safe" expression $x'$ which hashes to the same value.
```python
from functools import reduce
from operator import xor
from hashlib import sha256
from binascii import hexlify, unhexlify

with open("flag", "r") as f:
  FLAG = f.read().strip()

BLOCK_SZ = 32
HBS = BLOCK_SZ // 2
assert HBS % 4 == 0

def mpy(x, y):
  assert 0 <= min(x, y) <= max(x, y) < 256
  p = 0
  for _ in range(8):
    if y & 1 != 0:
      p ^= x
    x <<= 1
    if x & 0x100 != 0:
      x ^= 0x11d
    y >>= 1
  return p

M = [[0x04, 0x47, 0x8e, 0x01], [0x47, 0x04, 0x01, 0x8e], [0x8e, 0x01, 0x04, 0x47], [0x01, 0x8e, 0x47, 0x04]]
P = [10, 11, 12, 2, 14, 6, 15, 13, 8, 7, 9, 5, 0, 1, 4, 3]
S = [6, 98, 179, 28, 64, 3, 110, 124, 194, 137, 105, 62, 19, 146, 82, 73, 199, 10, 33, 165, 151, 251, 97, 148, 101, 153, 252, 187, 103, 254, 5, 213, 100, 108, 142, 51, 68, 224, 16, 58, 183, 208, 55, 215, 128, 210, 107, 242, 80, 192, 36, 50, 157, 173, 45, 122, 106, 56, 104, 32, 195, 232, 132, 13, 155, 246, 35, 138, 66, 221, 2, 121, 227, 113, 203, 234, 228, 207, 196, 9, 225, 201, 184, 89, 248, 95, 129, 126, 8, 222, 49, 181, 154, 241, 217, 250, 0, 249, 38, 167, 57, 41, 59, 12, 185, 30, 39, 26, 7, 214, 238, 20, 198, 79, 166, 162, 159, 239, 193, 119, 189, 65, 54, 130, 1, 178, 93, 237, 133, 63, 223, 147, 92, 43, 163, 123, 141, 191, 168, 37, 15, 220, 211, 69, 244, 27, 86, 70, 240, 53, 160, 116, 144, 145, 11, 134, 21, 229, 233, 22, 17, 182, 109, 114, 206, 158, 131, 115, 52, 197, 175, 202, 186, 143, 180, 245, 169, 25, 88, 102, 236, 140, 226, 120, 125, 4, 235, 177, 164, 47, 171, 81, 118, 48, 61, 14, 172, 72, 18, 112, 91, 255, 76, 174, 205, 216, 75, 161, 243, 29, 99, 44, 46, 231, 42, 139, 136, 67, 83, 135, 204, 84, 247, 253, 60, 150, 77, 176, 190, 127, 96, 117, 34, 90, 188, 78, 74, 149, 230, 209, 200, 31, 219, 24, 23, 85, 111, 94, 218, 71, 170, 152, 212, 40, 87, 156]

def perm(bs):
  bs = list(bs)
  assert len(bs) == HBS
  m = [bs[P[i]] for i in range(len(bs))]
  ns = []
  for i in range(0, len(m), 4):
    ms = m[i:i+4]
    ns.append([reduce(xor, [mpy(ms[j], M[i][j]) for j in range(4)]) for i in range(4)])
  return reduce(lambda a,b: a+b, ns)

def x(a, b):
  return bytes([x ^ y for (x, y) in zip(a, b)])

def encrypt_block(key, block):
  assert len(block) == BLOCK_SZ
  assert len(key) == BLOCK_SZ
  a = sha256(key).digest()
  b = sha256(a).digest()
  c = sha256(b).digest()
  sks = [key[:HBS], key[HBS:], a[:HBS], a[HBS:], b[:HBS], b[HBS:], c[:HBS]]
  assert all(len(x) == HBS for x in sks)
  L, R = block[:16], block[16:]
  L, R = x(perm(S[b] for b in x(R, sks[0])), L), R
  L, R = L, x(perm(S[b] for b in x(L, sks[1])), R)
  L, R = x(perm(S[b] for b in x(R, sks[2])), L), R
  L, R = L, x(perm(S[b] for b in x(L, sks[3])), R)
  L, R = x(perm(S[b] for b in x(R, sks[4])), L), R
  L, R = L, x(perm(S[b] for b in x(L, sks[5])), R)
  L, R = x(perm(S[b] for b in x(R, sks[6])), L), R
  return bytes(L + R)

def g(h):
  return bytes(h + bytes([S[c] for c in h]))[:BLOCK_SZ]

def hash(start_key, data):
  padding_needed = (BLOCK_SZ - (len(data) % BLOCK_SZ))
  data = data + bytes(padding_needed * [padding_needed])
  blocks = [data[i:i+BLOCK_SZ] for i in range(0, len(data), BLOCK_SZ)]
  now = start_key
  for block in blocks:
    # eh 128 bits is enough
    now = x(encrypt_block(g(now), block), block)[-16:]
  return now

import ast

SAFE_FUNCTIONS = set(["print"])
OP_MAP = {
  ast.Add: lambda a,b: a + b,
  ast.Sub: lambda a,b: a - b,
  ast.Mult: lambda a,b: a * b,
}
def check_expression_safety(expr):
  if isinstance(expr, ast.Call):
    func = expr.func
    if func.id not in SAFE_FUNCTIONS:
      return False
    return all(
      check_expression_safety(arg) for arg in expr.args
    ) and (len(expr.keywords) == 0)
  elif isinstance(expr, ast.BinOp):
    if not any(isinstance(expr.op, typ) for typ in OP_MAP):
      return False
    return check_expression_safety(expr.left) and check_expression_safety(expr.right)
  elif isinstance(expr, ast.Constant):
    return isinstance(expr.value, int) or isinstance(expr.value, str)
  return False

def check_if_safe(cmd):
  try:
    mod = ast.parse(cmd)
    assert len(mod.body) == 1 and isinstance(mod.body[0], ast.Expr)
    return check_expression_safety(mod.body[0].value)
  except (SyntaxError, UnicodeDecodeError):
    # if it doesn't parse, it won't run
    return True

FUNC_MAP = {
  "print": print,
  "get_flag": lambda: FLAG
}
def eval_expr(expr):
  if isinstance(expr, ast.Call):
    func = expr.func
    args = [eval_expr(arg) for arg in expr.args]
    return FUNC_MAP[func.id](*args)
  elif isinstance(expr, ast.BinOp):
    return OP_MAP[type(expr.op)](eval_expr(expr.left), eval_expr(expr.right))
  elif isinstance(expr, ast.Constant):
    if isinstance(expr.value, int) or isinstance(expr.value, str):
      return expr.value
  raise Exception("Something has gone wrong!")

def evaluate_safe(cmd):
  try:
    mod = ast.parse(cmd)
    assert len(mod.body) == 1 and isinstance(mod.body[0], ast.Expr)
    return eval_expr(mod.body[0].value)
  except (SyntaxError, UnicodeDecodeError):
    # no parse, just fail
    print("There was a syntax error in your command - try a different one?")

if __name__ == "__main__":
  import os
  START_KEY = os.urandom(BLOCK_SZ)
  print("Hashing via key", hexlify(START_KEY))
  safe_hashes = set()
  for _ in range(10):
    print("Send a hex-encoded command: ", end="")
    command = unhexlify(input())
    hsh = hash(START_KEY, command)
    if hsh in safe_hashes or check_if_safe(command):
      safe_hashes.add(hsh)
      print("I think your command is safe!")
      result = evaluate_safe(command)
      if result is not None:
        print(result)
```
The hash function used in this challenge is a Merkle-Damgard construction where the one-way compression function is derived from a block cipher using a Matyas-Meyer-Oseas construction (hence MMO in the challenge name). The block cipher itself is a 7-round Feistel cipher with round function given by a substitution permutation network bearing some similarity to AES. 

Initial linear cryptanalysis of the S-box revealed no glaring weaknesses, so I
focused my attention away from the round function and more on the peculiar
combination of MMO and Feistel ciphers. After some searching, I came across
[this paper](https://iacr.org/archive/asiacrypt2007/48330316/48330316.pdf) by
Knudsen and Rijmen which detailed the construction of known-key distinguishers
on 7-round Feistel ciphers. The construction required the round function $f$ be
invertible (or satisfying other nice properties), and that the second and sixth
subkeys in the key schedule be not identical (which is easily satisfied in
practice). If these conditions are met, the construction computes two plaintexts denoted $p = (p_L, p_R)$ and 
$\tilde{p} = (\tilde{p_L}, \tilde{p_R})$ such that if $c = (c_L, c_R)$ and $\tilde{c} = (\tilde{c_L}, \tilde{c_R})$
are the corresponding (Feistel-cipher) ciphertexts, then we have 
\begin{equation*}
p_R \oplus c_R = \tilde{p_R} \oplus \tilde{c_R}.
\end{equation*} When applied to an MMO context, this gives us a collision attack on the lower-half of the hash output. Luckily, the hash function $H$ used in the challenge conveniently discards the upper-half of the hash output, so our partial collision attack becomes a full collision attack, with
\begin{align*}
H(K, p) &= p_R \oplus c_R\\
H(K, \tilde{p}) &= \tilde{p_R} \oplus \tilde{c_R}
\end{align*} as desired.

To implement this attack, we will first needed to invert the round function $f$ used in the Feistel cipher. Fortunately, the S-box and permutation components of the SPN were fairly simple to invert and the diffusion step in the `perm()` function greatly resembled the [MixColumns](https://en.wikipedia.org/wiki/Rijndael_MixColumns) operation in AES in that both consisted of matrix multiplication in a particular finite field of order $2^8$. Compare for example the `mpy()` function from the challenge code, and a C# implementation of multiplication in Rijindael's finite field.
```python
def mpy(x, y):
  assert 0 <= min(x, y) <= max(x, y) < 256
  p = 0
  for _ in range(8):
    if y & 1 != 0:
      p ^= x
    x <<= 1
    if x & 0x100 != 0:
      x ^= 0x11d
    y >>= 1
  return p
```
```csharp
private byte GMul(byte a, byte b) { 
    byte p = 0;

    for (int counter = 0; counter < 8; counter++) {
        if ((b & 1) != 0) {
            p ^= a;
        }

        bool hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
        }
        b >>= 1;
    }

    return p;
}
```
The only difference between the field multiplication used by the round function and Rijindael is the finite field modulus has been changed from $x^8 + x^4 + x^3 + x + 1$ to $x^8 + x^4 + x^3 + x^2 + 1$. Besides this, we can invert this step in much the same way as inverting AES.

With a collision attack in hand, we are now ready to complete the challenge by finding a hash collision between a "safe" expression and an "unsafe" expression containing a call to `get_flag()`. The key vulnerability in the server's expression handling lies in the following function.
```python
def check_if_safe(cmd):
  try:
    mod = ast.parse(cmd)
    assert len(mod.body) == 1 and isinstance(mod.body[0], ast.Expr)
    return check_expression_safety(mod.body[0].value)
  except (SyntaxError, UnicodeDecodeError):
    # if it doesn't parse, it won't run
    return True
```
If a `cmd` is passed which results in a `SyntaxError` or a `UnicodeDecodeError`, then the server will deem that command to be safe under the assumption that it won't be able to be run. This means that we can pass two commands of the form
- `p_hat + b"\nget_flag()`
- `p + b"\nget_flag()`,
where `p` and `p_hat` are obtained from the collision attack above. Hence both expressions will have the same hash value. 

Since we have little control over `p` and `p_hat`, there is a good chance that both of them will contain invalid Unicode characters. Hence, it is likely that an error will be raised when the server attempts to parse `p_hat + b"\nget_flag()`, causing it to mark the hash as "safe". 

Afterwards, we can pass the command `p + b"\nget_flag()` to the server. Since its hash is the same as the previous command, the server will continue to execute without checking again for safety. 

For most values of `p`, this will again result in an error, since it is unlikely that `p` consists of valid Unicode, let alone valid Python source code. However if the first character of `p` is the comment character `#`, then any syntax errors in `p` are ignored, and execution begins starting from the next physical line, causing `get_flag()` to be executed! 

The probability that the first character of `p` is a `#` is roughly 1 in 256, so we can brute force for such a `p` locally with little effort.
Below is an implementation in Python putting all the pieces together.
```python
#!/usr/bin/env sage
from functools import reduce
import pwn
from operator import xor
from hashlib import sha256
from binascii import hexlify, unhexlify
from sage.crypto.sbox import SBox
import os
import ast

###
### Cipher construction
###
BLOCK_SZ = 32
HBS = BLOCK_SZ // 2  # 16
assert HBS % 4 == 0


def mpy(x, y):  # multiplication in K
    assert 0 <= min(x, y) <= max(x, y) < 256
    p = 0
    for _ in range(8):
        if y & 1 != 0:
            p = p ^^ x
        x <<= 1
        if x & 0x100 != 0:
            x = x ^^ 0x11D
        y >>= 1
    return p


# fmt: off
M = [[0x04, 0x47, 0x8e, 0x01], [0x47, 0x04, 0x01, 0x8e], [0x8e, 0x01, 0x04, 0x47], [0x01, 0x8e, 0x47, 0x04]] # 4x4 matrix
P = [10, 11, 12, 2, 14, 6, 15, 13, 8, 7, 9, 5, 0, 1, 4, 3] # 16. a permutation vector
S = [6, 98, 179, 28, 64, 3, 110, 124, 194, 137, 105, 62, 19, 146, 82, 73, 199, 10, 33, 165, 151, 251, 97, 148, 101, 153, 252, 187, 103, 254, 5, 213, 100, 108, 142, 51, 68, 224, 16, 58, 183, 208, 55, 215, 128, 210, 107, 242, 80, 192, 36, 50, 157, 173, 45, 122, 106, 56, 104, 32, 195, 232, 132, 13, 155, 246, 35, 138, 66, 221, 2, 121, 227, 113, 203, 234, 228, 207, 196, 9, 225, 201, 184, 89, 248, 95, 129, 126, 8, 222, 49, 181, 154, 241, 217, 250, 0, 249, 38, 167, 57, 41, 59, 12, 185, 30, 39, 26, 7, 214, 238, 20, 198, 79, 166, 162, 159, 239, 193, 119, 189, 65, 54, 130, 1, 178, 93, 237, 133, 63, 223, 147, 92, 43, 163, 123, 141, 191, 168, 37, 15, 220, 211, 69, 244, 27, 86, 70, 240, 53, 160, 116, 144, 145, 11, 134, 21, 229, 233, 22, 17, 182, 109, 114, 206, 158, 131, 115, 52, 197, 175, 202, 186, 143, 180, 245, 169, 25, 88, 102, 236, 140, 226, 120, 125, 4, 235, 177, 164, 47, 171, 81, 118, 48, 61, 14, 172, 72, 18, 112, 91, 255, 76, 174, 205, 216, 75, 161, 243, 29, 99, 44, 46, 231, 42, 139, 136, 67, 83, 135, 204, 84, 247, 253, 60, 150, 77, 176, 190, 127, 96, 117, 34, 90, 188, 78, 74, 149, 230, 209, 200, 31, 219, 24, 23, 85, 111, 94, 218, 71, 170, 152, 212, 40, 87, 156] # 256
# fmt: on


def perm(bs):  # permutation, followed by matrix multiplication in GF(2^q)
    bs = list(bs)
    assert len(bs) == HBS
    m = [bs[P[i]] for i in range(len(bs))]
    ns = []
    for i in range(0, len(m), 4):
        ms = m[i : i + 4]
        ns.append([reduce(xor, [mpy(ms[j], M[i][j]) for j in range(4)]) for i in range(4)])
    return reduce(lambda a, b: a + b, ns)


def x(a, b):
    return bytes([x ^^ y for (x, y) in zip(a, b)])


def encrypt_block(key, block):
    assert len(block) == BLOCK_SZ
    assert len(key) == BLOCK_SZ
    a = sha256(key).digest()
    b = sha256(a).digest()
    c = sha256(b).digest()
    sks = [key[:HBS], key[HBS:], a[:HBS], a[HBS:], b[:HBS], b[HBS:], c[:HBS]]
    assert all(len(x) == HBS for x in sks)
    L, R = block[:16], block[16:]
    L, R = x(perm(S[b] for b in x(R, sks[0])), L), R
    L, R = L, x(perm(S[b] for b in x(L, sks[1])), R)
    L, R = x(perm(S[b] for b in x(R, sks[2])), L), R
    L, R = L, x(perm(S[b] for b in x(L, sks[3])), R)
    L, R = x(perm(S[b] for b in x(R, sks[4])), L), R
    L, R = L, x(perm(S[b] for b in x(L, sks[5])), R)
    L, R = x(perm(S[b] for b in x(R, sks[6])), L), R
    return bytes(L + R)


def decrypt_block(key, block):
    assert len(block) == BLOCK_SZ
    assert len(key) == BLOCK_SZ
    a = sha256(key).digest()
    b = sha256(a).digest()
    c = sha256(b).digest()
    sks = [key[:HBS], key[HBS:], a[:HBS], a[HBS:], b[:HBS], b[HBS:], c[:HBS]]

    L, R = block[:16], block[16:]
    L, R = x(perm(S[b] for b in x(R, sks[6])), L), R
    L, R = L, x(perm(S[b] for b in x(L, sks[5])), R)
    L, R = x(perm(S[b] for b in x(R, sks[4])), L), R
    L, R = L, x(perm(S[b] for b in x(L, sks[3])), R)
    L, R = x(perm(S[b] for b in x(R, sks[2])), L), R
    L, R = L, x(perm(S[b] for b in x(L, sks[1])), R)
    L, R = x(perm(S[b] for b in x(R, sks[0])), L), R
    return bytes(L + R)


###
### Hash construction
### Matyas Meyer Oseas
###
def g(h):
    return bytes(h + bytes([S[c] for c in h]))[:BLOCK_SZ]


def hash(start_key, data):
    padding_needed = BLOCK_SZ - (len(data) % BLOCK_SZ)
    data = data + bytes(padding_needed * [padding_needed])
    blocks = [data[i : i + BLOCK_SZ] for i in range(0, len(data), BLOCK_SZ)]
    now = start_key
    for block in blocks:
        # eh 128 bits is enough
        now = x(encrypt_block(g(now), block), block)[-16:]
    return now


###
### https://iacr.org/archive/asiacrypt2007/48330316/48330316.pdf
###
# First, find an inverse for the round function F

# Helpers for MixColumns round
F = GF(2)
Fu = PolynomialRing(F, "u")
u = Fu.gen()
K = GF(2 ^ 8, "u", modulus=1 + u ^ 2 + u ^ 3 + u ^ 4 + u ^ 8)
u = K.gen()

def to_poly(byte):
    binary_repr = format(byte, "08b")[::-1] # little endian
    return K(sum(int(b) * u**k for k, b in enumerate(binary_repr)))

def from_poly(ele):
    return ele.to_integer()

M_algebraic = matrix(K, [list(map(to_poly, M_)) for M_ in M])

def to_matrix(half_block, algebraic = False, column_major = False):
    assert len(half_block) == HBS
    m = [half_block[i:i+4] for i in range(0, len(half_block), 4)]

    if algebraic:
        m = matrix(K, [list(map(to_poly, M_)) for M_ in m])
    else:
        m = matrix(ZZ, m)

    if column_major:
        m = m.transpose()

    return m

def from_matrix(mat, algebraic = False, column_major = False):
    if column_major:
        mat = mat.transpose()

    block = list(reduce(lambda a, b: list(a) + list(b), mat.rows()))
    if algebraic:
        block = [from_poly(p) for p in block]
    return block

# Helpers for substitution round
sbox = SBox(S)
sbox_inv = sbox.inverse()

# Helpers for permutation round
P_inv = [12, 13, 3, 15, 14, 11, 5, 9, 8, 10, 0, 1, 2, 7, 4, 6]

def f(half_block):
    assert len(half_block) == HBS

    # Substitution round
    half_block = [sbox(b) for b in half_block]

    # Permutation round
    half_block = [half_block[P[i]] for i in range(len(half_block))]

    # Mix columns round
    m = to_matrix(half_block, algebraic=True, column_major=True)
    m = M_algebraic * m
    half_block = from_matrix(m, algebraic=True, column_major=True)

    return half_block

def f_inverse(half_block):
    # Invert mix_columns round
    m = to_matrix(half_block, algebraic=True, column_major=True)
    m = M_algebraic.inverse() * m
    half_block = from_matrix(m, algebraic=True, column_major=True)

    # Invert permutation round
    half_block = [half_block[P_inv[i]] for i in range(len(half_block))]

    # Invert substitution round
    half_block = [sbox_inv(b) for b in half_block]

    return half_block

# Now to implement the distinguisher algorithm
def key_schedule(key):
    assert len(key) == BLOCK_SZ
    a = sha256(key).digest()
    b = sha256(a).digest()
    c = sha256(b).digest()
    sks = [key[:HBS], key[HBS:], a[:HBS], a[HBS:], b[:HBS], b[HBS:], c[:HBS]]
    return sks

def knudsen_rijmen_distinguisher(round_func, round_func_inv, key, x_ = None):
    subkeys = key_schedule(key)
    if not x_:
        x_ = os.urandom(HBS)

    gamma = x(subkeys[1], subkeys[5])
    alpha = x(x_, round_func_inv(x(round_func(x_), gamma)))
    z = round_func_inv(x(x(subkeys[2], subkeys[4]), alpha))

    p_R = reduce(x, [x_, subkeys[2], round_func(reduce(x, [z, round_func(x_), subkeys[3], subkeys[1]]))])
    p_L = reduce(x, [z, round_func(x_), subkeys[3], round_func(x(p_R, subkeys[0]))])

    p_hat_R = reduce(x, [x_, alpha, subkeys[2], round_func(reduce(x, [z, round_func(x_), subkeys[5], subkeys[3]]))])
    p_hat_L = reduce(x, [z, round_func(x_), gamma, subkeys[3], round_func(x(p_hat_R, subkeys[0]))])

    p = p_L + p_R
    p_hat = p_hat_L + p_hat_R

    c_R = encrypt_block(key, p)[-16:]
    c_hat_R = encrypt_block(key, p_hat)[-16:]

    assert reduce(x, [c_R, c_hat_R, p_R, p_hat_R]) == b"\x00" * HBS

    return p, p_hat

###
### AST parsing
###
SAFE_FUNCTIONS = set(["print"])
OP_MAP = {
  ast.Add: lambda a,b: a + b,
  ast.Sub: lambda a,b: a - b,
  ast.Mult: lambda a,b: a * b,
}
def check_expression_safety(expr):
  if isinstance(expr, ast.Call):
    func = expr.func
    if func.id not in SAFE_FUNCTIONS:
      return False
    return all(
      check_expression_safety(arg) for arg in expr.args
    ) and (len(expr.keywords) == 0)
  elif isinstance(expr, ast.BinOp):
    if not any(isinstance(expr.op, typ) for typ in OP_MAP):
      return False
    return check_expression_safety(expr.left) and check_expression_safety(expr.right)
  elif isinstance(expr, ast.Constant):
    return isinstance(expr.value, int) or isinstance(expr.value, str)
  return False

def check_if_safe(cmd):
  try:
    mod = ast.parse(cmd)
    assert len(mod.body) == 1 and isinstance(mod.body[0], ast.Expr)
    return check_expression_safety(mod.body[0].value)
  except (SyntaxError, UnicodeDecodeError):
    # if it doesn't parse, it won't run
    return True

FUNC_MAP = {
  "print": print,
  "get_flag": lambda: FLAG
}
def eval_expr(expr):
  if isinstance(expr, ast.Call):
    func = expr.func
    args = [eval_expr(arg) for arg in expr.args]
    return FUNC_MAP[func.id](*args)
  elif isinstance(expr, ast.BinOp):
    return OP_MAP[type(expr.op)](eval_expr(expr.left), eval_expr(expr.right))
  elif isinstance(expr, ast.Constant):
    if isinstance(expr.value, int) or isinstance(expr.value, str):
      return expr.value
  raise Exception("Something has gone wrong!")

def evaluate_safe(cmd):
  try:
    mod = ast.parse(cmd)
    assert len(mod.body) == 1 and isinstance(mod.body[0], ast.Expr)
    return eval_expr(mod.body[0].value)
  except (SyntaxError, UnicodeDecodeError):
    # no parse, just fail
    print("There was a syntax error in your command - try a different one?")

def find_exploit_pair(key):
    while True:
        p, p_hat = knudsen_rijmen_distinguisher(f, f_inverse, key)
        try:
            ast.parse(p)
            p_valid = True
        except:
            p_valid = False
        try:
            ast.parse(p_hat)
            p_hat_valid = True
        except:
            p_hat_valid = False
        if p_valid ^^ p_hat_valid:
            if p_valid:
                assert p[:1] == b"#"
                return p, p_hat
            else:
                assert p_hat_valid
                return p_hat, p

pwn.context.log_level = "debug"
def solve():
    conn = pwn.connect("mmorpg.chal.pwni.ng", 1337)
    # conn = pwn.process(["python", "mmorpg.py"])

    conn.recvuntil(b"Hashing via key")
    start_key = unhexlify(conn.recvline().decode().strip().strip("'").strip("b'"))

    p, p_hat = find_exploit_pair(start_key)

    safe = p_hat + b"\nget_flag()"
    unsafe = p + b"\nget_flag()"

    assert hash(start_key, safe) == hash(start_key, unsafe)
    conn.sendline(safe.hex().encode("utf-8"))
    conn.sendline(unsafe.hex().encode("utf-8"))
    conn.interactive()

```
### Flag
```plaintext
PCTF{n1c3_w0rk_th4ts_a_sp0oky_h45h_coll1der_e66351ecdc2a593278174541ad513125}
```


