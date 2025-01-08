# 0CTF 2024 - ZKPQC1

Big thank you to [Team 0ops](https://0ops.sjtu.cn/) for hosting this event and writing these great challenges!

During the competition I spent around 14 hours on this challenge, split between
12 hours on the first day, and 2 hours on the second. 
Ultimately, the solution hinged on a neat bit of isogeny trivia which I found quite interesting.

@def maxtoclevel=2
\toc


## ZKPQC1
This challenge takes place over the following SIDH parameters
\begin{align*}
a &= 49\\
b &= 36\\
p &= 2^a \cdot 3^b - 1 \\
\mathbb{F}_{p^2} &= \frac{\mathbb{F}_{p}}{(x^2 + 1)} = \mathbb{F}_p[i]. 
\end{align*} 
The starting curve is $E_0: y^2 = x^3 + 6x^2 + x$. 

```python
import signal
from hashlib import sha256
from Crypto.Util.number import bytes_to_long
from secret import FLAG

def _handle_timeout(signum, frame):
    raise TimeoutError('function timeout')

FAKE_NUM = 3

# Base field
a = 49
b = 36
p = 2**a * 3**b - 1


def get_canonical_basis(E, l, e):
    assert (p+1) % l^e == 0
    P = E(0)
    while (l^(e-1))*P == 0:
        P = ((p+1) // l^e) * E.random_point()
    Q = P
    while P.weil_pairing(Q, l^e)^(l^(e-1)) == 1:
        Q = ((p+1) // l^e) * E.random_point()
    return P, Q

def gen_torsion_points(E):
    Pa, Qa = get_canonical_basis(E, 2, a)
    Pb, Qb = get_canonical_basis(E, 3, b)
    return Pa, Qa, Pb, Qb


def hash_function(J):
    return (bytes_to_long(sha256(str(J[0]).encode()).digest()) // 2 * 2 + 1)  % 2^a, \
        (bytes_to_long(sha256(str(J[1]).encode()).digest()) // 2 * 2 + 1) % 2^a


def get_Fp2(i):
    return int(input()) + int(input())*i


def get_ECC_and_points():
    Ea4 = get_Fp2(i)
    Ea6 = get_Fp2(i)
    Ea = EllipticCurve(Fp2, [0, 6, 0, Ea4, Ea6])
    P = Ea(get_Fp2(i), get_Fp2(i))
    Q = Ea(get_Fp2(i), get_Fp2(i))
    return Ea, P, Q


class ZKP:

    def __init__(self, E, kernel):
        self.P0, self.Q0 = get_canonical_basis(E, 3, b)
        self.E0 = E
        self.chall_lst = []
        self.CHALL_NUM = 16
        self.kernel = kernel
        self.ker_phi = self.E0.isogeny(self.kernel, algorithm="factored")
        print(f"{self.P0 = }")
        print(f"{self.Q0 = }")


    def _commit(self):
        print("Give me E2:")
        E2a4 = get_Fp2(i)
        E2a6 = get_Fp2(i)
        self.E2 = EllipticCurve(Fp2, [0, 6, 0, E2a4, E2a6])

        self.P2, self.Q2 = get_canonical_basis(self.E2, 3, b)
        print(f"{self.P2 = }")
        print(f"{self.Q2 = }")

        self.E3, self.P3, self.Q3 = get_ECC_and_points()
        assert self.E3.is_supersingular()


    def _challenge(self, c=None):
        if c is None:
            self.chall = randint(0,1)
        else:
            self.chall = c
        print(f"chall = {self.chall}")


    def _verify(self):
        print("Your response:")

        if self.chall:
            Kphi_ = self.E2(get_Fp2(i), get_Fp2(i))
            assert 2^a * self.E2(Kphi_) == self.E2(0)
            phi_ = self.E2.isogeny(Kphi_, algorithm="factored")
            assert self.E3.j_invariant() == phi_.codomain().j_invariant()
            assert phi_(self.P2) == self.P3 and phi_(self.Q2) == self.Q3
        else:
            resp = input()
            sigma, delta = [int(_) for _ in resp.split(",")]
            Kbar_psi = sigma * self.P2 + delta * self.Q2
            Kbar_psi_ = sigma * self.P3 + delta * self.Q3
            assert 3^b * Kbar_psi == self.E2(0) and 3^b * Kbar_psi_ == self.E3(0)
            E0_ = self.E2.isogeny(Kbar_psi, algorithm="factored").codomain()
            E1_ = self.E3.isogeny(Kbar_psi_, algorithm="factored").codomain()
            assert E0.j_invariant() == E0_.j_invariant() and EA.j_invariant() == E1_.j_invariant()
            assert self.ker_phi.codomain().j_invariant() == E1_.j_invariant()
        return True


    def run(self):
        self.chall_lst = [randint(0,1) for _ in range(self.CHALL_NUM)]
        while sum(self.chall_lst) == 0 or sum(self.chall_lst) == self.CHALL_NUM:
            self.chall_lst = [randint(0, 1) for _ in range(self.CHALL_NUM)]

        for _ in range(self.CHALL_NUM):
            print(f"Now, for the {_} round of PoK:")
            self._commit()
            self._challenge(self.chall_lst[_])
            if not self._verify():
                return False
        return True

timeout = 90
signal.signal(signal.SIGALRM, _handle_timeout)
signal.alarm(timeout)

Fpx = PolynomialRing(GF(p), "x")
x = Fpx.gen()
Fp2.<i> = GF(p**2, modulus=[1,0,1])

E0 = EllipticCurve(Fp2, [0, 6, 0, 1, 0])
E0.set_order((p+1)**2)

Pa,Qa,Pb,Qb = gen_torsion_points(E0)
print(f"Pa = {Pa}")
print(f"Qa = {Qa}")
print(f"Pb = {Pb}")
print(f"Qb = {Qb}")

Ea, phiPb, phiQb = get_ECC_and_points()
assert Ea.is_supersingular()

Sb = randint(0, 3^b-1)
Tb = randint(0, 3^b-1)
R = Sb * Pb + Tb * Qb
psi = E0.isogeny(R, algorithm="factored")
Eb, psiPa, psiQa = psi.codomain(), psi(Pa), psi(Qa)
print(f"{Eb}")
print(f"psiPa = {psiPa}")
print(f"psiQa = {psiQa}")


J = Ea.isogeny(Sb * phiPb + Tb * phiQb, algorithm="factored").codomain().j_invariant()
Sa, Ta = hash_function(J)
EA = E0.isogeny(Sa * Pa + Ta * Qa, algorithm="factored").codomain()

s = set()
for _ in range(FAKE_NUM):
    print("Give me your share: ")

    kernel = E0(get_Fp2(i), get_Fp2(i))
    assert 2^a * kernel == E0(0) and 2^(a-2) * kernel != E0(0)
    zkp = ZKP(E0, kernel)

    if all(kernel.weil_pairing(PP, 2^a) != 1 for PP in s) and zkp.run():
        print("Good Job!")
        s.add(kernel)
    else:
        print("Out, you are cheating!")
        break

if len(s) == FAKE_NUM:
    print("You are a master of isogeny and ZKP.")
    print(FLAG)
```
In the first part of the challenge, we are asked to perform a SIDH key
exchange with the server in order to derive a shared $j$-invariant $J$. 
Since we don't care about the secrecy of this exchange, we can perform this exchange somewhat half-heartedly as long as we arrive at the same $j$-invariant as the server. So for our "secret" isogeny, we will choose $\varphi = \mathrm{id}$ and send the parameters 
\begin{equation*}
E_a = E_0, \;\varphi(P_b) = P_b, \;\varphi(Q_b) = Q_b. 
\end{equation*}

The server will then derive the shared curve
\begin{equation*}
\frac{E_a}{\langle [s_b]\varphi(P_b) + [t_b]\varphi(Q_b) \rangle} = \frac{E_0}{\langle [s_b]P_b + [t_b]Q_b \rangle} = E_b,
\end{equation*} which is known to us, and from there we can derived the shared $j$-invariant as $J = j(E_b)$.

Since we know the $j$-invariant $J$, then we also know the secret scalars $s_a,
t_a$ and from that the $2^a$-isogeny $\Phi: E_0 \longrightarrow E_A \cong E_0/\langle [s_a]P_a +
[t_a]Q_a \rangle$.

After the key exchange, the server will then ask us to prove knowledge of $\Phi$
three times, using the [SIDH-sign proof of
knowledge](https://eprint.iacr.org/2022/475.pdf). 
Since we already know $\Phi$ this is not too difficult, as we can just follow the protocol as an honest
prover. Moreover since we don't care about the zero-knowledge
component of the proof (the server already knows our isogeny), we can choose
$E_2 = E_0$, $E_3 = E_A$ as our commitment to greatly simplify the proof. 

Completing the proof three times will give us a flag, so the only problem remaining is a set of two checks we must pass prior to the ZKP starting.
```python

s = set()
for _ in range(FAKE_NUM): print("Give me your share: ")
    kernel = E0(get_Fp2(i), get_Fp2(i))
    assert 2^a * kernel == E0(0) and 2^(a-2) * kernel != E0(0)
    zkp = ZKP(E0, kernel)

    if all(kernel.weil_pairing(PP, 2^a) != 1 for PP in s) and zkp.run():
        print("Good Job!")
        s.add(kernel)
    else:
        print("Out, you are cheating!")
        break

```
At the beginning of each ZKP iteration, we are asked to supply a kernel
point which will generate an isogeny from $E_0$ to $E_A$. The checks above require us to submit three distinct kernel points. Moreover the condition
```python
    if all(kernel.weil_pairing(PP, 2^a) != 1 for PP in s) and zkp.run():
      ...
```
requires that the three kernel points be linearly independent.
This means that we must find three distinct paths through the
2-isogeny graph from $E_0$ to $E_A$.

In general, this problem is quite hard, and for the references in the literature which
I could find, the methods essentially boiled down to a [brute force search through the isogeny graph](https://eprint.iacr.org/2021/1051.pdf).

Luckily, our initial curve $E_0$ is an easy special case of this problem as
it is adjacent to the curve $E: y^2 = x^3 + x$ of $j$-invariant $1728$. The curve $E$
is special as its only 2-isogenous neighbours are $E_0$ and $E$ itself,
whereas other curves usually have three 2-isogenous neighbours generated by the
linear combinations $P, Q$ and $P + Q$ of a 2-torsion basis $(P,
Q)$ respectively.

@@small_image
@@invert_image
![Diagram](/assets/0CTF2024/cd.svg)
@@
@@

Using the notations in the above diagram, this means that any isogeny from $E_0$ to $E_A$ which factors through $E$ must necessarily return to $E_0$ via one of either $\varphi_1$ or $\varphi_2$ before continuing onto $E_A$. For
example, a possible sequence starting from $E_0$ could be
\begin{equation*}
\hat{\varphi_1} \rightarrow \varphi_3 \rightarrow \varphi_2 \rightarrow \phi_1 \rightarrow \ldots
\end{equation*} 
From this sequence, we can obtain two other distinct isogenies from $E_0$ to $E_A$ by altering the return isogeny from $E$ to $E_0$, or by cutting out the traversal to $E$ entirely.
\begin{align*}
\hat{\varphi_1} \rightarrow \varphi_3 &\rightarrow \varphi_2 \rightarrow \phi_1 \rightarrow \ldots\\
\hat{\varphi_1} \rightarrow \varphi_3 &\rightarrow \varphi_1 \rightarrow \phi_1 \rightarrow \ldots\\
&\phi_1 \rightarrow \ldots\\
\end{align*} 
Note that cutting out the traversal to $E$ reduces the degree of the isogeny by 2 to the power of the number of isogenes we truncated. This is important as we must ensure our isogeny's degree remains above $2^{a-2}$ in order 
to pass the check
```python
kernel = E0(get_Fp2(i), get_Fp2(i))
assert 2^a * kernel == E0(0) and 2^(a-2) * kernel != E0(0)
```
Since $\Phi$ has degree $2^a$, then in any truncation that we do, we must ensure we do not remove more than 2 isogenies from the path. In practice, this means that we can only perform the truncation if our initial isogeny does not pass through the automorphism $\varphi_3: E \rightarrow E$ in the diagram above. 

Luckily, the favourable situation is still quite common, as we have a $1/3$
chance for $\Phi$ to pass through $E$, and a $2/3$ chance for $\Phi$ not to
traverse through $\varphi_3$. Since every time we connect to the server we get a
new isogeny, this gives us a small bruteforce on the remote which
succeeds with probability $2/9$.

## Solve script
Below is an implementation of the solve in SageMath
```python
#!/usr/bin/env python3

from pwn import *

context.log_level = "debug"

from hashlib import sha256
from Crypto.Util.number import bytes_to_long
import itertools

FAKE_NUM = 3


# Base field
a = 49
b = 36
p = 2**a * 3**b - 1


def get_canonical_basis(E, l, e):
    assert (p + 1) % l ^ e == 0
    P = E(0)
    while (l ^ (e - 1)) * P == 0:
        P = ((p + 1) // l ^ e) * E.random_point()
    Q = P
    while P.weil_pairing(Q, l ^ e) ^ (l ^ (e - 1)) == 1:
        Q = ((p + 1) // l ^ e) * E.random_point()
    return P, Q


def gen_torsion_points(E):
    Pa, Qa = get_canonical_basis(E, 2, a)
    Pb, Qb = get_canonical_basis(E, 3, b)
    return Pa, Qa, Pb, Qb


def hash_function(J):
    return (bytes_to_long(sha256(str(J[0]).encode()).digest()) // 2 * 2 + 1) % 2 ^ a, (
        bytes_to_long(sha256(str(J[1]).encode()).digest()) // 2 * 2 + 1
    ) % 2 ^ a


Fp2 = GF(p**2, "i", modulus=[1, 0, 1])
i = Fp2.gen(0)

E0 = EllipticCurve(Fp2, [0, 6, 0, 1, 0])
E0.set_order((p + 1) ** 2)


def send_Fp2(conn, x):
    conn.sendline(str(x[0]).encode())
    conn.sendline(str(x[1]).encode())


def send_ECC_and_points(conn, E0, P, Q):
    send_Fp2(conn, Fp2(E0.a4()))
    send_Fp2(conn, Fp2(E0.a6()))

    # P
    send_Fp2(conn, Fp2(P.x()))
    send_Fp2(conn, Fp2(P.y()))

    # Q
    send_Fp2(conn, Fp2(Q.x()))
    send_Fp2(conn, Fp2(Q.y()))


def parse_ec(line):
    nums = re.findall(r"[0-9]+", line)
    E = EllipticCurve(
        Fp2,
        [0, int(nums[2]), 0, int(nums[4]) * i + int(nums[5]), int(nums[6]) * i + int(nums[7])],
    )
    return E


def parse_point(ec, line):
    lines = line.split("=")[-1].replace("(", "").replace(")", "").split(":")
    lines = [line for line in lines if line.strip()]

    return ec(*list(map(eval, lines)))


def eval_point(curve_name, line):
    exec(line.replace(":", ",").replace("(", f"{curve_name}("))


def compose_all(factors):
    curr = factors[0]
    for factor in factors[1:]:
        curr = factor * curr
    return curr


def find_other_edge(factor):
    return replacement


def generate_associates(phi):
    factors = list(phi.factors())
    for j, factor in enumerate(factors):
        source, dest = factor.domain(), factor.codomain()

        if source.j_invariant() == 1728 and dest.j_invariant() == E0.j_invariant():
            yield compose_all([E0.isomorphism_to(dest)] + factors[j + 1 :])
            for forwardedge in source.isogenies_degree(2):
                if forwardedge.codomain().is_isomorphic(dest):
                    yield compose_all(factors[:j] + [forwardedge, forwardedge.codomain().isomorphism_to(dest)] + factors[j + 1 :])

        if source.j_invariant() == 1728 and dest.j_invariant() == 1728:
            yield compose_all(
                factors[:j] + [factors[j - 1].codomain().isomorphism_to(factors[j + 1].domain())] + factors[j + 1 :]
            )


def solve():
    # conn = process(["sage", "task.sage"])
    conn = connect("instance.penguin.0ops.sjtu.cn", 18432)

    # Get SIDH Parameters
    Pa = parse_point(E0, conn.recvline().decode())
    Qa = parse_point(E0, conn.recvline().decode())
    Pb = parse_point(E0, conn.recvline().decode())
    Qb = parse_point(E0, conn.recvline().decode())

    send_ECC_and_points(conn, E0, Pb, Qb)
    Eb = parse_ec(conn.recvline().decode())

    psiPa = parse_point(Eb, conn.recvline().decode())
    psiQa = parse_point(Eb, conn.recvline().decode())
    J = Eb.j_invariant()
    Sa, Ta = hash_function(J)

    phi_A = E0.isogeny(Sa * Pa + Ta * Qa, algorithm="factored")
    EA = phi_A.codomain()
    associates = list(generate_associates(phi_A))
    if not associates:
        conn.close()
        return

    kernels = set()

    for ass in associates:
        l, e = factor(ass.degree())[0]
        P, Q = get_canonical_basis(ass.domain(), l, e)
        try:
            kernels.add(P + -ass(P).log(ass(Q)) * Q)
        except ValueError:
            pass
        try:
            kernels.add(Q + -ass(Q).log(ass(P)) * P)
        except ValueError:
            pass

    # Remove any invalid associates we overgenerated
    to_remove = set()
    for kernel in kernels:
        if E0.isogeny(kernel, algorithm="factored").codomain().j_invariant() != EA.j_invariant():
            to_remove.add(kernel)
        if 2 ^ (a - 2) * kernel == E0(0):
            to_remove.add(kernel)
    kernels = kernels - to_remove

    # Find a linearly independent subset
    final = set()
    for perm in itertools.combinations(kernels, r=3):
        s = set()
        for kernel in perm:
            if all(kernel.weil_pairing(PP, 2 ^ a) != 1 for PP in s):
                s.add(kernel)
            else:
                break
        if len(s) > len(final):
            final = s

    if len(final) < 3:
        conn.close()
        return

    # Now we have a set of 3 linearly independent kernels, and can complete the proof.
    for kernel in final:
        # Send kernel
        send_Fp2(conn, Fp2(kernel.x()))
        send_Fp2(conn, Fp2(kernel.y()))
        P0 = parse_point(E0, conn.recvline_startswith(b"self.P0").decode())
        Q0 = parse_point(E0, conn.recvline_startswith(b"self.Q0").decode())

        for _ in range(16):
            # commit
            # E2
            conn.recvuntil(b"Give me E2:")
            send_Fp2(conn, Fp2(E0.a4()))
            send_Fp2(conn, Fp2(E0.a6()))
            P2 = parse_point(E0, conn.recvline_startswith(b"self.P2").decode())
            Q2 = parse_point(E0, conn.recvline_startswith(b"self.Q2").decode())

            # EA
            send_ECC_and_points(conn, EA, phi_A(P2), phi_A(Q2))

            # Chall
            chall = int(conn.recvline_startswith(b"chall = ").split(b"=")[-1].decode())
            if chall:
                # Reveal kernel
                orig_kernel = Sa * Pa + Ta * Qa
                send_Fp2(conn, Fp2(orig_kernel.x()))
                send_Fp2(conn, Fp2(orig_kernel.y()))
            else:
                # Send identity isogenies
                conn.sendline(f"{3^b},{3^b}".encode())
    print(conn.recvall())
    return True


def main():
    for _ in range(100):
        solved = solve()
        if solved:
            break
```

## Flag
```text
0ops{https://eprint.iacr.org/2022/475.pdf_1s_ju5t_a_proof_0f_know1edge.>.<.././././}
```

