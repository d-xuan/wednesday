# 0xL4ughCTF 2024
Thank you to team 0xL4ugh for hosting this event!

\toc

## gcd rsa

This challenge is a small twist on one of the math puzzles at [Cryptohack](Cryptohack). 
```python
import math
from Crypto.Util.number import *
from secret import flag,p,q
from gmpy2 import next_prime
m = bytes_to_long(flag.encode())
n=p*q


power1=getPrime(128)
power2=getPrime(128)
out1=pow((p+5*q),power1,n)
out2=pow((2*p-3*q),power2,n)
eq1 = next_prime(out1)

c = pow(m,eq1,n)


with open('chall2.txt', 'w') as f:
    f.write(f"power1={power1}\npower2={power2}\neq1={eq1}\nout2={out2}\nc={c}\nn={n}")
```
We are given equations of the form
\begin{align*}
c_1 &= (p + 5q)^{e_1} \pmod n\\
c_2 &= (2p - 3q)^{e_2} \pmod n
\end{align*}
Our goal is to factorise $n$ so we can decrypt the flag using RSA.
Put
\begin{align*}
q_1 &= c_1^{e_2} = p^{e_1e_2}\pmod q\\
q_2 &= c_2^{e_2} = (2p)^{e_1e_2} \pmod q.
\end{align*}
Then we have
\begin{equation*}
2^{e_1e_2}q_1 - q_2 = 0 \pmod q 
\end{equation*} 
and so $q$ divides $D = 2^{e_1e_2}q_1 - q_2$. Then $q = \mathrm{gcd}(n, D)$ and $p = n / q$.

The only thing stopping us now is that we were given the next prime after $c_1$
instead of $c_1$ itself. Luckily there are only 2000 or so integers between that
prime and the previous prime, so we can brute force values of $c_1$ in that
range until we come across a factorisation.

### Implementation
```python
#!/usr/bin/env sage
from Crypto.Util.number import long_to_bytes

power1 = 281633240040397659252345654576211057861
power2 = 176308336928924352184372543940536917109
eq1 = 2215046782468309450936082777612424211412337114444319825829990136530150023421973276679233466961721799435832008176351257758211795258104410574651506816371525399470106295329892650116954910145110061394115128594706653901546850341101164907898346828022518433436756708015867100484886064022613201281974922516001003812543875124931017296069171534425347946706516721158931976668856772032986107756096884279339277577522744896393586820406756687660577611656150151320563864609280700993052969723348256651525099282363827609407754245152456057637748180188320357373038585979521690892103252278817084504770389439547939576161027195745675950581
out2 = 224716457567805571457452109314840584938194777933567695025383598737742953385932774494061722186466488058963292298731548262946252467708201178039920036687466838646578780171659412046424661511424885847858605733166167243266967519888832320006319574592040964724166606818031851868781293898640006645588451478651078888573257764059329308290191330600751437003945959195015039080555651110109402824088914942521092411739845889504681057496784722485112900862556479793984461508688747584333779913379205326096741063817431486115062002833764884691478125957020515087151797715139500054071639511693796733701302441791646733348130465995741750305
c = 11590329449898382355259097288126297723330518724423158499663195432429148659629360772046004567610391586374248766268949395442626129829280485822846914892742999919200424494797999357420039284200041554727864577173539470903740570358887403929574729181050580051531054419822604967970652657582680503568450858145445133903843997167785099694035636639751563864456765279184903793606195210085887908261552418052046078949269345060242959548584449958223195825915868527413527818920779142424249900048576415289642381588131825356703220549540141172856377628272697983038659289548768939062762166728868090528927622873912001462022092096509127650036
n = 14478207897963700838626231927254146456438092099321018357600633229947985294943471593095346392445363289100367665921624202726871181236619222731528254291046753377214521099844204178495251951493800962582981218384073953742392905995080971992691440003270383672514914405392107063745075388073134658615835329573872949946915357348899005066190003231102036536377065461296855755685790186655198033248021908662540544378202344400991059576331593290430353385561730605371820149402732270319368867098328023646016284500105286746932167888156663308664771634423721001257809156324013490651392177956201509967182496047787358208600006325742127976151

out1_lower_bound = previous_prime(eq1)

curr = out1_lower_bound
while curr <= eq1:
    out1 = curr
    q1 = pow(out1, power2, n)
    q2 = pow(out2, power1, n)

    d = pow(2, power1 * power2, n) * q1 - q2

    q = gcd(d, n)
    if q != 1:
        p = n // q
        if p * q == n:
            break
    curr += 1

lam = LCM(p - 1, q - 1)
d_exp = inverse_mod(eq1, lam)
m = pow(c, d_exp, n)
print(long_to_bytes(m))
```
### Flag
```plaintext
0xL4ugh{you_know_how_factor_N!}
```

## poison

We are presented with an elliptic curve $E/k$ and four sequences of points on it
derived from the bits of the flag.

```python
from random import *
from Crypto.Util.number import *

flag = b"REDACTED"

# DEFINITION
K = GF(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF)
a = K(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC)
b = K(0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1)
E = EllipticCurve(K, (a, b))
G = E(0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012, 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811)


# DAMAGE
def poison(val, index):
    val = list(val)
    if val[index] == "1":
        val[index] = "0"
    else:
        val[index] = "1"
    return "".join(val)


my_priv = bin(bytes_to_long(flag))[2:]
ms = []
C1s = []
C2s = []
decs = []

count = 0

while count < len(my_priv):
    try:
        k = randint(2, G.order() - 2)
        Q = int(my_priv, 2) * G
        M = randint(2, G.order() - 2)
        M = E.lift_x(Integer(M))
        ms.append((M[0], M[1]))

        C1 = k * G
        C1s.append((C1[0], C1[1]))
        C2 = M + k * Q
        C2s.append((C2[0], C2[1]))

        ind = len(my_priv) - 1 - count
        new_priv = poison(my_priv, ind)
        new_priv = int(new_priv, 2)
        dec = C2 - (new_priv) * C1
        decs.append((dec[0], dec[1]))
        count += 1
    except:
        pass

with open("out.txt", "w") as f:
    f.write(f"ms={ms}\n")
    f.write(f"C1s={C1s}\n")
    f.write(f"C2s={C2s}\n")
    f.write(f"decs={decs}")

```

Writing out the relations for each sequence, we have for $ 0 \leq i < \mathrm{nbits}(\mathrm{flag})$
<!-- todo; need to write poison function better -->
\begin{align*}
m_i &= \text{random point in } E(k)\\
k_i &= \text{random scalar in } k\\
c_i^{1} &= k_i \times G\\
c_i^{2} &= m_i + k_i \times Q = m_i + k_i \times \mathrm{flag}_i \times G\\ 
d_i &= c_i^{2} - \mathrm{flag}_{i+1} \times c_i^1, 
\end{align*}
where $\mathrm{flag}_i$ is the value of the flag with the last $i-1$ bits flipped. We observe that
\begin{align*}
d_i &= c_i^{2} - \mathrm{flag}_{i+1} \times c_i^1 \\
&= m_i + k_i \times \mathrm{flag}_i \times G - \mathrm{flag}_{i+1} \times k_i \times G\\
&= m_i + (\mathrm{flag}_i - \mathrm{flag_{i+1}}) \times k_i \times G.
\end{align*}

Since $\mathrm{flag}_i$ and $\mathrm{flag_{i+1}}$ differ only in their $i$-th bit, we have
\begin{equation*}
\mathrm{flag}_i - \mathrm{flag_{i+1}} = \pm 2^{i}
\end{equation*} 
or more specifically
\begin{equation*}
\mathrm{flag}_i - \mathrm{flag_{i+1}} = 
\begin{cases}
2^{i}, &i\text{-th bit of flag is 1}\\
-2^{i},&i\text{-th bit of flag is 0},
\end{cases}
\end{equation*}

Since there are only two cases, we can test both options to see which value of
$d_i$ we have, and from there we can deduce the flag.

### Implementation
```python
#!/usr/bin/env sage
from Crypto.Util.number import long_to_bytes


# ----- large challenge output elided  ------ #


# Curve parameters
K = GF(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF)
a = K(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC)
b = K(0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1)
E = EllipticCurve(K, (a, b))
G = E(0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012, 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811)

# Solution
bit_index = 0  # counting from the last bit
bits = []
while bit_index < len(decs):
    dec = E(decs[bit_index])
    C1 = E(C1s[bit_index])
    C2 = E(C2s[bit_index])
    M = E(ms[bit_index])

    hi = M + pow(2, bit_index) * C1
    lo = M - pow(2, bit_index) * C1

    if hi == dec:
        bits.append("1")
    elif lo == dec:
        bits.append("0")
    else:
        print("Assumption broken: bit_index = ", bit_index)
        break

    bit_index += 1

print(long_to_bytes(int("".join(bits[::-1]), 2)))
```
### Flag
```plaintext
0xL4ugh{f4u1ty_3CC_EG_CR4CK3r!!!}
```

[Cryptohack]: (https://cryptohack.org/)



