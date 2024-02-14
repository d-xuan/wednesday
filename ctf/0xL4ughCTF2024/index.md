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
M_i &= \text{random point in } E(k)\\
k_i &= \text{random scalar in } k\\
C_{1, i} &= \left[k_i\right]G\\
C_{2, i} &= M_i + \left[k_i\right]Q = M_i + \left[k_i \cdot \mathrm{flag}_i\right]G\\ 
D_i &= C_{2, i} - \left[\mathrm{flag}_{i+1}\right]C_{1, i}, 
\end{align*}
where $\mathrm{flag}_i$ is the value of the flag with the last $i-1$ bits flipped. We observe that
\begin{align*}
D_i &= C_{2, i} - \left[\mathrm{flag}_{i+1} \right]C_{1, i} \\
&= M_i + \left[k_i \cdot \mathrm{flag}_i \right] G - \left[\mathrm{flag}_{i+1} \cdot k_i \right] G\\
&= M_i + \left[(\mathrm{flag}_i - \mathrm{flag_{i+1}}) \cdot k_i \right]G.
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

## 0xL4ugh
I didn't solve this one within allotted the time limit, but I worked it out after
with some additional analysis. Thank you to [Berlian
Gabriel](https://berliangabriel.github.io/post/0xl4ugh-ctf-2024/) for providing
the ideas behind solving the first stage of the challenge.

### Solving for d\_evil
The first stage consists of finding two secret 333-bit numbers `d_evil` and
 `d_good`. To obtain `d_evil`, we are provided with three RSA public key pairs
 for which `d_evil` is the private exponent.
 ```python
 def RsaGen(d): # d_evil passed in here
    for _ in range(max_retries):
        try:
            Ns, es = [], []
            for evilChar in "666":
                p = getPrime(512)
                q = getPrime(512)
                phi = (p - 1) * (q - 1)
                e = inverse(d, phi)
                Ns.append(p * q)
                es.append(e)

            return Ns, es
        except ValueError as e:
            # Ignore the error and continue the loop
            pass
 
 ```
 
 The following attack comes from [Kumar et al.
 (2012)](https://www.ijcsi.org/papers/IJCSI-9-2-1-311-314.pdf). Since $d$ is the
 shared private exponent for three RSA public key pairs $(N_i, e_i)$, we have
 the following relations
 
 \begin{align*}
  de_1 &\equiv 1 \pmod{\phi_1}\\
  de_2 &\equiv 1 \pmod{\phi_2}\\
  de_3 &\equiv 1 \pmod{\phi_3},
\end{align*} where $\phi_i = \phi(N_i) = \phi(p_iq_i)$. Lifting to relations in $\mathbb{Z}$, we have for some $k_1,k_2,k_3 \in \mathbb{Z}$
 \begin{align*}
  de_1 &= 1 + k_1\phi_1\\
  de_2 &= 1 + k_2\phi_2\\
  de_3 &= 1 + k_3\phi_3.\\
\end{align*}
Now for $1 \leq i \leq 3$, put $s_i = p_i q_i$. Then 
\begin{align*}
  de_1 &= 1 + k_1N_1 - k_1s_1\\
  de_2 &= 1 + k_2N_2 - k_2s_2\\
  de_3 &= 1 + k_3N3 - k_3s_3\\
\end{align*}
which is instance of the hidden number problem. So consider the lattice $L$ spanned by the rows of the matrix

\begin{equation*}
  \mathbf{B} = 
  \begin{bmatrix}
  N_1 & 0 & 0 & 0\\
  0 & N_2 & 0 & 0\\
  0 & 0 & N_3 & 0\\
  -e1 & -e2 & -e3 & M\\
  \end{bmatrix}.
\end{equation*}
The linear combination $(k_1, k_2, k_3, d)$ generates the vector
\begin{equation*}
\mathbf{e} = (k_1s_1 - 1, k_2s_2 - 1, k_3s_3 - 1, dM)
\end{equation*} which we hope to be small enough to be an SVP solution for the lattice.

We observe that each $s_i,e_i,\phi_i$ are all on the order of 512 bits, and
since $d_i$ is approx. 333 bits, then $de_i = 1 + k_i\phi_i$ implies that $k_is_i$
is approx. 800 bits. Hence $|\mathbf{e}|$ will be small relative to other
lattice vectors provided we choose $M$ appropriately. In particular, we have
the lower bound \begin{equation*} \lambda_1(L) \geq \mathrm{min}\{N_1, N_2, N_3,
M\} \end{equation*} due to the Gram-Schmidt orthogonalisation, which is sharp for sufficiently
large $M \leq \mathrm{max}\{N_1, N_2, N_3\}$. Following [Kumar et al.
 (2012)](https://www.ijcsi.org/papers/IJCSI-9-2-1-311-314.pdf) we will use 
 \begin{equation*}
 M = \left\lfloor \sqrt{\mathrm{max}\{N_1, N_2, N_3\}} \right\rfloor
 \end{equation*} which is on the order 512 bits.
```julia
using Sockets
using JSON
using LinearAlgebra

function solve_d_evil(conn)
  @show readuntil(conn, "option:")
  option = Dict("option" => "1")
  write(conn, JSON.json(option) * "\n")
  Ns = readuntil(conn, "\n") |> strip |> Meta.parse |> Meta.eval
  es = readuntil(conn, "\n") |> strip |> Meta.parse |> Meta.eval

  d_evil = rsa_common_d_lattice(Ns, es)

  d_evil
end

function rsa_common_d_lattice(moduli, exponents)
  M = BigInt(floor(sqrt(maximum(moduli))))
  B = BigInt[
    diagm(moduli) zeros(BigInt, length(moduli))
    transpose(-exponents) [M]
  ]

  B_reduced = open(`fplll`; read = true, write = true) do fplll
    write(fplll, to_fplll(B))
    read(fplll, String)
  end

  shortest_vector = open(`fplll -a svp`; read = true, write = true) do svp
    write(svp, B_reduced)
    from_fplll(read(svp, String))
  end
  @show log2(norm(shortest_vector))

  dM = abs(last(shortest_vector))
  if dM % M != 0
    error("Target vector was not shortest vector of lattice")
  end
  return fld(dM, M)
end

function to_fplll(matrix::AbstractMatrix)
  ret = "["
  for row in eachrow(matrix)
    ret *= "[" * join(string.(row), " ") * "]"
  end
  ret *= "]"

  ret
end

function to_fplll(v::AbstractVector)
  ret = "[" * join(string.(v), " ") * "]"
  ret
end

function from_fplll(v::AbstractString)
  reshape(permutedims(Meta.eval(Meta.parse(v))), :)
end
```
### Solving for `d_good`
The challenge provides us with a sequence of 10 integers $x_i$ given by the relation
\begin{equation*}
x_i = d_\mathrm{good}\cdot y_i + p_i
\end{equation*}
where $p_i$ is an unknown 333 bit prime and $y_i$ is chosen. One observes that by choosing $y_i$ sufficiently large, we can recover $d_\mathrm{good}$ through floor division
\begin{equation*}
d_\mathrm{good} = \left\lfloor \frac{x_i}{y_i}\right\rfloor
\end{equation*}
```julia
function solve_d_good(conn)
  @show readuntil(conn, "option:")
  option = Dict("option" => "2")
  write(conn, JSON.json(option) * "\n")
  @show readuntil(conn, "Enter your payload:\t")

  # Choose multiple larger than 333-bit prime, but still 333 bit
  payload = big(2)^333 - 1
  @assert length(digits(payload; base = 2)) == 333
  write(conn, string(payload) * "\n")
  rand = readuntil(conn, "\n") |> strip |> Meta.parse |> Meta.eval

  # RAND[1] = d_good * 2^333 + (something less than 2*333)
  d_good = fld(first(rand), payload)

  d_good
end
```

### CBC bit-flipping
Once authenticated, the final segment of the challenge is a classic [CBC bit-flip attack](https://crypto.stackexchange.com/questions/66085/bit-flipping-attack-on-cbc-mode). 
Since we control both the IV and the ciphertext, as well as having
access to failed decryptions, we essentially have full control over the entire
token.
```julia
function authenticate!(conn, key)
  write(conn, JSON.json(key) * "\n")
  @show readuntil(conn, "2.sign in")
end

const AES_BLOCK_SIZE = 16
function cbc_bitflip(conn, key)
  authenticate!(conn, key)
  option = Dict("option" => "1", "user" => "wednesday")
  write(conn, JSON.json(option) * "\n")

  token = replace(readuntil(conn, "\n"), "'" => "\"", "False" => "false")
  @show token
  ciphertext = hex2bytes(readuntil(conn, "\n"))
  @assert length(ciphertext) % 16 == 0
  @show ciphertext
  iv, ciphertext = ciphertext[1:AES_BLOCK_SIZE], ciphertext[AES_BLOCK_SIZE+1:end]
  @show ciphertext
  authenticate!(conn, key)

  # Manipulate first ciphertext block to change block 2 of plaintext
  current = token[AES_BLOCK_SIZE+1:2*AES_BLOCK_SIZE]
  @show current
  current = UInt8.([Char(c) for c in current])
  want = b"isadmin\": true, "
  @assert length(want) == length(current) == AES_BLOCK_SIZE
  # current = AES(C2) + C1
  # current + want = AES(C2) + (C1 + want)
  # want = AES(C2) + (C1 + want + current)
  new_ciphertext_1 = ciphertext[1:AES_BLOCK_SIZE] .⊻ want .⊻ current

  # See what the first block got encrypted to and change IV acccordingly
  payload = [iv; new_ciphertext_1; ciphertext[AES_BLOCK_SIZE+1:end]]
  @assert length(payload) % AES_BLOCK_SIZE == 0
  option = Dict("option" => "2", "token" => bytes2hex(payload))
  write(conn, JSON.json(option) * "\n")
  response = readuntil(conn, "\n")
  # mein gott
  decrypted = replace(only(match(r"b'(.*)'", response)), "\\\\" => '\\')
  decrypted = "b'" * decrypted * "'"
  decrypted = hex2bytes(strip(String(read(`python -c print\($decrypted.hex\(\)\)`))))

  @assert length(decrypted) % AES_BLOCK_SIZE == 0

  # Second round
  # current = AES(new_C1) + IV
  # current + want = AES(new_C1) + (IV + want)
  # want = AES(new_C1) + (IV + want + current)
  current = decrypted[1:AES_BLOCK_SIZE]
  want = [b"{"; repeat(b" ", 14); b"\""]
  @assert length(current) == length(want) == AES_BLOCK_SIZE
  new_iv = iv .⊻ want .⊻ current

  # Get flag
  authenticate!(conn, key)
  payload = [new_iv; new_ciphertext_1; ciphertext[AES_BLOCK_SIZE+1:end]]
  @assert length(payload) % AES_BLOCK_SIZE == 0
  option = Dict("option" => "2", "token" => bytes2hex(payload))
  write(conn, JSON.json(option) * "\n")
  option = Dict("option" => "1")
  write(conn, JSON.json(option) * "\n")
  while true
    @show response = readuntil(conn, "\n")
  end
end
```
### Flag (not captured)
```plaintext
0xL4ugh{cryptocats_B3b0_4nd_M1ndfl4y3r}
```





[Cryptohack]: (https://cryptohack.org/)



