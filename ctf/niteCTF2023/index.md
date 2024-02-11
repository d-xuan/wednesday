# niteCTF 2023
@@subtitle
cha-cha-cha
@@

@def mintoclevel=3
\toc

### Introduction
We are provided with a decryption oracle for ChaCha20Poly1305, and tasked
with determining the oracle's key derivation secret in order to retrieve the flag.
```python
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from secret import FLAG

TOKEN = ''.join(['{:02x}'.format(byte) for byte in os.urandom(9)])

def get_tokens():
    tokens = [str(TOKEN[i:i+3]) for i in range(0, len(TOKEN), 3)]
    return tokens

def derive_key(token, iterations=100000, key_length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b'CryPT0N1t3',
        length=key_length,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(token.encode())
    return key

def decrypt(ciphertext, token_index):
    nonce = ciphertext[:12]
    ciphertext = ciphertext[12:]
    key = derive_key(tokens[token_index])
    cipher = ChaCha20Poly1305(key)
    plaintext = cipher.decrypt(nonce, ciphertext, None)
    return plaintext

def main():
    global tokens
    global token_index
    global queries

    tokens = get_tokens()
    token_index = 0
    queries = 0

    while queries <= 800:
        print ("\nchoose an option:\n")
        print("1. select token")
        print("2. decrypt")
        print("3. get flag")
        print("4. exit")

        option = input(">>: ")

        if option == "1":
            sel = int(input("\nselect a token (1-6)\n>>: "))
            if 1 <= sel <= 6:
                token_index = sel - 1
            else:
                print("invalid token index")

        elif option == "2":
            ciphertext = bytes.fromhex(input("ciphertext (hex): "))
            try:
                pt = decrypt(ciphertext, token_index)
                print (f"decrypted (hex): {pt.hex()}")
            except:
                print ("error decrypting")

        elif option == "3":
            entered_token = input("enter token: ")
            if entered_token == TOKEN:
                print(f"{FLAG}")
                break
            else:
                print("wrong token")
                break

        elif option == "4":
            break

        queries += 1

if __name__ == "__main__":
    main()
```

The entire secret is 9 bytes (72 bits), however we only need to submit guesses in
12 bit tokens. While it wouldn't take long to enumerate all 4096 possibilities
for each token, we are prevented from doing so by the oracle's limit on the
number of queries we're allowed to place.

> Whenever a linear search doesn't work, try binary

What we can do instead is apply a partitioning oracle attack, following [Len,
Grubbs and Ristenpart][LenGrubsRistenpart]. Looking at the ChaCha20Poly1305
algorithm, we see that the validity of a ciphertext depends only on the validity
of the Poly1305 tag $T$ relative to the authentication inputs $(AD, K, N, C)$
of which we control all but $K$.

@@invert_image
![ChaCha20Poly1305](https://upload.wikimedia.org/wikipedia/commons/5/55/ChaCha20-Poly1305_Encryption.svg)
@@

Hence given two distinct keys $K_1$, $K_2$, one hopes to manipulate the
remaining inputs $(AD, N, C)$ in such a way so as to make the tags

\begin{align*}
T_1 &= \mathrm{Poly1305}(AD, K_1, N, C)\\
T_2 &= \mathrm{Poly1305}(AD, K_2, N, C)
\end{align*} equal.

If successful, we can treat the two keys as one when submitting to the oracle.
Rejection of $(T_1, C)$ entails rejection of $(T_2, C)$, allowing us to exclude 
both $K_1$ and $K_2$ as candidates with a single query. Generalising to
simultaneous collisions involving $n$ keys, we can carve away large
portions of the key space with only a few queries.

In practice, $AD$ and $N$ are kept fixed at sensible defaults (in our case empty
and zero) whilst $C$ is manipulated to produce the desired effect. A successful
ciphertext $C$ is known as a *splitting ciphertext*, and the number of distinct
keys for which it causes a tag collision is the splitting ciphertext's *degree*.

Splitting ciphertexts of degree $n$ partition the key space
$\mathcal{K}$ into $|\mathcal{K}|/n$ subsets. This allows determining the
correct key in approximately $|\mathcal{K}|/n + \log_2(n)$ queries compared to
the $|\mathcal{K}|$ queries of a brute force search. In the $n = |\mathcal{K}|/2$
case we recover classical binary search, however reaching high values
of $n$ for Poly1305 requires significant computational effort.

### Finding splitting ciphertexts
Given keys $K_1, K_2, \ldots,K_n$, we seek a ciphertext $C$ such that 

\begin{equation}
\mathrm{Poly1305}(K_1, C) = \mathrm{Poly1305}(K_2, C) = \ldots = \mathrm{Poly1305}(K_n, C). \label{eq:1} 
\end{equation}

Suppose $C$ is composed of $m$ 16-byte blocks $m_1, \ldots, m_m$ and let $m_{\mathrm{meta}}$ be a fixed metadata block containing ciphertext length information.
If $s_i, r_i$ are the (clamped) Poly1305 keys derived via ChaCha20 from $K_i$, then 

\begin{equation*}
\mathrm{Poly1305}(K_i, C) = s_i + \left[m_{\mathrm{meta}} + \sum_{k = 1}^m \mathrm{pad}(m_k) r_i^k \right]_p
\end{equation*}

where $p$ is the prime $2^{130} - 5$. We see that Poly1305 deliberately
sabotages its algebraic structure in two ways: first through the unreduced
addition of $s_i$, and second by requiring that its polynomial coefficients be
padded by appending one byte beyond the number of octects. Sidestepping these
issues for the moment, we can reduce \eqref{eq:1} modulo $p$ to obtain a system of linear equations in $\mathbb{F}_p$ with 
$n - 1$ constraints and  $m$ unknowns

\begin{align*}
s_1 + m_{\mathrm{meta}} + \sum_{k = 1}^m \mathrm{pad}(m_k)r_1^k &= s_2 + m_{\mathrm{meta}} + \sum_{k = 1}^m \mathrm{pad}(m_k) r_2^k\\ 
s_2 + m_{\mathrm{meta}} + \sum_{k = 1}^m \mathrm{pad}(m_k)r_2^k &= s_3 + m_{\mathrm{meta}} + \sum_{k = 1}^m \mathrm{pad}(m_k) r_3^k\\ 
    \vdots&\\
s_{n-1} + m_{\mathrm{meta}} + \sum_{k = 1}^m \mathrm{pad}(m_k)r_{n-1}^k &= s_n + m_{\mathrm{meta}} + \sum_{k = 1}^m \mathrm{pad}(m_k) r_n^k.\\
\end{align*}

Assuming linear independence of the equations, this bounds $m \geq n - 1$ in order for the system to not be overdetermined. The solutions form an $m - n -1$ dimensional subspace of $\mathbb{F}_p^m$

\begin{equation*}
\begin{bmatrix}
&\mathrm{pad}(m_1)&\\
&\vdots&\\
&\mathrm{pad}(m_m)&\\
    \end{bmatrix} = \mathbf{p} + \sum_{k = 1}^{m - n - 1}t_k\mathbf{v}_k, \quad \mathbf{p},\mathbf{v_k} \in \mathbb{F}_p^m, t_k \in \mathbb{F}_p. 
\end{equation*}

### Satisfying padding requirements
In order for $\mathbf{p} + \sum_{k = 1}^{m - n - 1}t_k\mathbf{v}_k$ to form a
valid splitting ciphertext, each coordinate must lie in the image of the
Poly1305 $\mathrm{pad}(\cdot)$ operation. For 16-byte message blocks, this is
equivalent to requiring that each $\mathrm{pad}(m_i)$ be congruent to $a_i$
modulo $p$ for some $a_i$ in the interval $\left[2^{128}, 2^{129}\right]$.

If coordinates were uniformly distributed, the probability of any one coordinate
lying in the required interval is approximately $1/4$, so the probability of the
padding requirement being satisfied by chance is approximately $1/4^m$. Using a
generate-and-test method, splitting ciphertexts can be brute-forced for degrees
up to $n \approx 10$, but chances diminish exponentially for higher
values of $n$. Moreover $n = 10$ will not be sufficient for our use-case:
splitting ciphertexts of degree $10$ will require (worst case) approx. $400$
queries to determine the applicable partition for each token, which exceeds our
budget of 800 total queries across all six tokens.

The idea for generating splitting ciphertexts of higher degree comes from
[KryptosLogic]. First we lift our solution to $\mathbb{Z}^{m}$ by appending
arbitrary linear combinations of $p\mathbf{e}_1,\ldots,p\mathbf{e}_m \in \mathbb{Z}^m$

\begin{equation*}
\begin{bmatrix}
&\mathrm{pad}(m_1)&\\
&\vdots&\\
&\mathrm{pad}(m_m)&\\
\end{bmatrix} = \mathbf{p} + \sum_{k = 1}^{m - n - 1}t_k\mathbf{v}_k + p\sum_{k=1}^{m}t'_k \mathbf{e}_k, \quad \mathbf{p},\mathbf{v_k} \in \mathbb{Z}^{m}, t_k,t'_k \in \mathbb{Z}. 
\end{equation*}

The vectors $(\mathbf{v}_1,\ldots,\mathbf{v}_{m - n - 1}, p\mathbf{e}_1, \ldots,
p\mathbf{e}_m)$ then span a lattice $L \subseteq \mathbb{Z}^m$, and so the
problem of finding vectors with coordinates in the interval $\left[2^{128},
2^{129}\right]$ becomes equivalent to finding vectors in $L$ sufficiently close
to the midpoint vector $(2^{128} + 2^{127}, \ldots, 2^{128} + 2^{127}) \in
\mathbb{Z}^m$. This is an instance of the [closest vector problem][CVP], which
can be solved for reasonable values of $m$ by implementations such as `[fplll]`.
In particular $m \geq 32$ will be sufficient for our purposes.

### Implementation in Julia
Julia doesn't have a native ChaCha20Poly1305 implementation, so we'll be
implementing parts of the algorithm according to [RFC 7539][RFC] ourselves.

First, we have the ChaCha20 section of the algorithm.
```julia
function quarter_round(a::UInt32, b::UInt32, c::UInt32, d::UInt32)
    a += b; d ⊻= a; d = bitrotate(d, 16);
    c += d; b ⊻= c; b = bitrotate(b, 12);
    a += b; d ⊻= a; d = bitrotate(d, 8);
    c += d; b ⊻= c; b = bitrotate(b, 7);

  a, b, c, d
end

function quarter_round!(state::AbstractMatrix{UInt32}, a_idx, b_idx, c_idx, d_idx)
  state[a_idx], state[b_idx], state[c_idx], state[d_idx] =
    quarter_round(state[a_idx], state[b_idx], state[c_idx], state[d_idx])

  state
end

function chacha20_block_checkdims(key, nonce, block_count)
  if sizeof(key) * 8 != 256 || sizeof(nonce) * 8 != 96 || sizeof(block_count) * 8 != 32
    false
  end

  true
end

function chacha20_block_init_state(
  key::AbstractVector{UInt8},
  nonce::AbstractVector{UInt8},
  block_count::AbstractVector{UInt8},
)
  key = reinterpret(UInt32, key)
  nonce = reinterpret(UInt32, nonce)
  block_count = reinterpret(UInt32, block_count)

  UInt32[
    0x61707865 0x3320646e 0x79622d32 0x6b206574
    transpose(key[1:4])
    transpose(key[5:8])
    transpose(block_count) transpose(nonce)
  ]
end

function chacha20_block(
  key::AbstractVector{UInt8},
  nonce::AbstractVector{UInt8},
  block_count::AbstractVector{UInt8},
)
  chacha20_block_checkdims(key, nonce, block_count) || throw(
    ArgumentError(
      "Expected 256 bit key, 96 bit nonce, 32 bit block_count, passed as 32-bit little endian integers",
    ),
  )

  state = chacha20_block_init_state(key, nonce, block_count)
  working_state = copy(state)
  rm_view = transpose(working_state) # row-major indexed matrix
  for _ = 1:10
    chacha20_block_innerblock!(rm_view)
  end
  state += working_state

  serialize(state)
end

function chacha20_block_innerblock!(rm_view::AbstractMatrix{UInt32})
  # using 1-based row-major indexes
  quarter_round!(rm_view, 1, 5, 9, 13)
  quarter_round!(rm_view, 2, 6, 10, 14)
  quarter_round!(rm_view, 3, 7, 11, 15)
  quarter_round!(rm_view, 4, 8, 12, 16)
  quarter_round!(rm_view, 1, 6, 11, 16)
  quarter_round!(rm_view, 2, 7, 12, 13)
  quarter_round!(rm_view, 3, 8, 9, 14)
  quarter_round!(rm_view, 4, 5, 10, 15)
end

function serialize(chacha_state::AbstractMatrix{UInt32})
  reshape(reinterpret(UInt8, transpose(chacha_state)), 64)
end

function chacha20(
  key::AbstractVector{UInt8},
  block_count::AbstractVector{UInt8},
  nonce::AbstractVector{UInt8},
  plaintext::AbstractVector{UInt8},
)
  chacha20_block_checkdims(key, nonce, block_count)
  base_count = only(reinterpret(UInt32, block_count))
  encrypted_message = UInt8[]
  for (i::UInt32, message_block) in enumerate(Iterators.partition(plaintext, 64))
    counter = reinterpret(UInt8, [base_count + (i - one(UInt32))])
    key_stream = chacha20_block(key, nonce, counter)
    block = collect(x ⊻ y for (x, y) in zip(key_stream, message_block))
    append!(encrypted_message, block)
  end

  encrypted_message
end
```
Next we have the Poly1305 section
```julia
using AbstractAlgebra

const P = BigInt(2)^130 - 5
const F_p = GF(P)

function poly1305_clamp!(r::AbstractVector{UInt8})
  # 1-based index again
  r[4] &= 0x0f
  r[8] &= 0x0f
  r[12] &= 0x0f
  r[16] &= 0x0f

  r[5] &= 0xfc
  r[9] &= 0xfc
  r[13] &= 0xfc

  r
end

function poly1305_checkdims(key)
  if sizeof(key) * 8 != 256
    false
  end

  true
end

function poly1305_prepare_key(key::AbstractVector{UInt8})
  r, s = key[1:16], key[17:end]
  poly1305_clamp!(r)
  r = F_p(only(reinterpret(UInt128, r)))
  s = BigInt(only(reinterpret(UInt128, s)))

  return r, s
end

function poly1305_poly(message::AbstractVector{UInt8}, r::FinFieldElem)
  acc = zero(F_p)

  for m in Iterators.partition(message, 16)
    n = evalpoly(F_p(256), [m; [0x01]])
    acc += n
    acc *= r
  end

  acc
end

function poly1305(key::AbstractVector{UInt8}, message::AbstractVector{UInt8})
  poly1305_checkdims(key) || throw(
    ArgumentError(
      "Expected 256 bit key, 96 bit nonce, 32 bit block_count, passed as 32-bit little endian integers",
    ),
  )

  r, s = poly1305_prepare_key(key)

  acc = poly1305_poly(message, r)
  acc = lift(acc) + s

  lower128 = acc & ~UInt128(0)

  convert.(UInt8, digits(lower128, base = 256, pad = 16))
end

function poly1305_key_gen(key::AbstractVector{UInt8}, nonce::AbstractVector{UInt8})
  counter = reinterpret(UInt8, [0x00000000])
  block = chacha20_block(key, nonce, counter)

  block[1:32]          # first 256 bits
end
```

And finally the two composed together.
```julia
function aead_chacha20_poly1305(
  key::AbstractVector{UInt8},
  nonce::AbstractVector{UInt8},
  plaintext::AbstractVector{UInt8},
  aad::AbstractVector{UInt8},
)
  poly1305_key = poly1305_key_gen(key, nonce)
  counter = reinterpret(UInt8, [0x00000001])
  ciphertext = chacha20(key, counter, nonce, plaintext)

  message = aead_chacha20_poly1305_message_construct(ciphertext, aad)
  tag = poly1305(poly1305_key, message)

  return tag, ciphertext
end
```
Julia doesn't seem to have a PBKDF2HMAC implementation either, so let's quickly enumerate the 12-bit key space
```python
import itertools
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

TOKENS = ["{:03x}".format(byte) for byte in range(pow(2, 12))]
def derive_key(token, iterations=100000, key_length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b"CryPT0N1t3",
        length=key_length,
        iterations=iterations,
        backend=default_backend(),
    )
    key = kdf.derive(token.encode())
    return key

with open("keys.txt", "w") as fp:
    for tok in TOKENS:
        key = derive_key(tok)
        fp.write("[" + ",".join("0x{:02x}".format(x) for x in key) + "]" + "\n")
```
and pass it through in a file
```julia
struct Key
  raw::String           # e.g "20a", "6fe"
  hashed::Vector{UInt8} # 32 bits
end

const KEYS = map(enumerate(eachline(open("keys.txt")))) do (i, line)
  raw = string(i - 1, base = 16, pad = 3)
  hashed = Meta.eval(Meta.parse(line))
  Key(raw, hashed)
end
```
Next we partition the key space into a forest of binary trees. Since we can compute splitting ciphertexts of degree $n = 32$, each tree will contain 32 keys.
```julia
struct Ciphertext
  tag::Vector{UInt8}
  nonce::Vector{UInt8}
  ciphertext::Vector{UInt8}
end

mutable struct TreeNode
  splitting::Ciphertext
  keys::AbstractVector{Key}
  lo::Union{TreeNode,Nothing}
  hi::Union{TreeNode,Nothing}
end

forest = []

for keys in Iterators.partition(KEYS, 32)
  splitting_ciphertext = find_collision(keys)
  tree = TreeNode(splitting_ciphertext, keys, nothing, nothing)
  push!(forest, tree)
end

stck = copy(forest)
while !isempty(stck)
  tree = pop!(stck)

  if length(tree.keys) <= 1
    continue
  end

  mid = cld(length(tree.keys), 2)
  lokeys, hikeys = tree.keys[1:mid], tree.keys[mid+1:end]

  if !isempty(lokeys)
    losplit = find_collision(lokeys)
    tree.lo = TreeNode(losplit, lokeys, nothing, nothing)
    push!(stck, tree.lo)
  end

  if !isempty(hikeys)
    hisplit = find_collision(hikeys)
    tree.hi = TreeNode(hisplit, hikeys, nothing, nothing)
    push!(stck, tree.hi)
  end
end
```
The `find_collision` function generates a splitting ciphertext by setting up the system of equations and solving the corresponding lattice problem
```julia
function find_collision(keys::AbstractVector{Key})
  find_collision(getfield.(keys, :hashed))
end

# `redundancy` parameter controls how much `m` exceeds `n`, i.e `redundancy` = m - n
function find_collision(keys::AbstractVector{Vector{UInt8}}; redundancy = 0)
  if length(keys) == 1
    return random_ciphertext(only(keys))
  end

  poly1305_keys = map(Base.Fix2(poly1305_key_gen, NONCE), keys)
  r_s = poly1305_prepare_key.(poly1305_keys)
  r, s = first.(r_s), last.(r_s)

  # Last 16 byte block is a constant metadata block
  num_ciphertext_blocks = length(keys) + redundancy
  aad_length = reinterpret(UInt8, [length(AAD)])
  ciphertext_length = reinterpret(UInt8, [16 * num_ciphertext_blocks])
  metadata_block = [aad_length; ciphertext_length]

  # RHS of linear system
  b = [
    F_p(s[i] - s[i-1]) - evalpoly(F_p(256), [metadata_block; [0x01]]) * (r[i-1] - r[i])
    for i = 2:length(keys)
  ]
  b = matrix(F_p, reshape(b, :, 1))

  # LHS of linear system
  A = [[(r[i-1]^j - r[i]^j) for j = (num_ciphertext_blocks+1):-1:2] for i = 2:length(keys)]
  A = matrix(F_p, stack(A; dims = 1))

  particular_sol = AbstractAlgebra.solve(A, b)
  nullity, homogenous_sol = nullspace(A)
  d = length(particular_sol)

  # Solution is a subspace of Fp^n. Lift solution to ZZ by appending (e1, e2, ..., e_d) to the basis
  particular_sol = lift.(Matrix(particular_sol))
  homogenous_sol = [
    lift.(Matrix(homogenous_sol)) P*diagm(ones(Int64, d))
  ]

  # LLL-reduce lattice basis
  reduced_basis = open(`fplll`; read = true, write = true) do fplll
    write(fplll, to_fplll(transpose(homogenous_sol))) # Transpose because fplll expects row vectors
    reduced_basis = read(fplll, String)
    
    # First row is all zeros since we have nvectors > ndims. Remove it.
    reduced_basis = "[" * join(split(reduced_basis, "\n")[(2+redundancy):end]) 
  end

  # Solve CVP
  midpoint = fill(big(2)^128 + big(2)^127, d)
  target = to_fplll(reshape(midpoint - particular_sol, :))

  closest_vector = open(`fplll -a cvp`; read = true, write = true) do cvp
    write(cvp, reduced_basis * target)
    closest = from_fplll(read(cvp, String))
  end
  solution = mod.(particular_sol + closest_vector, P)

  # Generate a ciphertext from the CVP solution
  ciphertext = UInt8[]
  for block in solution
    ciphertext_block = UInt8.(digits(block; base = 256, pad = 17)[1:end-1])
    append!(ciphertext, ciphertext_block)
  end

  # We could still be off by a factor of p because of the unreduced addition of s in Poly1305.
  # If that's the case, we'll just generate a new splitting ciphertext by increasing the redundancy factor.
  message = aead_chacha20_poly1305_message_construct(ciphertext, AAD)
  tag = unique(poly1305(key, message) for key in poly1305_keys)
  if length(tag) > 1
    return find_collision(keys; redundancy = redundancy + 1)
  else
    tag = only(tag)
    return Ciphertext(tag, NONCE, ciphertext)
  end
end

function random_ciphertext(key)
  ct = rand(UInt8, 16)
  poly1305_key = poly1305_key_gen(key, NONCE)
  message = aead_chacha20_poly1305_message_construct(ct, AAD)
  tag = poly1305(poly1305_key, message)

  Ciphertext(tag, NONCE, ct)
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
Finally we pass our splitting ciphertexts to the oracle, and partition/binary-search our way through the key space.
```julia
const SELECT_TOKEN = "1\n"
const DECRYPT = "2\n"
const GET_FLAG = "3\n"

function writeafter(process, delimiter, towrite)
  print(readuntil(process, delimiter))
  write(process, towrite)
end

function valid_ciphertext(server_process, ciphertext)
  writeafter(server_process, ">>:", DECRYPT)
  writeafter(
    server_process,
    ":",
    bytes2hex([ciphertext.nonce; ciphertext.ciphertext; ciphertext.tag]) * "\n",
  )

  result = String(readuntil(server_process, "\n"))
  print(result)
  if occursin("decrypted", result)
    return true
  end
  return false
end


server_process = open(`python server.py`; read = true, write = true)
full_token = ""
for token_idx = 1:6
  writeafter(server_process, ">>:", SELECT_TOKEN)
  writeafter(server_process, ">>:", "$token_idx\n")

  tree = nothing
  for t in forest
    if valid_ciphertext(server_process, t.splitting)
      tree = t
      break
    end
  end

  t = tree
  while !isnothing(t.lo) && !isnothing(t.hi)
    if valid_ciphertext(server_process, t.hi.splitting)
      t = t.hi
    elseif valid_ciphertext(server_process, t.lo.splitting)
      t = t.lo
    else
      error("Neither subtree contained a valid key")
    end
  end
  full_token *= only(t.keys).raw
end

writeafter(server_process, ">>:", GET_FLAG)
write(server_process, full_token * "\n")

flag = read(server_process, String)
@show flag
```
### Flag
```plaintext
flag = " enter token: nite{p@dd1nG...umm..n0..p@rT1tI0niNg_oR4cL3s_ftw}\n"
```

[RFC 2.6.1]: https://datatracker.ietf.org/doc/html/rfc7539#section-2.6.1
[RFC]: https://datatracker.ietf.org/doc/html/rfc7539
[CVP]: https://en.wikipedia.org/wiki/Lattice_problem#Closest_vector_problem_(CVP)
[fplll]: https://github.com/fplll/fplll
[KryptosLogic]: https://www.kryptoslogic.com/blog/2021/01/faster-poly1305-key-multicollisions/
[LenGrubsRistenpart]: https://www.usenix.org/system/files/sec21summer_len.pdf




