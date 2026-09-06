# bcrypt lane core — design

Date: 2026-09-06. Goal: make Hashsmith the fastest CPU bcrypt cracker of the
three tools, by a margin that survives hardware Hashsmith has not been measured
on.

## 1. The measurement this exists to move

Apple M2 (8-core, 4P+4E), single thread, bcrypt cost 5, measured 2026-09-06:

| | ns/op | c/s |
|---|---|---|
| `bcrypt.CompareHashAndPassword` — what `crack.go:2476` calls today | 3,305,662 | 302 |
| the EksBlowfish key schedule alone, no library wrapper | 3,291,526 | 304 |
| John the Ripper, `john --test=10 --format=bcrypt`, `[Blowfish 32/64 X2]` | — | 591 |

**The library wrapper costs 0.4%.** Allocation removal, base64 handling and
`verifyCandidate` plumbing are not worth touching; every one of them is inside
that 0.4%. The whole cost is the key schedule, so the key schedule is the only
thing this design changes.

Multi-threaded wall clock on the same machine, 40,000 candidates, exhaustive,
best of two: Hashsmith 18.74 s, John `--fork=8` 16.61 s, Hashcat `-m 3200`
22.32 s. Hashsmith's near-parity there is Go's scheduler beating John's
8-process fork model, and it masks the ~1.96x per-thread core deficit above. It
would not mask it on a machine with many more cores, which is why the target
below is a per-thread one.

## 2. Target

**>= 887 c/s single-thread at cost 5** (1.5 x John's 591), **and** faster wall
clock than `john --fork=<physical core count>` at 4k, 40k and 400k candidates
(`--fork=8` on the measuring machine).

That is a **2.94x** improvement over today's 302 c/s.

### Why it is reachable

At cost 5 a bcrypt is `521 * (1 + 2 * 2^5) = 33,865` Blowfish block encryptions
for the key schedule, plus 192 for the final `OrpheanBeholderScryDoubt` pass:
**34,057** block encryptions. Today's 3.3057 ms over 34,057 blocks is 97.1 ns
per block — about **340 cycles per block, 21.2 cycles per Feistel round** on a
~3.5 GHz P-core.

A Blowfish round's four S-box lookups are mutually independent: all four index
different 256-entry tables from the same input word, and only their combination
`((S0[a] + S1[b]) ^ S2[c]) + S3[d]` is serial. So the round's *latency* floor is
roughly L1 load latency plus three arithmetic ops, ~8-9 cycles, and its
*throughput* floor, given three load units against four loads, is ~1.3
cycles/round/lane. 21.2 is far above both.

**What the excess is not.** Measured 2026-09-06 with
`go build -gcflags=-d=ssa/check_bce/debug=1` over `x/crypto/blowfish@v0.31.0`:
`encryptBlock` (block.go:115-137) emits **zero** bounds checks. Go already
proves a `byte` index fits a `[256]uint32`. The package's 45 checks are all in
scaffolding the bcrypt inner loop never executes -- `getNextWord`, the key and
salt loops (block.go:13, 34, 74-109), and `cipher.go`'s byte-slice
`Encrypt`/`Decrypt`. So bounds-check elimination is not the win, and an
implementer must not spend time hunting for it.

**What it probably is**, stated as a hypothesis to be measured rather than
assumed: `ExpandKey` writes into `s0`..`s3` between encryptions, so every
`encryptBlock` load has to be disambiguated against very recent stores to the
same tables. Store-to-load forwarding pressure of this kind stalls a single
dependency chain and is precisely what independent lanes hide. Task 1 of the
implementation plan establishes the real bottleneck before any core is written;
nothing downstream depends on this hypothesis being right, because the remedy
-- more independent chains in flight -- is the same for any of the plausible
causes.

The target needs 7.25 cycles/round. That is above the latency floor for a single
lane, so it cannot be reached by one chain no matter how tight — and comfortably
above the throughput floor once several independent chains are in flight. Hence
lanes.

### Why lanes and not SIMD

Blowfish resists vectorization: the F function is four data-dependent table
lookups, NEON has no gather at all, and AVX2's `vpgatherdd` is slower than
scalar loads for L1-resident tables. John's own format string says the same
thing — `[Blowfish 32/64 X2]` is two *scalar interleaved* lanes hiding load
latency through instruction-level parallelism, not vector lanes, and it is
generic C rather than hand-written assembly. This design does the same thing
with more lanes.

### Budget check

Each lane needs its own mutable Blowfish state, because bcrypt mutates the
S-boxes per candidate: 4 x 256 x 4 bytes of S-boxes plus an 18-entry P array,
~4.1 KB per lane. Four lanes is ~16.4 KB against a 128 KB L1D — comfortable, and
even eight lanes fit. arm64's 31 general registers hold four lanes' working
state without spilling.

## 3. Scope

**In:** the bare `bcrypt` type, single target.

**Out, deliberately:**

- **Multi-target bcrypt dumps.** Every lane in a batch must share one cost and
  one salt, because they execute the same iteration count in lockstep. A dump
  has per-target salts and possibly mixed costs. Multi-hash mode keeps today's
  path unchanged.
- **Composite bcrypt formats** — django-bcrypt, `bcrypt-md5`, `bcrypt-sha1`,
  `bcrypt-sha256` — which reach `bcrypt.CompareHashAndPassword` from
  `crack_django.go`, `crack_hashcat_more_records.go` and
  `crack_hashcat_vendor_records.go`. They stay on the library path.
- **Assembly.** Decided against for this pass; see §8.
- **Every other slow hash.** The crypt(3) family, PBKDF2, scrypt and Argon2 are
  out. Notably `sha256crypt`/`sha512crypt` are iterated SHA-2 with no
  data-dependent lookups, so unlike Blowfish they vectorize cleanly and are
  probably a larger win for less work — but they are a separate design.

## 4. Architecture

### 4.1 `internal/bcryptlane`

A new internal package, not more files in `cmd/hashsmith`. That directory is
already ~44k LOC across 275 crack-type cases; `internal/argon2d` and
`internal/hashid` set the precedent; and the core has to be differential-tested
against `x/crypto/bcrypt` with no CLI in the way.

| file | contents |
|---|---|
| `blowfish.go` | vendored cipher state and initial P/S tables |
| `eks_lanes.go` | the N-lane interleaved key schedule, generated |
| `bcryptlane_gen.py` | generator for `eks_lanes.go` |
| `bcrypt.go` | `Hasher`: parse once, hash many |

**Vendoring is forced, not stylistic.** `blowfish.Cipher`'s `p`, `s0`..`s3`
fields are unexported, so interleaving through the public `ExpandKey(key, *Cipher)`
API is impossible — the lanes have to step through the schedule together, inside
the state. The vendored code is BSD-3-Clause; its copyright notice travels with
it and is preserved at the top of `blowfish.go`.

**Generation follows existing practice.** `md5neon_gen.py`, `md5avx2_gen.py`,
`md4neon_gen.py` and `md4avx2_gen.py` already emit their cores; `bcryptlane_gen.py`
is a fifth in the same style. Go does not unroll loops, so the per-lane work has
to be written out literally for the chains to stay independent — which is what
makes a generator worth having rather than hand-maintaining four copies of a
16-round Feistel network.

**Bounds-check freedom is a regression guard, not a goal.** The vendored code
already emits no bounds checks in the round function (see §2), and the
interleaved rewrite must not introduce any -- lane state held in slices rather
than fixed-size arrays would. A test asserts this via
`go build -gcflags=-d=ssa/check_bce/debug=1`, so a later edit cannot silently
regress it.

### 4.2 API

```go
// Hasher is one parsed bcrypt target. Parsing happens once; Run is the hot path.
type Hasher struct{ /* cost, salt, digest, prefix */ }

func NewHasher(crypt string) (*Hasher, error)

// Lanes is the compiled-in interleave width.
const Lanes = /* tuned, see §7 */

// Run hashes up to Lanes passwords against the target, writing out[i] for
// pw[i]. len(out) must be >= len(pw); len(pw) must be <= Lanes. Short slices
// are handled without padding cost.
func (h *Hasher) Run(pw [][]byte, out []bool)
```

`Run` taking a short slice rather than requiring padding matters: wordlist tails
and rule expansions rarely divide evenly by the lane width, and padding with
dummy candidates would waste up to `Lanes-1` full bcrypt computations per flush.

### 4.3 Integration, two sites

Both already batch, so no cross-cutting interface change is needed.

**Brute/mask.** `runBruteOrMaskLayout` (`crack.go:73`) is already a dispatcher
choosing specialized runners behind eligibility predicates — `fastPathEligible`
to `runLayoutFast` for the vector cores, `stdPathEligible` to `runLayoutStd` for
the contiguous batch path, scalar fallback otherwise. Add `lanePathEligible(typ,
salt, saltMode, layout)` as a fourth, dispatching to `runLayoutLanes` in a new
`lanes.go`. It must honour the same watermark and session contract as its
siblings so `--session` resume is unaffected.

**Dictionary.** `dictAttack` (`crack.go:1812`) already reads words into
`[]string` batches over `batchCh`; its worker at `crack.go:1885` calls
`verify` one candidate at a time. The worker accumulates base words *and* their
rule expansions into a `Lanes`-wide buffer and flushes through the `Hasher`.
The buffer must be flushed on batch end, on context cancellation, and at
end-of-wordlist, or trailing candidates go untested — this is the single most
likely correctness bug in the change and §6 tests it directly.

**Attribution on a hit.** A match in lane 2 of 4 must report lane 2's password
and, in dict mode, lane 2's rule label. The buffer therefore carries
`(password, ruleLabel)` pairs, not bare strings.

## 5. What does not change

The single-candidate `verifyCandidate` path stays exactly as it is for the other
456 formats. Multi-hash mode, the potfile, session resume semantics, `--keyspace`
/`--skip`/`--limit` slicing and the feasibility guard are untouched. The
feasibility probe already times the real dispatch, so it picks up the new rate
without modification.

## 6. Correctness

Differential testing against `x/crypto/bcrypt` is the backbone: it is the exact
implementation Hashsmith ships today, so any divergence is a regression by
definition.

1. **Differential, randomized.** Thousands of cases over random salts and costs
   4-10, with passwords including empty, one byte, exactly 72 bytes, over 72
   bytes (truncation), embedded NUL, and multi-byte UTF-8.
2. **Prefix compatibility.** `$2a$`, `$2b$`, `$2x$` and `$2y$` differ in the
   >255-byte key wraparound bug. Behaviour must match `x/crypto` exactly,
   including where `x/crypto` rejects.
3. **Lane invariance.** Widths 1, 2, 4 and 8 produce identical results for the
   same inputs. This is what makes the tuning in §7 safe.
4. **Tail and flush.** Candidate counts not divisible by `Lanes`, with the
   correct password planted at every position of the final partial batch, and
   at the last position of the wordlist overall.
5. **Attribution.** A hit in each lane position reports that lane's password and
   rule label.
6. **Existing vectors.** The `selftest` bcrypt vectors pass unchanged through
   the new path, and `-slow` stays green.
7. **No bounds checks introduced.** Asserted via
   `-d=ssa/check_bce/debug=1` over the round function, guarding the property
   the vendored code already has rather than establishing a new one.

## 7. Tuning and the performance gate

Lane width is chosen by measurement, not prediction: build at 1, 2, 4 and 8,
benchmark each, ship the winner as `Lanes`. Prediction is 4, on the register and
cache budget in §2; the measurement decides.

**The CI gate is a ratio, not an absolute.** A c/s floor is machine-dependent and
would flake across runners. Instead the benchmark measures `bcryptlane` and
`x/crypto/bcrypt` *in the same process on the same machine* and ratchets on
their ratio, in the style of `recognitionFloor` (`recognition_test.go:20`) —
a computed constant with a stated margin, raised as the number improves, never
hand-rounded in Hashsmith's favour.

Reporting keeps John's number alongside: the README table gains a per-thread
row, since §1 shows wall clock alone hid a 1.96x core deficit and should not be
allowed to hide it again.

## 8. Risks and decisions taken

**The target may not be met in pure Go.** 2.94x is a real stretch, and the
estimate that Go can reach it is an inference from a cycle budget, not a
measurement. Assembly was considered and deliberately deferred: the pure-Go core
is required regardless as the portable path, it is the correctness oracle any
future assembly would be differential-tested against, and it yields the real
number that would make an assembly decision evidence-based rather than
speculative. If the core lands short of 887 c/s, that is a **bar decision to
revisit, not rework** — no part of this design is discarded by adding assembly
later.

**Vendoring adds ~1,000 lines of constant tables** to the repository, and a
BSD-3-Clause notice to honour.

**Scope creep toward the crypt(3) family** is the likely pull, since
`sha256crypt`/`sha512crypt` look easier. Resisted here on purpose; §3 records
why they are a better *second* target and a separate design.
