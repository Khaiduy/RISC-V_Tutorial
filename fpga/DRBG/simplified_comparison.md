# TRNG Simplification Analysis

## Architecture Comparison

### Current Design: Full DRBG
```
TRNG_DF_DRBG (NIST SP 800-90A compliant)
├── TRNG (384-bit collector)
│   └── TopTRNG (ring osc + LFSR_64)
├── AES_256_CTR (deterministic RBG)
│   ├── AES_Controller
│   ├── ExpandKey
│   ├── SubBytes
│   ├── ShiftRows
│   └── MixColumns
└── DRBG FSM (18 states)
    ├── Instantiate
    ├── Reseed
    ├── Generate
    └── Update
```

**Stats:**
- Lines of code: ~2024
- Verilog files: 14
- State machine: 18 states
- Output: 384 bits (processed through AES)

### Simplified Design: Direct TRNG
```
SimpleTRNG
├── TopTRNG (ring osc + LFSR_64)
└── Collection FSM (4 states)
    ├── IDLE
    ├── WARMUP (2048 cycles/word)
    ├── COLLECT (4 words)
    └── DONE
```

**Stats:**
- Lines of code: ~450
- Verilog files: 4
- State machine: 4 states
- Output: 256 bits (raw entropy)

## Code Reduction Breakdown

### Files to REMOVE (1574 lines):
1. **AES_256_CTR.v** (242 lines) - AES encryption engine
2. **ExpandKey.v** (245 lines) - AES key expansion
3. **SubBytes.v** (298 lines) - AES substitution layer
4. **MixColumns.v** (111 lines) - AES diffusion layer
5. **AES_Controller.v** (120 lines) - AES state machine
6. **ShiftRows.v** (55 lines) - AES row shifts
7. **Shift_Rows.v** (26 lines) - Duplicate module
8. **TRNG_DF_DRBG.v** (371 lines) - Full DRBG wrapper
9. **MMIO_TRNG.v** (18 lines) - Old MMIO interface
10. **FF_D.v** (17 lines) - Flip-flop (can use standard)

### Files to KEEP (450 lines):
1. **TopTRNG.v** (30 lines) - Core entropy source
2. **LFSR_64.v** (328 lines) - Entropy conditioning
3. **ringOsc.v** (72 lines) - Ring oscillator
4. **TRNG.v** (91 lines) - Can adapt or replace with SimpleTRNG.v

### New File (150 lines):
1. **SimpleTRNG.v** - Direct 256-bit collection with simple FSM

## Resource Savings (Estimated)

### FPGA Resources:
| Component | Current | Simplified | Savings |
|-----------|---------|------------|---------|
| LUTs | ~2500 | ~600 | 76% |
| Registers | ~800 | ~350 | 56% |
| Block RAM | 0 | 0 | 0% |

### AES-256 Removal:
- **10 AES rounds**: ~200 LUTs/round = 2000 LUTs saved
- **Key expansion**: ~300 LUTs saved
- **Controllers**: ~200 LUTs saved

### Timing/Performance:
| Metric | Current | Simplified | Improvement |
|--------|---------|------------|-------------|
| Latency | ~50k cycles | ~8k cycles | 6x faster |
| Throughput | 128 bits/50k cycles | 256 bits/8k cycles | 10x faster |
| Clock constraint | Complex paths | Simple paths | Better timing closure |

## Security Considerations

### Current DRBG (NIST SP 800-90A):
- ✅ Cryptographically secure (AES-256-CTR)
- ✅ Forward/backward prediction resistance
- ✅ Reseed capability
- ✅ FIPS 140-2 compliant
- ❌ Overkill for ephemeral keys
- ❌ High latency

### Simplified TRNG:
- ✅ Direct hardware entropy (ring oscillator)
- ✅ LFSR conditioning (removes bias)
- ✅ Sufficient for ephemeral/session keys
- ✅ Low latency
- ⚠️ Not NIST compliant (if required)
- ⚠️ Raw entropy (no post-processing)

### Use Case Analysis:
For **ephemeral key generation** (one-time session keys):
- ✅ Raw TRNG is **sufficient** (256 bits of hardware entropy)
- ✅ Keys used once and discarded (no long-term prediction risk)
- ✅ Ring oscillator provides true randomness
- ✅ LFSR removes metastability/bias

For **long-term keys** or **FIPS compliance**:
- ❌ Keep full DRBG with AES post-processing
- ❌ Need reseed capability
- ❌ Need prediction resistance guarantees

## Recommendation

### For Ephemeral Keys: Use SimpleTRNG
**Rationale:**
- You only need 256 bits per key generation
- Keys are session-specific (not stored/reused)
- Direct hardware entropy is cryptographically sound
- 85% code reduction + 6x faster + simpler debug

**Implementation:**
```scala
// In DRBG.scala, change resources list:
addResource("/trng_vsrc/SimpleTRNG.v")
addResource("/trng_vsrc/TopTRNG.v")
addResource("/trng_vsrc/LFSR_64.v")
addResource("/trng_vsrc/ringOsc.v")
addResource("/trng_vsrc/FF_D.v")
// Remove all AES and DRBG resources
```

### MMIO Interface
Simple register map for SimpleTRNG:
```
0x00: Status register [0] = ready flag
0x04: Data[31:0]     - bits [31:0]
0x08: Data[63:32]    - bits [63:32]
0x0C: Data[95:64]    - bits [95:64]
0x10: Data[127:96]   - bits [127:96]
0x14: Data[159:128]  - bits [159:128]
0x18: Data[191:160]  - bits [191:160]
0x1C: Data[223:192]  - bits [223:192]
0x20: Data[255:224]  - bits [255:224]
0x24: Control [0] = restart generation
```

Software usage:
```c
// Wait for entropy ready
while (!(*(volatile uint32_t*)(TRNG_BASE + 0x00) & 0x1));

// Read 256-bit key
uint32_t key[8];
for (int i = 0; i < 8; i++) {
    key[i] = *(volatile uint32_t*)(TRNG_BASE + 0x04 + i*4);
}

// Restart for next key
*(volatile uint32_t*)(TRNG_BASE + 0x24) = 0x1;
```

## Next Steps

1. **Validate SimpleTRNG.v** - Review the provided module
2. **Create new MMIO wrapper** - Replace MMIO_TRNG.v with 256-bit interface
3. **Update DRBG.scala** - Change resource list to simplified modules
4. **Test entropy quality** - Run NIST randomness tests if needed
5. **Measure resource usage** - Compare LUT/FF usage before/after
6. **Update software drivers** - Adapt to new register map

Would you like me to create the complete simplified design with the MMIO wrapper?
