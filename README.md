# CVE-2025-24257

**IOGPUFamily bitmap_mask underflow — kernel heap OOB write**

First public PoC. Original discovery by [Wang Yu] of Cyberserval.

## Vulnerability

The IOGPUFamily kernel extension (`com.apple.IOGPU`) contains an integer underflow in `newResourceGroup()`:

```c
bitmap_mask = (capacity >> 6) - 1;
```

When `capacity < 64`, the right shift produces `0`, and the unsigned subtraction underflows to `0xFFFFFFFF`. This means the bitmap — allocated as 8 bytes — is treated as 32GB.

On connection close, the destructor iterates `bitmap[0..bitmap_mask]`, reading far past the allocation into unmapped kernel memory, causing a panic.

The same underflow also enables **OOB writes** during resource insertion: `bitmap[hash/64] |= bit` and `group_info[hash] |= bit` write single bits at attacker-controlled offsets into adjacent kernel heap objects.

## Impact

- **Type**: Kernel heap OOB read/write
- **Trigger**: 3 IOKit calls (open, create resource, close)
- **Entitlements**: None required
- **Sandbox**: Reachable from app sandbox
- **Result**: Kernel panic (DoS). OOB write primitive exists but exploitation is not demonstrated.

## Affected Versions

| Version | Status |
|---------|--------|
| iOS 18.3 (22D60) | VULNERABLE |
| iOS 18.4+ | FIXED |
| macOS (with Apple GPU) | Likely vulnerable (untested) |

## How to Use

1. Add `CVE_2025_24257.m` to an Xcode project targeting a **real device** (not simulator)
2. Link `IOKit.framework`
3. Call `trigger_CVE_2025_24257()` from your app
4. Device will kernel panic within milliseconds

```objc
// Example: call from viewDidLoad or a button action
extern void trigger_CVE_2025_24257(void);
trigger_CVE_2025_24257();
```

> **WARNING**: This will immediately crash your device. It will reboot.

## Technical Details

| Field | Value |
|-------|-------|
| Service | `IOGPU` |
| User client type | 1 |
| Selector | 9 (`s_new_resource`) |
| structIn size | 128 bytes |
| structIn[0] | 3 (resource group) |
| structIn[56] | 1 (capacity) |
| bitmap_mask | `0xFFFFFFFF` (underflow from `(1>>6)-1`) |
| Bitmap alloc | 8 bytes in `kalloc.type.var*.16` |
| Panic PC | `sub_FFFFFFF009863C7C` (bitmap iterator) |

## Panic Log Signature

```
panic: kernel data abort
FAR: 0xffffffe0XXXXXXXX   (unmapped, past zone page)
PC:  0xFFFFFFF009863C7C   (IOGPUFamily bitmap iterator)
x27: 1                    (capacity of vulnerable group)
```

## Root Cause (Pseudocode)

```c
void newResourceGroup(uint32_t capacity) {
    // BUG: no check for capacity < 64
    uint32_t bitmap_mask = (capacity >> 6) - 1;  // 0xFFFFFFFF when capacity < 64

    uint64_t *bitmap = kalloc(sizeof(uint64_t));  // 8 bytes
    // bitmap_mask says 4 billion qwords exist

    // Later, destructor does:
    for (uint32_t i = 0; i <= bitmap_mask; i++) {  // iterates 4 billion times
        if (bitmap[i]) { /* process entries */ }   // OOB read → panic
    }
}
```

## Fix

Apple fixed this in iOS 18.4 by adding a minimum capacity check, ensuring `capacity >= 64` before computing `bitmap_mask`.

## Credits

- **Vulnerability Discovery**: Wang Yu of Cyberserval
- **PoC Development**: CrazyMind90 (with Claude Code)

## Disclaimer

This PoC is provided for **defensive security research and education only**. The vulnerability is fully patched. Do not use this against devices you do not own. The author is not responsible for misuse.

## License

MIT
