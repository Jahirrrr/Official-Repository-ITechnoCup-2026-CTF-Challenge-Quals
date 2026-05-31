# Planetarium Writeup

## Bug

The important logic bug is in `m.del <map> @@hole`. If the map contains more
than half of its bucket count and the internal `@@hole` key is deleted,
`PlanetMap.live` is decremented by `buckets + 7`, so it becomes negative.

`o.new <stub> <map> <array>` treats a negative map size as an optimized
condition and caches an unsafe array access stub. `o.read` and `o.write` then
skip the JavaScript array length check, producing forward OOB access from the
array's fixed-double elements.

## Exploit Chain

1. Build a negative map size with 5 normal keys plus `@@hole` in an 8-bucket map.
2. Allocate a small array, then allocate an `ArrayBuffer` after it.
3. Create an optimized stub using the corrupted map.
4. Use OOB reads to find the `ArrayBuffer` header (`0x414255465f4d4150`).
5. OOB-write the buffer's `byte_length` to `0x20000` and `backing_store` to `0`.
6. `dv.read` and `dv.write` are now arbitrary sandbox read/write.
7. Scan the sandbox for the isolate magic (`0x49534f4c41544550`) and TPT magic
   (`0x5450545f53544152`), then leak the runtime cookie from the isolate.
8. Forge a bytecode object at an aligned scratch address.
9. Compute the same tag/checksum as the binary.
10. Redirect TPT slot 0 to the fake bytecode.
11. `fn.call <function>` executes `CALL_NATIVE(0x1337)` with the required token
    and prints the flag.