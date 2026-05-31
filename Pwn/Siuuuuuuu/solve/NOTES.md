# Siuuuuuuu

Intended route:

1. Drive the shop state machine into the ready-to-pack path.
2. Use the receipt printer truncation bug as an OOB read to leak the sealed completion callback plus pointer-mangling values.
3. Decode the callback to recover the PIE base.
4. Use the gift-box packing truncation bug as an OOB write to replace the sealed callback and forge the ticket checked by the hidden completion path.

Shop-to-CVE mapping:

- cashier terminal -> AF_ALG socket setup
- catalog shelf -> algorithm bind
- price rule / loyalty blob -> key schedule gates
- order note -> sendmsg ancillary-data gates
- gift-box packing -> zero-copy write path
- receipt printer -> copy-to-user read path