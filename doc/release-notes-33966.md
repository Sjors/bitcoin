Mining
------

- The IPC mining interface now rejects out-of-range block template options
  instead of silently clamping them, such as oversized reserved block weight or
  coinbase sigops limits. (#33966)
