Mining
------

- The IPC mining interface `BlockCreateOptions` now has an
  `alwaysAddCoinbaseCommitment` option. It defaults to `false`, so empty block
  templates and templates without SegWit spends no longer include a dummy
  coinbase witness and SegWit OP_RETURN. IPC clients that need the previous
  behavior can set this option to `true`. IPC clients should not set this
  option when connecting to previous Bitcoin Core releases, which do not
  understand it and use the previous behavior. (#34568)
