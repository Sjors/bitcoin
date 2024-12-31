# Various test vectors

## mainnet_alt.json

For easier testing the difficulty is maximally increased in the first (and only)
regarget period, by producing blocks approximately 2 minutes apart.

The alternate mainnet chain was generated as follows:
- use faketime to set node clock to 2 minutes after genesis block
- mine a block using a CPU miner such as https://github.com/pooler/cpuminer
- restart node with a faketime 2 minutes later

```sh
for i in {1..2015}
do
 faketime "`date -d @"$(( 1231006505 + $i * 120 ))"  +'%Y-%m-%d %H:%M:%S'`" \
 bitcoind -connect=0 -nocheckpoints -stopatheight=$i
done
```

The CPU miner is kept running as follows:

```sh
./minerd --coinbase-addr ... --no-stratum --algo sha256d --no-longpoll --scantime 3 --retry-pause 1
```

This makes each block determinisic except for its timestamp and nonce, which
are stored in data/mainnet_alt.json and used to reconstruct the chain without
having to redo the proof-of-work.

The timestamp was not kept constant because at difficulty 1 it's not sufficient
to only grind the nonce. Grinding the extra_nonce or version field instead
would have required additional (stratum) software. It would also make it more
complicated to reconstruct the blocks in this test.
