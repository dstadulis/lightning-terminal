# setup for taproot asset channel testing on regtest

Two `litd` nodes, Zane and Yara.

## Zane

```text
--httpslisten=[::]:8443
--insecure-httplisten=[::]:8088
--uipassword=testnet3
--network=regtest
--enablerest
--restcors=*
--lnd-mode=integrated
--lnd.lnddir=/home/guggero/.lnd-dev-zane
--lnd.alias=zane
--lnd.noseedbackup
--lnd.rpclisten=0.0.0.0:10019
--lnd.listen=0.0.0.0:9749
--lnd.restlisten=0.0.0.0:8099
--lnd.externalip=127.0.0.1
--lnd.bitcoin.active
--lnd.bitcoin.node=bitcoind
--lnd.bitcoind.rpchost=localhost
--lnd.bitcoind.rpcuser=lightning
--lnd.bitcoind.rpcpass=lightning
--lnd.bitcoind.zmqpubrawblock=localhost:28332
--lnd.bitcoind.zmqpubrawtx=localhost:28333
--lnd.debuglevel=trace,SRVR=debug,PEER=warn,BTCN=warn,GRPC=error
--lnd.rpcmiddleware.enable
--lnd.protocol.option-scid-alias
--lnd.protocol.zero-conf
--lnd.protocol.simple-taproot-chans
--loop.server.host=[::]:11009
--loop.server.notls
--pool.auctionserver=localhost:12009
--pool.tlspathauctserver=/home/guggero/.auctionserver/tls.cert
--pool.fakeauth
--autopilot.disable
--taproot-assets.debuglevel=trace
--taproot-assets.universe.public-access
--taproot-assets.universerpccourier.initialbackoff=2s
--taproot-assets.universerpccourier.maxbackoff=30s
--taproot-assets.allow-public-uni-proof-courier
--taproot-assets.allow-public-stats
```

## Yara

```text
--httpslisten=[::]:8442
--uipassword=testnet3
--network=regtest
--enablerest
--restcors=*
--lit-dir=/home/guggero/.lit-yara
--lnd-mode=integrated
--lnd.lnddir=/home/guggero/.lnd-dev-yara
--lnd.alias=yara
--lnd.noseedbackup
--lnd.rpclisten=0.0.0.0:10018
--lnd.listen=0.0.0.0:9748
--lnd.restlisten=0.0.0.0:8098
--lnd.externalip=127.0.0.1
--lnd.bitcoin.active
--lnd.bitcoin.node=bitcoind
--lnd.bitcoind.rpchost=localhost
--lnd.bitcoind.rpcuser=lightning
--lnd.bitcoind.rpcpass=lightning
--lnd.bitcoind.zmqpubrawblock=localhost:28332
--lnd.bitcoind.zmqpubrawtx=localhost:28333
--lnd.debuglevel=trace,SRVR=debug,PEER=warn,BTCN=warn,GRPC=error
--lnd.rpcmiddleware.enable
--lnd.protocol.option-scid-alias
--lnd.protocol.zero-conf
--lnd.protocol.simple-taproot-chans
--loop.server.host=[::]:11009
--loop.server.notls
--pool.auctionserver=localhost:12009
--pool.tlspathauctserver=/home/guggero/.auctionserver/tls.cert
--pool.fakeauth
--autopilot.disable
--taproot-assets.debuglevel=trace
--taproot-assets.tapddir=/home/guggero/.tapd-bob
--taproot-assets.rpclisten=10032
--taproot-assets.restlisten=8090
--taproot-assets.universe.public-access
--taproot-assets.universerpccourier.initialbackoff=2s
--taproot-assets.universerpccourier.maxbackoff=30s
--taproot-assets.allow-public-uni-proof-courier
--taproot-assets.allow-public-stats
--taproot-assets.universe.federationserver=localhost:8443
--taproot-assets.universe.syncinterval=60m
```

## Shell commands / aliases

```shell
function reg_zane () { 
    lncli --lnddir "$HOME"/.lnd-dev-zane --network regtest --rpcserver localhost:10019 "$@"
}

function fundzane () { 
    ADDR_ZANE=$(reg_zane newaddress p2wkh | jq .address -r);
    echo "sending funds to zane..";
    reg_bitcoin sendtoaddress "$ADDR_ZANE" 1;
    mine
}

function lit_tap() {
  tapcli --network regtest --tapddir "$HOME"/.tapd --tlscertpath "$HOME"/.lnd-dev-zane/tls.cert --rpcserver localhost:10019 "$@"
}

function lit_tap_yara() {
  tapcli --network regtest --macaroonpath "$HOME"/.tapd-bob/data/regtest/admin.macaroon --tlscertpath "$HOME"/.lnd-dev-yara/tls.cert --rpcserver localhost:10018 "$@"
}

function lit_zane() {
  litcli --tlscertpath "$HOME"/.lnd-dev-zane/tls.cert --macaroonpath "$HOME"/.lnd-dev-zane/data/chain/bitcoin/regtest/admin.macaroon --rpcserver localhost:10019 "$@"
}

function lit_yara() {
  litcli --tlscertpath "$HOME"/.lnd-dev-yara/tls.cert --macaroonpath "$HOME"/.lnd-dev-yara/data/chain/bitcoin/regtest/admin.macaroon --rpcserver localhost:10018 "$@"
}

function preptapchannel() {
  fundzane
  YARA=$(reg_yara getinfo | jq .identity_pubkey -r)
  reg_zane connect $YARA@172.17.0.1:9748
  lit_tap assets mint --type normal --name lnbuxx --supply 21000000
  lit_tap assets mint finalize
  regtest mine 1
  sleep 1
  lit_tap_yara u s --universe_host localhost:8443
  sleep 1
  lit_tap_yara u r
}

function fundtapchannel() {
  YARA=$(reg_yara getinfo | jq .identity_pubkey -r)
  reg_zane connect $YARA@172.17.0.1:9748
  ASSETID=$(lit_tap a l | jq -r '.assets[0].asset_genesis.asset_id')
  lit_zane ln fundchannel --node_key $YARA --sat_per_vbyte 2 --asset_id $ASSETID --asset_amount 1000
}

```