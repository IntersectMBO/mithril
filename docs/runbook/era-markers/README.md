# Store Mithril Era Markers On Chain

**This is a work in progress** :hammer_and_wrench:

This is the process for storing Mithril activation eras markers on the Cardano chain (bootstrap and update operations).

> [!IMPORTANT]
> :fire: The process described in this document can lead to disturbed service of the associated Mihtril network. Thus it should be manipulated by experts only.

## Pre-requisites

- You need to have a recent version of [`jq`](https://stedolan.github.io/jq/download/) running (1.6+)
- A running Cardano node running locally on the network you are targeting
- A running Mithril Aggregator node
- The era activation marker Cardano payment keypairs of your Mithril network
- The era activation marker secret key of your Mithril network (you can generate one by running the aggregator command `tools generate-keypair ed25519 --target-path <KEYPAIR_DIRECTORY>` if none exists for the target environment)

## Setup

### Setup environment variables

Export the environment variables needed to complete the process:

```bash
export CARDANO_CLI=**CARDANO_CLI_COMMAND**
export CARDANO_NODE_SOCKET_PATH=**PATH_TO_YOUR_NODE_SOCKET**
export CARDANO_WALLET_PATH=**PATH_TO_YOUR_KEYPAIRS**
export ERA_ACTIVATION_SECRET_KEY=**YOUR_ERA_ACTIVATION_SECRET_KEY**
export ASSETS_PATH=**YOUR_ASSETS_PATH**
export SCRIPT_TX_VALUE=**MINIUM_SCRIPT_TX_VALUE**
```

A common value for the transaction amount used when a script transaction is made is:

```bash
export SCRIPT_TX_VALUE=2100000
```

Compute the network magic parameter that handles both the Cardano mainnet and Cardano test networks:

- If this is for a testing network

```bash
export CARDANO_TESTNET_MAGIC=**YOUR_TESTNET_MAGIC**
export CARDANO_NETWORK_MAGIC="--testnet-magic $CARDANO_TESTNET_MAGIC"
```

- If this is for the `mainnet`

```bash
export CARDANO_NETWORK_MAGIC="--mainnet"
```

Compute the current Cardano era:

```bash
export CARDANO_ERA=$($CARDANO_CLI query tip $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH | jq  -r '.era |= ascii_downcase | .era')
```

### Prepare era markers

> [!IMPORTANT]
> :fire: A misconfiguration of the era markers can cause disturbed service on a Mithril network. The `CURRENT_ERA_EPOCH` and `NEXT_ERA_EPOCH` must be selected very cautiously.

#### If there is only one supported era

Set the epoch at which the era is active:

```bash
export CURRENT_ERA_EPOCH=**ERA_FIRST_ACTIVATION_EPOCH**
```

Create the datum file for a unique era:

```bash
./mithril-aggregator era generate-tx-datum --current-era-epoch $CURRENT_ERA_EPOCH --era-markers-secret-key $ERA_ACTIVATION_SECRET_KEY --target-path $ASSETS_PATH/mithril-era-datum.json
```

#### If there are two supported eras

Set the epoch at which the current era and the next era are active (the `CURRENT_ERA_EPOCH` must be lower than the current epoch and the `NEXT_ERA_EPOCH` must be set to a strictly greater epoch than the current epoch):

```bash
export CURRENT_ERA_EPOCH=**CURRENT_ERA_FIRST_ACTIVATION_EPOCH**
export NEXT_ERA_EPOCH=**NEXT_ERA_FIRST_ACTIVATION_EPOCH**
```

Create the datum file for two eras:

```bash
./mithril-aggregator era generate-tx-datum --current-era-epoch $CURRENT_ERA_EPOCH --next-era-epoch $NEXT_ERA_EPOCH --era-markers-secret-key $ERA_ACTIVATION_SECRET_KEY --target-path $ASSETS_PATH/mithril-era-datum.json
```

#### Verify the produced era marker

> [!IMPORTANT]
> :fire: The `mithril-aggregator` binary used to create the era markers must imperatively be compiled with all the targeted supported eras.

Verify that the produced era markers are exactly what is expected with the following command:

```bash
cat $ASSETS_PATH/mithril-era-datum.json| jq -r '.fields[].bytes' | tr '\n' ' ' | xxd -r -p | jq
```

An example output of the command is:

```json
{
  "markers": [
    {
      "name": "thales",
      "epoch": 1
    },
    {
      "name": "pythagoras",
      "epoch": 723
    }
  ],
  "signature": "fdcd45debabc148ef11c0bf71e42b7e583102dd5b8e486cd621a18e56136a57ff4f7bf9d036aed6148328a30a20eb6e79422ea4d1cc613e0bf97e14da64a5f00"
}
```

## Bootstrap Era Markers: Write a transaction with the first version of datum on chain

> [!IMPORTANT]
> :fire: This step must be done only once for an address when no prior datum has been written in a UTxO.
> Otherwise, you need to refer to this [section](#update-era-markers-write-a-new-version-of-datum-on-chain)

Verify that the payment address has funds:

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH
```

```bash
                           TxHash                                 TxIx        Amount
--------------------------------------------------------------------------------------
f0c0345f151f9365fbbb4e7afa217e56b987d9e91fd754ca609d9dfec97275c7     0        10000000000 lovelace + TxOutDatumNone
```

And create the variable `TX_IN={TxHash}#{TxIn}` by replacing with values from the previous command:

```bash
TX_IN=f0c0345f151f9365fbbb4e7afa217e56b987d9e91fd754ca609d9dfec97275c7#0
```

Now create the bootstrap transaction with datum:

```bash
$CARDANO_CLI $CARDANO_ERA transaction build $CARDANO_NETWORK_MAGIC \
    --tx-in $TX_IN \
    --tx-out $(cat $CARDANO_WALLET_PATH/payment.addr)+$SCRIPT_TX_VALUE \
    --tx-out-inline-datum-file $ASSETS_PATH/mithril-era-datum.json \
    --change-address $(cat $CARDANO_WALLET_PATH/payment.addr) \
    --out-file $ASSETS_PATH/tx.raw \
    --socket-path $CARDANO_NODE_SOCKET_PATH
```

```bash
Estimated transaction fee: Lovelace 168669
```

Then sign the transaction:

```bash
$CARDANO_CLI $CARDANO_ERA transaction sign \
    --tx-body-file $ASSETS_PATH/tx.raw \
    --signing-key-file $CARDANO_WALLET_PATH/payment.skey \
    $CARDANO_NETWORK_MAGIC \
    --out-file $ASSETS_PATH/tx.signed
```

And submit it:

```bash
$CARDANO_CLI $CARDANO_ERA transaction submit \
    $CARDANO_NETWORK_MAGIC \
    --tx-file $ASSETS_PATH/tx.signed \
    --socket-path $CARDANO_NODE_SOCKET_PATH
```

```bash
Transaction successfully submitted.
```

Also get the transaction id:

```bash
$CARDANO_CLI $CARDANO_ERA transaction txid --tx-file $ASSETS_PATH/tx.signed
```

```bash
6518b3cea0b49b55746ec61148e7c60ab042959d534f6bb6e8f6a844d4af69fb
```

We need to wait a few seconds before the transaction is available and we can see the initial datum for the script address:

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH
```

```bash
                           TxHash                                 TxIx        Amount
--------------------------------------------------------------------------------------
6518b3cea0b49b55746ec61148e7c60ab042959d534f6bb6e8f6a844d4af69fb     0        1500000 lovelace + TxOutDatumInline ReferenceTxInsScriptsInlineDatumsInBabbageEra (ScriptDataConstructor 0 [ScriptDataBytes "[{\"n\":\"thales\",\"e\":1}]",ScriptDataBytes "\165\143\232\227\&6\244e\222\211\187\167\197\167\175\229\181\162o/\182[|Nnt.h\ACKE\241=\242\139\242\182:a\204r\217\200&\190I\SO,\US\DLE\152\217U\223P5\128\164\232\153\181\ETB8\132\227\SO"])
6518b3cea0b49b55746ec61148e7c60ab042959d534f6bb6e8f6a844d4af69fb     1        9998327415 lovelace + TxOutDatumNone
```

Optional: We can retrieve the initial value stored in the datum with the cardano cli:

The full utxo json representation:

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH --out-file temp.json && cat temp.json | jq '.[] | select(.inlineDatum | . != null and . != "")'
```

```bash
{
  "address": "addr_test1qzzngukkj9ydjemqjlgfn42sevy2xnvauay46weushlpuq9thd4ray00csjssf4sxftv04xeequ3xfx72nujg9y4d5ysgkxxlh",
  "datum": null,
  "inlineDatum": {
    "constructor": 0,
    "fields": [
      {
        "bytes": "5b7b226e223a227468616c6573222c2265223a317d5d"
      },
      {
        "bytes": "a58fe8e336f465ded3bba7c5a7afe5b5a26f2fb65b7c4e6e742e680645f13df28bf2b63a61cc72d9c826be490e2c1f1098d955df503580a4e899b5173884e30e"
      }
    ]
  },
  "inlineDatumhash": "d8c1865816a520b92aa19ac5bc295fb1996281adf5ff06366343c6432d591cd1",
  "referenceScript": null,
  "value": {
    "lovelace": 1500000
  }
}
```

The parsed era markers json representation:

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH --out-file temp.json && cat temp.json | jq -r '.[] | select(.inlineDatum | . != null and . != "")| .inlineDatum.fields[].bytes' | tr '\n' ' ' | xxd -r -p | jq
```

```json
{
  "markers": [
    {
      "name": "thales",
      "epoch": 1
    },
    {
      "name": "pythagoras",
      "epoch": null
    }
  ],
  "signature": "a83a8dee3b875a7e8d259500a8ce14cc73587ef838899d269ad58aadd16086cfe0486528e54b841b3a1d5aa8b7176d55c0803337ca59fbd3654b2bdd5a480d05"
}
```

## Update Era Markers: Write a new version of datum on chain

> [!IMPORTANT]
> :fire: This step must be used anytime the era markers must be updated on chain for an address when prior datum has already been written in a UTxO.
> Otherwise, you need to refer to this [section](#bootstrap-era-markers-write-a-transaction-with-the-first-version-of-datum-on-chain)

Retrieve the utxo of the payment address:

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH
```

```bash
                           TxHash                                 TxIx        Amount
--------------------------------------------------------------------------------------
6518b3cea0b49b55746ec61148e7c60ab042959d534f6bb6e8f6a844d4af69fb     0        1500000 lovelace + TxOutDatumInline ReferenceTxInsScriptsInlineDatumsInBabbageEra (ScriptDataConstructor 0 [ScriptDataBytes "[{\"n\":\"thales\",\"e\":1}]",ScriptDataBytes "\165\143\232\227\&6\244e\222\211\187\167\197\167\175\229\181\162o/\182[|Nnt.h\ACKE\241=\242\139\242\182:a\204r\217\200&\190I\SO,\US\DLE\152\217U\223P5\128\164\232\153\181\ETB8\132\227\SO"])
6518b3cea0b49b55746ec61148e7c60ab042959d534f6bb6e8f6a844d4af69fb     1        9998327415 lovelace + TxOutDatumNone
```

And create the variable `TX_IN_DATUM={TxHash}#{TxIn}` by replacing with values from the previous command (where inline datumn are available):

```bash
TX_IN_DATUM=6518b3cea0b49b55746ec61148e7c60ab042959d534f6bb6e8f6a844d4af69fb#0
```

And create the variable `TX_IN_NO_DATUM={TxHash}#{TxIn}` by replacing with values from the previous command (where inline datumn are not available):

```bash
TX_IN_NO_DATUM=6518b3cea0b49b55746ec61148e7c60ab042959d534f6bb6e8f6a844d4af69fb#1
```

Now create the update transaction with datum:

```bash
$CARDANO_CLI $CARDANO_ERA transaction build $CARDANO_NETWORK_MAGIC \
    --tx-in $TX_IN_DATUM \
    --tx-in $TX_IN_NO_DATUM \
    --tx-out $(cat $CARDANO_WALLET_PATH/payment.addr)+$SCRIPT_TX_VALUE \
    --tx-out-inline-datum-file $ASSETS_PATH/mithril-era-datum.json \
    --change-address $(cat $CARDANO_WALLET_PATH/payment.addr) \
    --out-file $ASSETS_PATH/tx.raw \
    --socket-path $CARDANO_NODE_SOCKET_PATH
Estimated transaction fee: Lovelace 179889
```

Then sign the transaction:

```bash
$CARDANO_CLI $CARDANO_ERA transaction sign \
    --tx-body-file $ASSETS_PATH/tx.raw \
    --signing-key-file $CARDANO_WALLET_PATH/payment.skey \
    $CARDANO_NETWORK_MAGIC \
    --out-file $ASSETS_PATH/tx.signed
```

And submit it:

```bash
$CARDANO_CLI $CARDANO_ERA transaction submit \
    $CARDANO_NETWORK_MAGIC \
    --tx-file $ASSETS_PATH/tx.signed \
    --socket-path $CARDANO_NODE_SOCKET_PATH
Transaction successfully submitted.
```

Also get the transaction id:

```bash
$CARDANO_CLI $CARDANO_ERA transaction txid --tx-file $ASSETS_PATH/tx.signed
```

```bash
1fd4d3e131afe3c8b212772a3f3083d2fbc6b2a7b20e54e4ff08e001598818d8
```

We need to wait a few seconds before the transaction is available and we can see the updated datum for the script address:

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH
```

```bash
                           TxHash                                 TxIx        Amount
--------------------------------------------------------------------------------------
1f139b47017c9c90d4622ac768e249d25d37ad4461db44a20486b7da72a78915     0        2000000 lovelace + TxOutDatumInline ReferenceTxInsScriptsInlineDatumsInBabbageEra (ScriptDataConstructor 0 [ScriptDataBytes "[{\"n\":\"thales\",\"e\":1},{\"n\":\"pythagoras\",\"e\":null}]",ScriptDataBytes "^P\EOT\248k3\196/\139\tU\173H\138\FS\194MD\240\153\227\142z\181\134\213\168\&2\222\219i1\246\NAK\\]\247\154U\143-^vmtq\204\207#\236\213\f\201\&1\152\145(\161\ETX;\183\128\195\r"])
1f139b47017c9c90d4622ac768e249d25d37ad4461db44a20486b7da72a78915     1        9997647526 lovelace + TxOutDatumNone
```

We can retrieve the updated value stored in the datum with the cardano cli:

The full utxo json representation:

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH --out-file temp.json && cat temp.json | jq '.[] | select(.inlineDatum | . != null and . != "")'
```

```bash
{
  "address": "addr_test1qzzngukkj9ydjemqjlgfn42sevy2xnvauay46weushlpuq9thd4ray00csjssf4sxftv04xeequ3xfx72nujg9y4d5ysgkxxlh",
  "datum": null,
  "inlineDatum": {
    "constructor": 0,
    "fields": [
      {
        "bytes": "5b7b226e223a227468616c6573222c2265223a317d2c7b226e223a227079746861676f726173222c2265223a6e756c6c7d5d"
      },
      {
        "bytes": "5e5004f86b33c42f8b0955ad488a1cc24d44f099e38e7ab586d5a832dedb6931f6155c5df79a558f2d5e766d7471cccf23ecd50cc931989128a1033bb780c30d"
      }
    ]
  },
  "inlineDatumhash": "021310e8764d7d7ec3d66c00792ff391fa2145e1c8328eaf4630734c43bcfedc",
  "referenceScript": null,
  "value": {
    "lovelace": 2000000
  }
}
```

The parsed era markers json representation:

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH --out-file temp.json && cat temp.json | jq -r '.[] | select(.inlineDatum | . != null and . != "")| .inlineDatum.fields[].bytes' | tr '\n' ' ' | xxd -r -p | jq
```

```json
{
  "markers": [
    {
      "name": "thales",
      "epoch": 1
    },
    {
      "name": "pythagoras",
      "epoch": 123
    }
  ],
  "signature": "a83a8dee3b875a7e8d259500a8ce14cc73587ef838899d269ad58aadd16086cfe0486528e54b841b3a1d5aa8b7176d55c0803337ca59fbd3654b2bdd5a480d05"
}
```
