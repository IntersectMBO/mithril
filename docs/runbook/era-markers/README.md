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

#### Era markers formats

The era markers exist in two formats, both signed with the era markers secret key:

| Format  | Signed content                    | Read by                                                        | Created with                 |
| ------- | --------------------------------- | -------------------------------------------------------------- | ---------------------------- |
| Current | The markers and a sequence number | The nodes that support the sequence number                     | `--sequence-number <NUMBER>` |
| Legacy  | The markers alone                 | The nodes that do not support the sequence number (deprecated) | `--legacy`                   |

A node that supports the sequence number only reads the era markers in the current format: it selects the era markers with the highest sequence number among the datums with a valid signature, and ignores the legacy era markers.
A node that does not support the sequence number discards the era markers in the current format and only reads the legacy ones.

> [!IMPORTANT]
> :fire: Until all the aggregators and signers of the network run a version that supports the sequence number (the deprecation window), every creation or update of the era markers must store **two datums** with the same markers: one in the current format and one in the legacy format.
> If only one of them is updated, the nodes that read the other one keep the previous era markers and diverge from the rest of the network.

> [!IMPORTANT]
> :fire: On a network that only has legacy era markers on chain, the era markers in the current format (with the same markers) must be stored on chain **before** the first node is upgraded to a version that supports the sequence number: such a node reads no era markers at all (and stops) when no datum in the current format is stored at the address.

The deprecation window of a network ends when all its aggregators (leader and followers) and all its signers (see the signer versions reported by its aggregator) run a version that supports the sequence number, so that no node needs the legacy era markers anymore.
The legacy datum is then removed as explained in this [section](#end-of-the-deprecation-window-remove-the-legacy-datum).

#### Set the sequence number

The sequence number must be strictly greater than the sequence number of the last era markers signed for the network.

> [!WARNING]
> :fire: The sequence number must come from the last era markers datum file that **you** created (`mithril-era-datum.json`, to keep with the era markers keys), never from a datum read on chain alone: anyone can pay a datum with an arbitrary sequence number and no valid signature to the address.
> Signing a sequence number close to the maximum value (`18446744073709551615`) would leave no higher sequence number for the next update, which could then only be done with a new era markers keypair deployed on all the nodes.

Retrieve the sequence number of the last era markers datum file created for the network:

```bash
cat **PATH_TO_THE_LAST_ERA_DATUM_FILE** | jq -r '.fields[].bytes' | tr '\n' ' ' | xxd -r -p | jq '.sequence_number'
```

A sequence number that was signed is never reused nor lowered, even if the datum file was not stored on chain: a signed datum file is either stored on chain or kept with the era markers keys.

Set the sequence number to this value plus one (or to `1` if no era markers in the current format were created for the network yet):

```bash
export ERA_MARKERS_SEQUENCE_NUMBER=**NEXT_SEQUENCE_NUMBER**
```

As a cross check only, list the era markers datums currently stored on chain with the output (`{TxHash}#{TxIn}`) that holds each of them (a legacy datum has no sequence number, and the signatures are **not** verified by this command):

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH --out-file temp.json
jq -r 'to_entries[] | select(.value.inlineDatum | . != null and . != "") | "\(.key) \([.value.inlineDatum.fields[]? | .bytes? // empty] | join(""))"' temp.json | while read -r DATUM_TX_IN ERA_MARKERS_PAYLOAD; do
  echo "$DATUM_TX_IN $(echo $ERA_MARKERS_PAYLOAD | xxd -r -p | jq -c '{sequence_number: (.sequence_number // "legacy"), markers: .markers}')"
done
```

An example output of the command is:

```bash
6518b3cea0b49b55746ec61148e7c60ab042959d534f6bb6e8f6a844d4af69fb#0 {"sequence_number":1,"markers":[{"name":"pythagoras","epoch":1},{"name":"lagrange","epoch":null}]}
6518b3cea0b49b55746ec61148e7c60ab042959d534f6bb6e8f6a844d4af69fb#1 {"sequence_number":"legacy","markers":[{"name":"pythagoras","epoch":1},{"name":"lagrange","epoch":null}]}
```

The highest sequence number listed is expected to be the one of your last era markers datum file. If a datum that you did not create is listed, do not reuse its sequence number: spend its output in the update transaction, see this [section](#react-to-several-era-markers-datums-at-the-address).

#### If there is only one supported era

Set the epoch at which the era is active:

```bash
export CURRENT_ERA_EPOCH=**ERA_FIRST_ACTIVATION_EPOCH**
```

Create the datum file for a unique era:

```bash
./mithril-aggregator era generate-tx-datum --current-era-epoch $CURRENT_ERA_EPOCH --sequence-number $ERA_MARKERS_SEQUENCE_NUMBER --era-markers-secret-key $ERA_ACTIVATION_SECRET_KEY --target-path $ASSETS_PATH/mithril-era-datum.json
```

During the deprecation window, also create the legacy datum file for a unique era:

```bash
./mithril-aggregator era generate-tx-datum --current-era-epoch $CURRENT_ERA_EPOCH --legacy --era-markers-secret-key $ERA_ACTIVATION_SECRET_KEY --target-path $ASSETS_PATH/mithril-era-legacy-datum.json
```

#### If there are two supported eras

Set the epoch at which the current era and the next era are active (the `CURRENT_ERA_EPOCH` must be lower than the current epoch and the `NEXT_ERA_EPOCH` must be set to a strictly greater epoch than the current epoch):

```bash
export CURRENT_ERA_EPOCH=**CURRENT_ERA_FIRST_ACTIVATION_EPOCH**
export NEXT_ERA_EPOCH=**NEXT_ERA_FIRST_ACTIVATION_EPOCH**
```

Create the datum file for two eras:

```bash
./mithril-aggregator era generate-tx-datum --current-era-epoch $CURRENT_ERA_EPOCH --next-era-epoch $NEXT_ERA_EPOCH --sequence-number $ERA_MARKERS_SEQUENCE_NUMBER --era-markers-secret-key $ERA_ACTIVATION_SECRET_KEY --target-path $ASSETS_PATH/mithril-era-datum.json
```

During the deprecation window, also create the legacy datum file for two eras:

```bash
./mithril-aggregator era generate-tx-datum --current-era-epoch $CURRENT_ERA_EPOCH --next-era-epoch $NEXT_ERA_EPOCH --legacy --era-markers-secret-key $ERA_ACTIVATION_SECRET_KEY --target-path $ASSETS_PATH/mithril-era-legacy-datum.json
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
      "name": "pythagoras",
      "epoch": 1
    },
    {
      "name": "lagrange",
      "epoch": 123
    }
  ],
  "sequence_number": 2,
  "signature": "a66ebf71aa7b63a0fd9ba5421b23364bcafe749caa305cb70e2222bac4caabd6e4b4ef6ca4b048f059b6f4eab2df62d46e63149e7425805779663600ee26ee04"
}
```

During the deprecation window, verify the legacy era markers the same way: they must hold the same markers, and no sequence number.

```bash
cat $ASSETS_PATH/mithril-era-legacy-datum.json| jq -r '.fields[].bytes' | tr '\n' ' ' | xxd -r -p | jq
```

#### Compute the transaction amount

Compute the minimum amount of the transaction output holding the datum, which depends on the size of the datum:

```bash
$CARDANO_CLI $CARDANO_ERA query protocol-parameters $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH --out-file $ASSETS_PATH/protocol-parameters.json
export SCRIPT_TX_VALUE=$($CARDANO_CLI $CARDANO_ERA transaction calculate-min-required-utxo \
    --protocol-params-file $ASSETS_PATH/protocol-parameters.json \
    --tx-out "$(cat $CARDANO_WALLET_PATH/payment.addr)+0" \
    --tx-out-inline-datum-file $ASSETS_PATH/mithril-era-datum.json | awk '{print $2}')
echo $SCRIPT_TX_VALUE
```

During the deprecation window, also compute the minimum amount of the transaction output holding the legacy datum:

```bash
export LEGACY_SCRIPT_TX_VALUE=$($CARDANO_CLI $CARDANO_ERA transaction calculate-min-required-utxo \
    --protocol-params-file $ASSETS_PATH/protocol-parameters.json \
    --tx-out "$(cat $CARDANO_WALLET_PATH/payment.addr)+0" \
    --tx-out-inline-datum-file $ASSETS_PATH/mithril-era-legacy-datum.json | awk '{print $2}')
echo $LEGACY_SCRIPT_TX_VALUE
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

- If all the nodes of the network support the sequence number

```bash
$CARDANO_CLI $CARDANO_ERA transaction build $CARDANO_NETWORK_MAGIC \
    --tx-in $TX_IN \
    --tx-out $(cat $CARDANO_WALLET_PATH/payment.addr)+$SCRIPT_TX_VALUE \
    --tx-out-inline-datum-file $ASSETS_PATH/mithril-era-datum.json \
    --change-address $(cat $CARDANO_WALLET_PATH/payment.addr) \
    --out-file $ASSETS_PATH/tx.raw \
    --socket-path $CARDANO_NODE_SOCKET_PATH
```

- If this is during the deprecation window (the legacy datum is stored in a second output)

```bash
$CARDANO_CLI $CARDANO_ERA transaction build $CARDANO_NETWORK_MAGIC \
    --tx-in $TX_IN \
    --tx-out $(cat $CARDANO_WALLET_PATH/payment.addr)+$SCRIPT_TX_VALUE \
    --tx-out-inline-datum-file $ASSETS_PATH/mithril-era-datum.json \
    --tx-out $(cat $CARDANO_WALLET_PATH/payment.addr)+$LEGACY_SCRIPT_TX_VALUE \
    --tx-out-inline-datum-file $ASSETS_PATH/mithril-era-legacy-datum.json \
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

The parsed era markers json representation of each datum:

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH --out-file temp.json
jq -r '.[] | select(.inlineDatum | . != null and . != "") | [.inlineDatum.fields[]? | .bytes? // empty] | join("")' temp.json | while read -r ERA_MARKERS_PAYLOAD; do
  echo $ERA_MARKERS_PAYLOAD | xxd -r -p | jq
done
```

```json
{
  "markers": [
    {
      "name": "pythagoras",
      "epoch": 1
    },
    {
      "name": "lagrange",
      "epoch": null
    }
  ],
  "sequence_number": 1,
  "signature": "d9ea5eab66828c78eb4d27e3e46542f0223269f8f2cb39c3ecf42310bccbc959feb7123420284c17d4b18b56436d098820c58df3daf2bfd581fd4fe6d1cdc20b"
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

During the deprecation window, two outputs hold an inline datum. Identify the output that holds each datum with the cross check [command](#set-the-sequence-number), for example:

```bash
6518b3cea0b49b55746ec61148e7c60ab042959d534f6bb6e8f6a844d4af69fb#0 {"sequence_number":1,"markers":[{"name":"pythagoras","epoch":1},{"name":"lagrange","epoch":null}]}
6518b3cea0b49b55746ec61148e7c60ab042959d534f6bb6e8f6a844d4af69fb#1 {"sequence_number":"legacy","markers":[{"name":"pythagoras","epoch":1},{"name":"lagrange","epoch":null}]}
```

And create the three variables instead (the datum with a sequence number, the legacy datum and an output without inline datum):

```bash
TX_IN_DATUM=6518b3cea0b49b55746ec61148e7c60ab042959d534f6bb6e8f6a844d4af69fb#0
TX_IN_LEGACY_DATUM=6518b3cea0b49b55746ec61148e7c60ab042959d534f6bb6e8f6a844d4af69fb#1
TX_IN_NO_DATUM=6518b3cea0b49b55746ec61148e7c60ab042959d534f6bb6e8f6a844d4af69fb#2
```

> [!IMPORTANT]
> :fire: All the outputs holding a previous era markers datum must be spent by the update transaction (one `--tx-in` option per output), otherwise several era markers datums coexist at the address, see this [section](#react-to-several-era-markers-datums-at-the-address). The only exception is a [key rotation](#recover-with-a-new-era-markers-key) in progress.

Now create the update transaction with datum:

- If all the nodes of the network support the sequence number and no legacy datum is stored on chain

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

- If this is during the deprecation window (both datums are spent and stored again)

```bash
$CARDANO_CLI $CARDANO_ERA transaction build $CARDANO_NETWORK_MAGIC \
    --tx-in $TX_IN_DATUM \
    --tx-in $TX_IN_LEGACY_DATUM \
    --tx-in $TX_IN_NO_DATUM \
    --tx-out $(cat $CARDANO_WALLET_PATH/payment.addr)+$SCRIPT_TX_VALUE \
    --tx-out-inline-datum-file $ASSETS_PATH/mithril-era-datum.json \
    --tx-out $(cat $CARDANO_WALLET_PATH/payment.addr)+$LEGACY_SCRIPT_TX_VALUE \
    --tx-out-inline-datum-file $ASSETS_PATH/mithril-era-legacy-datum.json \
    --change-address $(cat $CARDANO_WALLET_PATH/payment.addr) \
    --out-file $ASSETS_PATH/tx.raw \
    --socket-path $CARDANO_NODE_SOCKET_PATH
```

- If this is the first update with a sequence number of a network that only has a legacy datum on chain, use the command of the deprecation window without the `--tx-in $TX_IN_LEGACY_DATUM` line (`TX_IN_DATUM` is then the output holding the legacy datum).

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

The parsed era markers json representation of each datum:

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH --out-file temp.json
jq -r '.[] | select(.inlineDatum | . != null and . != "") | [.inlineDatum.fields[]? | .bytes? // empty] | join("")' temp.json | while read -r ERA_MARKERS_PAYLOAD; do
  echo $ERA_MARKERS_PAYLOAD | xxd -r -p | jq
done
```

```json
{
  "markers": [
    {
      "name": "pythagoras",
      "epoch": 1
    },
    {
      "name": "lagrange",
      "epoch": 123
    }
  ],
  "sequence_number": 2,
  "signature": "a66ebf71aa7b63a0fd9ba5421b23364bcafe749caa305cb70e2222bac4caabd6e4b4ef6ca4b048f059b6f4eab2df62d46e63149e7425805779663600ee26ee04"
}
```

## End of the deprecation window: remove the legacy datum

> [!IMPORTANT]
> :fire: This step must be done only when all the aggregators and signers of the network run a version that supports the sequence number: the nodes that do not support it read no era markers anymore once the legacy datum is removed.

Follow the [update](#update-era-markers-write-a-new-version-of-datum-on-chain) process with these differences:

- Increment the sequence number and create the datum file in the current format only (no `--legacy` datum file).
- Spend the outputs holding the current and the legacy datums, and store the new datum only:

```bash
$CARDANO_CLI $CARDANO_ERA transaction build $CARDANO_NETWORK_MAGIC \
    --tx-in $TX_IN_DATUM \
    --tx-in $TX_IN_LEGACY_DATUM \
    --tx-in $TX_IN_NO_DATUM \
    --tx-out $(cat $CARDANO_WALLET_PATH/payment.addr)+$SCRIPT_TX_VALUE \
    --tx-out-inline-datum-file $ASSETS_PATH/mithril-era-datum.json \
    --change-address $(cat $CARDANO_WALLET_PATH/payment.addr) \
    --out-file $ASSETS_PATH/tx.raw \
    --socket-path $CARDANO_NODE_SOCKET_PATH
```

Then sign and submit the transaction, and verify with this [command](#set-the-sequence-number) that a single era markers datum with a sequence number is stored on chain.

## Troubleshooting

### React to several era markers datums at the address

The nodes that support the sequence number log the warning `Several era markers datums with a valid signature coexist` when several datums in the current format with a valid signature coexist, with:

- The address (`address`).
- The count of datums stored at the address, whether they are valid or not (`datums_count`).
- The count of datums in the current format with a valid signature (`valid_datums_count`).
- The selected sequence number (`selected_sequence_number`), the count of datums that share it (`datums_with_selected_sequence_number_count`) and the selected era markers (`selected_markers`).

A `datums_count` greater than the `valid_datums_count` is expected during the deprecation window (the legacy datum is not counted as valid). Beyond that, it means that datums which are not era markers signed with the era markers key are also stored at the address.
A `datums_with_selected_sequence_number_count` greater than `1` means that the same era markers are stored several times with the selected sequence number.

When different era markers are signed with the same highest sequence number, the nodes do not select any of them: they fail to read the era markers with the error `different era markers share the highest sequence number`.

> [!IMPORTANT]
> :fire: The aggregators and the signers that fail to read the era markers stop (at startup, and at the next epoch transition when they are running), and they can not be restarted until new era markers with a higher sequence number are stored.
> Store the new era markers before the next epoch transition whenever possible. The nodes that stopped must be restarted once the new era markers are stored, which requires a coordination with the SPOs whose signer is not restarted automatically.

List the era markers of each datum stored at the address with the cross check [command](#set-the-sequence-number).

The outputs holding an unexpected datum belong to the payment address: spend all of them, together with the outputs holding the current datums, in an [update](#update-era-markers-write-a-new-version-of-datum-on-chain) transaction (one `--tx-in` option per output), so that a single era markers datum of each format remains at the address.
The only exception is a key rotation in progress, during which datums signed with different keys are stored at the address on purpose (see this [section](#recover-with-a-new-era-markers-key)).

### Recover with a new era markers key

A new era markers keypair is needed when the era markers key must be replaced, or when no higher sequence number is available.

> [!IMPORTANT]
> :fire: The steps must be done in this order, as a node reads no era markers at all (and stops) when no datum is signed with the key it is configured with.
> From step 2 to step 4, the nodes that use the new key read the new era markers while the nodes that still use the previous key read the superseded ones. All the nodes must thus use the new key (step 3) **before the earliest activation epoch** of the next era in the new and in the superseded era markers, otherwise the nodes activate the next era at different epochs and the network is split.

1. Generate a new era markers keypair with the aggregator command `tools generate-keypair ed25519 --target-path <KEYPAIR_DIRECTORY>`.
2. Store the era markers signed with the new key in **additional** outputs:
   - Export the new secret key with `export ERA_ACTIVATION_SECRET_KEY=**YOUR_NEW_ERA_ACTIVATION_SECRET_KEY**`.
   - Create the datum files (the current format, and the legacy format during the deprecation window) and compute the transaction amounts again as described in the [Prepare era markers](#prepare-era-markers) section. The sequence number can start again at `1`, as the datums signed with the previous key are not valid for the new key.
   - Submit the [bootstrap](#bootstrap-era-markers-write-a-transaction-with-the-first-version-of-datum-on-chain) transaction, which does not spend the outputs holding the datums signed with the previous key (the "only once" warning of that section does not apply to a key rotation).
3. Deploy the new era markers verification key on all the aggregators and signers of every network configured with this era address and this verification key (several networks can share them), which requires a coordination with the SPOs: it is the `verification_key` of the `era_reader_adapter_params` configuration parameter of the nodes, published in the `mithril-infra/configuration/<NETWORK>/era.vkey` file of the repository.
4. Once all the nodes use the new key, spend the outputs holding the datums signed with the previous key, without storing a datum again. Create the variable `TX_IN_PREVIOUS_KEY_DATUM={TxHash}#{TxIn}` (the output holding the datum signed with the previous key, with one `--tx-in` option per output if there are several) and `TX_IN_NO_DATUM={TxHash}#{TxIn}` (an output without inline datum), then build the transaction:

```bash
$CARDANO_CLI $CARDANO_ERA transaction build $CARDANO_NETWORK_MAGIC \
    --tx-in $TX_IN_PREVIOUS_KEY_DATUM \
    --tx-in $TX_IN_NO_DATUM \
    --change-address $(cat $CARDANO_WALLET_PATH/payment.addr) \
    --out-file $ASSETS_PATH/tx.raw \
    --socket-path $CARDANO_NODE_SOCKET_PATH
```

Then sign and submit it as in the [update](#update-era-markers-write-a-new-version-of-datum-on-chain) process.

A node that is not migrated to the new key at step 3 keeps reading the superseded era markers (and activates the next era at their epoch) as long as the previous datums are stored at the address, then reads no era markers and stops once step 4 is done.
