# Store Mithril Protocol Configuration Markers On Chain

This is the process for storing Mithril Protocol Configuration markers on the Cardano chain (bootstrap and update operations).

> [!IMPORTANT]
> :fire: The process described in this document can lead to disturbed service of the associated Mithril network. Thus it should be manipulated by experts only.

## Prerequisites

- You need to have a recent version of [`jq`](https://stedolan.github.io/jq/download/) running (1.6+)
- A Cardano node running locally on the network you are targeting
- A running Mithril Aggregator node
- The protocol configuration activation marker Cardano payment keypairs of your Mithril network
- The protocol configuration secret key of your Mithril network

## Setup

### Setup environment variables

Export the environment variables needed to complete the process:

```bash
export CARDANO_CLI=**CARDANO_CLI_COMMAND**
export CARDANO_NODE_SOCKET_PATH=**PATH_TO_YOUR_NODE_SOCKET**
export CARDANO_WALLET_PATH=**PATH_TO_YOUR_KEYPAIRS**
export PROTOCOL_CONFIGURATION_MARKERS_SECRET_KEY=**YOUR_PROTOCOL_CONFIGURATION_MARKERS_SECRET_KEY**
export PROTOCOL_CONFIGURATION_READER_VERIFICATION_KEY=**YOUR_PROTOCOL_CONFIGURATION_READER_VERIFICATION_KEY**
export ASSETS_PATH=**YOUR_ASSETS_PATH**
export SCRIPT_TX_VALUE=**MINIMUM_SCRIPT_TX_VALUE**
export NETWORK=**YOUR_NETWORK**
export CHAIN_OBSERVER_TYPE=pallas
```

A common value for the transaction amount used when a script transaction is made is:

```bash
export SCRIPT_TX_VALUE=4600000
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

Compute the protocol configuration reader adapter config:

```bash
export PROTOCOL_CONFIGURATION_READER_ADDRESS=**YOUR_PROTOCOL_CONFIGURATION_READER_ADDRESS**
export PROTOCOL_CONFIGURATION_READER_ADAPTER_TYPE="cardano-chain"
export PROTOCOL_CONFIGURATION_READER_ADAPTER_CONFIG="{\"type\":\"$PROTOCOL_CONFIGURATION_READER_ADAPTER_TYPE\",\"address\":\"$PROTOCOL_CONFIGURATION_READER_ADDRESS\",\"verification_key\":\"$PROTOCOL_CONFIGURATION_READER_VERIFICATION_KEY\"}"
```

### Prepare protocol configuration markers

> [!IMPORTANT]
> :fire: A misconfiguration of the protocol configuration markers can cause disturbed service on a Mithril network.

#### Exporting last active protocol configurations markers from the chain in a JSON file

Export latest active configurations from the Cardano chain:

> [!IMPORTANT]
> If it's the first time on the targeted environment and there are no protocol configurations on-chain, add `--default` at the end of the `protocol-configuration export-markers` command.

```bash
./mithril-aggregator protocol-configuration export-markers --target-path $ASSETS_PATH/protocol-configurations.json
```

Default JSON prettified export will look like below:

```bash
cat $ASSETS_PATH/protocol-configurations.json | jq
```

```json
[
  {
    "epoch": 0,
    "protocol_parameters": {
      "k": 1944,
      "m": 16948,
      "phi_f": 0.2
    },
    "cardano_transaction_signing_config": {
      "security_parameter": 100,
      "step": 30
    },
    "cardano_blocks_transactions_signing_config": {
      "security_parameter": 100,
      "step": 30
    },
    "enabled_signed_entity_types": [
      "MithrilStakeDistribution",
      "CardanoStakeDistribution",
      "CardanoDatabase",
      "CardanoTransactions",
      "CardanoBlocksTransactions"
    ]
  }
]
```

#### Modifying protocol configurations

Manually edit previously exported JSON file written at `$ASSETS_PATH/protocol-configurations.json`

> [!IMPORTANT]
> :fire: Make sure to keep, if it exists, at least the three last epoch's configuration without any modification.

#### Generate Tx Datum payload file

Generate Tx Datum payload file by using previously edited JSON file

```bash
./mithril-aggregator protocol-configuration import-markers --import-path $ASSETS_PATH/protocol-configurations.json --target-path $ASSETS_PATH/protocol-configurations-datum.json
```

> [!IMPORTANT]
> You may encounter errors if JSON is not valid, contains zero values or contains inconsistent configurations regarding the chain configurations of the targeted environment.

#### Verify the produced protocol configuration marker

Verify that the produced protocol configuration markers are exactly what is expected with the following command:

```bash
cat $ASSETS_PATH/protocol-configurations-datum.json| jq -r '.fields[].bytes' | tr '\n' ' ' | xxd -r -p | jq
```

An example output of the command is:

```json
{
  "markers": [
    {
      "epoch": 1386,
      "configuration": "a47370726f746f636f6c5f706172616d6574657273a3616b190798616d194234657068695f66fb3fc999999999999a781b656e61626c65645f7369676e65645f656e746974795f74797065738578184d69746872696c5374616b65446973747269627574696f6e781843617264616e6f5374616b65446973747269627574696f6e6f43617264616e6f44617461626173657343617264616e6f5472616e73616374696f6e73781943617264616e6f426c6f636b735472616e73616374696f6e737463617264616e6f5f7472616e73616374696f6e73a27273656375726974795f706172616d657465720064737465700f781b63617264616e6f5f626c6f636b735f7472616e73616374696f6e73a27273656375726974795f706172616d6574657218646473746570181e"
    }
  ],
  "signature": "6310e8eab0261643a5115cfe331d78c1826d5637c2cf28ae0e4df72cc11b95657c6948ff468227ffc2f16471bb3fc3e44973ec30a78a8ef0de2295454171e706"
}
```

## Bootstrap Protocol Configuration Markers: Write a transaction with the first version of datum on chain

> [!IMPORTANT]
> :fire: This step must be done only once for an address when no prior datum has been written in a UTxO.
> Otherwise, you need to refer to this [section](#update-protocol-configuration-markers-write-a-new-version-of-datum-on-chain)

Verify that the payment address has funds:

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH
```

```json
    "add77f3246f19d2d1d599ff2decb7ac477b8a4839d7f9040ee704a53b519bc8b#0": {
        "address": "addr_test1qrcym4tvqjdntjvv0pdsp6keenwrk4xe7gq9exqqeh2x2p6gm9mtgjyvcvps92vzd3j2x0gzdudypuaca5r7d5elfe4q9da4p9",
        "datum": null,
        "datumhash": null,
        "inlineDatum": null,
        "inlineDatumRaw": null,
        "referenceScript": null,
        "value": {
            "lovelace": 10000000000
        }
    }
```

And create the variable `TX_IN={TxHash}#{TxIn}` by replacing with values from the previous command:

```bash
TX_IN=add77f3246f19d2d1d599ff2decb7ac477b8a4839d7f9040ee704a53b519bc8b#0
```

Now create the bootstrap transaction with datum:

```bash
$CARDANO_CLI $CARDANO_ERA transaction build $CARDANO_NETWORK_MAGIC \
    --tx-in $TX_IN \
    --tx-out $(cat $CARDANO_WALLET_PATH/payment.addr)+$SCRIPT_TX_VALUE \
    --tx-out-inline-datum-file $ASSETS_PATH/protocol-configurations-datum.json \
    --change-address $(cat $CARDANO_WALLET_PATH/payment.addr) \
    --out-file $ASSETS_PATH/tx.raw \
    --socket-path $CARDANO_NODE_SOCKET_PATH
```

```bash
Estimated transaction fee: 209017 Lovelace
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
Transaction successfully submitted. Transaction hash is:
{"txhash":"5ea0faac1d4b3ea633c4b2667b24d649b5d778123b32e942881246479bdab08d"}
```

We need to wait a few seconds before the transaction is available and we can see the initial datum for the script address:

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH
```

```json
{
    "5ea0faac1d4b3ea633c4b2667b24d649b5d778123b32e942881246479bdab08d#0": {
        "address": "addr_test1qrcym4tvqjdntjvv0pdsp6keenwrk4xe7gq9exqqeh2x2p6gm9mtgjyvcvps92vzd3j2x0gzdudypuaca5r7d5elfe4q9da4p9",
        "datum": null,
        "inlineDatum": {
            "constructor": 0,
            "fields": [
                {
                    "bytes": "7b226d61726b657273223a5b7b2265706f6368223a313338362c22636f6e66696775726174696f6e223a22613437333730373236663734366636333666366335"
                },
                {
                    "bytes": "66373036313732363136643635373436353732373361333631366231393037393836313664313934323334363537303638363935663636666233666339393939"
                },
                {
                    "bytes": "39393939393939396137383162363536653631363236633635363435663733363936373665363536343566363536653734363937343739356637343739373036"
                },
                {
                    "bytes": "35373338353738313834643639373436383732363936633533373436313662363534343639373337343732363936323735373436393666366537383138343336"
                },
                {
                    "bytes": "31373236343631366536663533373436313662363534343639373337343732363936323735373436393666366536663433363137323634363136653666343436"
                },
                {
                    "bytes": "31373436313632363137333635373334333631373236343631366536663534373236313665373336313633373436393666366537333738313934333631373236"
                },
                {
                    "bytes": "34363136653666343236633666363336623733353437323631366537333631363337343639366636653733373436333631373236343631366536663566373437"
                },
                {
                    "bytes": "32363136653733363136333734363936663665373361323732373336353633373537323639373437393566373036313732363136643635373436353732303036"
                },
                {
                    "bytes": "34373337343635373030663738316236333631373236343631366536663566363236633666363336623733356637343732363136653733363136333734363936"
                },
                {
                    "bytes": "66366537336132373237333635363337353732363937343739356637303631373236313664363537343635373231383634363437333734363537303138316522"
                },
                {
                    "bytes": "7d5d2c227369676e6174757265223a22363331306538656162303236313634336135313135636665333331643738633138323664353633376332636632386165"
                },
                {
                    "bytes": "30653464663732636331316239353635376336393438666634363832323766666332663136343731626233666333653434393733656333306137386138656630"
                },
                {
                    "bytes": "64653232393534353431373165373036227d"
                }
            ]
        },
        "inlineDatumRaw": "d8799f58407b226d61726b657273223a5b7b2265706f6368223a313338362c22636f6e66696775726174696f6e223a2261343733373037323666373436663633366636633558406637303631373236313664363537343635373237336133363136623139303739383631366431393432333436353730363836393566363666623366633939393958403939393939393939613738316236353665363136323663363536343566373336393637366536353634356636353665373436393734373935663734373937303658403537333835373831383464363937343638373236393663353337343631366236353434363937333734373236393632373537343639366636653738313834333658403137323634363136653666353337343631366236353434363937333734373236393632373537343639366636653666343336313732363436313665366634343658403137343631363236313733363537333433363137323634363136653666353437323631366537333631363337343639366636653733373831393433363137323658403436313665366634323663366636333662373335343732363136653733363136333734363936663665373337343633363137323634363136653666356637343758403236313665373336313633373436393666366537336132373237333635363337353732363937343739356637303631373236313664363537343635373230303658403437333734363537303066373831623633363137323634363136653666356636323663366636333662373335663734373236313665373336313633373436393658406636653733613237323733363536333735373236393734373935663730363137323631366436353734363537323138363436343733373436353730313831652258407d5d2c227369676e6174757265223a223633313065386561623032363136343361353131356366653333316437386331383236643536333763326366323861655840306534646637326363313162393536353763363934386666343638323237666663326631363437316262336663336534343937336563333061373861386566305264653232393534353431373165373036227dff",
        "inlineDatumhash": "2a08b8f14e45f9d0e5d0a6b9c03cc2217198f8c66fd6f32138c81e163cd28c74",
        "referenceScript": null,
        "value": {
            "lovelace": 4600000
        }
    },
    "5ea0faac1d4b3ea633c4b2667b24d649b5d778123b32e942881246479bdab08d#1": {
        "address": "addr_test1qrcym4tvqjdntjvv0pdsp6keenwrk4xe7gq9exqqeh2x2p6gm9mtgjyvcvps92vzd3j2x0gzdudypuaca5r7d5elfe4q9da4p9",
        "datum": null,
        "datumhash": null,
        "inlineDatum": null,
        "inlineDatumRaw": null,
        "referenceScript": null,
        "value": {
            "lovelace": 9995190983
        }
    }
```

Optional: We can retrieve the initial value stored in the datum with the cardano cli:

The parsed protocol configuration markers json representation:

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH --out-file temp.json && cat temp.json | jq -r '.[] | select(.inlineDatum | . != null and . != "")| .inlineDatum.fields[].bytes' | tr '\n' ' ' | xxd -r -p | jq
```

```json
{
  "markers": [
    {
      "epoch": 1386,
      "configuration": "a47370726f746f636f6c5f706172616d6574657273a3616b190798616d194234657068695f66fb3fc999999999999a781b656e61626c65645f7369676e65645f656e746974795f74797065738578184d69746872696c5374616b65446973747269627574696f6e781843617264616e6f5374616b65446973747269627574696f6e6f43617264616e6f44617461626173657343617264616e6f5472616e73616374696f6e73781943617264616e6f426c6f636b735472616e73616374696f6e737463617264616e6f5f7472616e73616374696f6e73a27273656375726974795f706172616d657465720064737465700f781b63617264616e6f5f626c6f636b735f7472616e73616374696f6e73a27273656375726974795f706172616d6574657218646473746570181e"
    }
  ],
  "signature": "6310e8eab0261643a5115cfe331d78c1826d5637c2cf28ae0e4df72cc11b95657c6948ff468227ffc2f16471bb3fc3e44973ec30a78a8ef0de2295454171e706"
}
```

Optional : We can also validate what has been written on chain by re-running the export command :

```bash
./mithril-aggregator protocol-configuration export-markers --target-path $ASSETS_PATH/protocol-configurations.json
```

```json
[
  {
    "epoch": 1386,
    "protocol_parameters": {
      "k": 1944,
      "m": 16948,
      "phi_f": 0.2
    },
    "cardano_transaction_signing_config": {
      "security_parameter": 0,
      "step": 15
    },
    "cardano_blocks_transactions_signing_config": {
      "security_parameter": 100,
      "step": 30
    },
    "enabled_signed_entity_types": [
      "MithrilStakeDistribution",
      "CardanoStakeDistribution",
      "CardanoDatabase",
      "CardanoTransactions",
      "CardanoBlocksTransactions"
    ]
  }
]
```

## Update Protocol Configuration Markers: Write a new version of datum on chain

> [!IMPORTANT]
> :fire: This step must be used anytime the protocol configuration markers must be updated on chain for an address when prior datum has already been written in a UTxO.
> Otherwise, you need to refer to this [section](#bootstrap-protocol-configuration-markers-write-a-transaction-with-the-first-version-of-datum-on-chain)

Retrieve the utxo of the payment address:

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH
```

```json
{
  "add77f3246f19d2d1d599ff2decb7ac477b8a4839d7f9040ee704a53b519bc8b#0": {
    "address": "addr_test1qrcym4tvqjdntjvv0pdsp6keenwrk4xe7gq9exqqeh2x2p6gm9mtgjyvcvps92vzd3j2x0gzdudypuaca5r7d5elfe4q9da4p9",
    "datum": null,
    "datumhash": null,
    "inlineDatum": null,
    "inlineDatumRaw": null,
    "referenceScript": null,
    "value": {
      "lovelace": 10000000000
    }
  }
}
```

And create the variable `TX_IN_DATUM={TxHash}#{TxIn}` by replacing with values from the previous command (where inline datum are available):

```bash
TX_IN_DATUM=add77f3246f19d2d1d599ff2decb7ac477b8a4839d7f9040ee704a53b519bc8b#0
```

And create the variable `TX_IN_NO_DATUM={TxHash}#{TxIn}` by replacing with values from the previous command (where inline datum are not available):

```bash
TX_IN_NO_DATUM=add77f3246f19d2d1d599ff2decb7ac477b8a4839d7f9040ee704a53b519bc8b#1
```

Now create the update transaction with datum:

```bash
$CARDANO_CLI $CARDANO_ERA transaction build $CARDANO_NETWORK_MAGIC \
    --tx-in $TX_IN_DATUM \
    --tx-in $TX_IN_NO_DATUM \
    --tx-out $(cat $CARDANO_WALLET_PATH/payment.addr)+$SCRIPT_TX_VALUE \
    --tx-out-inline-datum-file $ASSETS_PATH/protocol-configurations-datum.json \
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

```json
{
    "5ea0faac1d4b3ea633c4b2667b24d649b5d778123b32e942881246479bdab08d#0": {
        "address": "addr_test1qrcym4tvqjdntjvv0pdsp6keenwrk4xe7gq9exqqeh2x2p6gm9mtgjyvcvps92vzd3j2x0gzdudypuaca5r7d5elfe4q9da4p9",
        "datum": null,
        "inlineDatum": {
            "constructor": 0,
            "fields": [
                {
                    "bytes": "7b226d61726b657273223a5b7b2265706f6368223a313338362c22636f6e66696775726174696f6e223a22613437333730373236663734366636333666366335"
                },
                {
                    "bytes": "66373036313732363136643635373436353732373361333631366231393037393836313664313934323334363537303638363935663636666233666339393939"
                },
                {
                    "bytes": "39393939393939396137383162363536653631363236633635363435663733363936373665363536343566363536653734363937343739356637343739373036"
                },
                {
                    "bytes": "35373338353738313834643639373436383732363936633533373436313662363534343639373337343732363936323735373436393666366537383138343336"
                },
                {
                    "bytes": "31373236343631366536663533373436313662363534343639373337343732363936323735373436393666366536663433363137323634363136653666343436"
                },
                {
                    "bytes": "31373436313632363137333635373334333631373236343631366536663534373236313665373336313633373436393666366537333738313934333631373236"
                },
                {
                    "bytes": "34363136653666343236633666363336623733353437323631366537333631363337343639366636653733373436333631373236343631366536663566373437"
                },
                {
                    "bytes": "32363136653733363136333734363936663665373361323732373336353633373537323639373437393566373036313732363136643635373436353732303036"
                },
                {
                    "bytes": "34373337343635373030663738316236333631373236343631366536663566363236633666363336623733356637343732363136653733363136333734363936"
                },
                {
                    "bytes": "66366537336132373237333635363337353732363937343739356637303631373236313664363537343635373231383634363437333734363537303138316522"
                },
                {
                    "bytes": "7d5d2c227369676e6174757265223a22363331306538656162303236313634336135313135636665333331643738633138323664353633376332636632386165"
                },
                {
                    "bytes": "30653464663732636331316239353635376336393438666634363832323766666332663136343731626233666333653434393733656333306137386138656630"
                },
                {
                    "bytes": "64653232393534353431373165373036227d"
                }
            ]
        },
        "inlineDatumRaw": "d8799f58407b226d61726b657273223a5b7b2265706f6368223a313338362c22636f6e66696775726174696f6e223a2261343733373037323666373436663633366636633558406637303631373236313664363537343635373237336133363136623139303739383631366431393432333436353730363836393566363666623366633939393958403939393939393939613738316236353665363136323663363536343566373336393637366536353634356636353665373436393734373935663734373937303658403537333835373831383464363937343638373236393663353337343631366236353434363937333734373236393632373537343639366636653738313834333658403137323634363136653666353337343631366236353434363937333734373236393632373537343639366636653666343336313732363436313665366634343658403137343631363236313733363537333433363137323634363136653666353437323631366537333631363337343639366636653733373831393433363137323658403436313665366634323663366636333662373335343732363136653733363136333734363936663665373337343633363137323634363136653666356637343758403236313665373336313633373436393666366537336132373237333635363337353732363937343739356637303631373236313664363537343635373230303658403437333734363537303066373831623633363137323634363136653666356636323663366636333662373335663734373236313665373336313633373436393658406636653733613237323733363536333735373236393734373935663730363137323631366436353734363537323138363436343733373436353730313831652258407d5d2c227369676e6174757265223a223633313065386561623032363136343361353131356366653333316437386331383236643536333763326366323861655840306534646637326363313162393536353763363934386666343638323237666663326631363437316262336663336534343937336563333061373861386566305264653232393534353431373165373036227dff",
        "inlineDatumhash": "2a08b8f14e45f9d0e5d0a6b9c03cc2217198f8c66fd6f32138c81e163cd28c74",
        "referenceScript": null,
        "value": {
            "lovelace": 4600000
        }
    },
    "5ea0faac1d4b3ea633c4b2667b24d649b5d778123b32e942881246479bdab08d#1": {
        "address": "addr_test1qrcym4tvqjdntjvv0pdsp6keenwrk4xe7gq9exqqeh2x2p6gm9mtgjyvcvps92vzd3j2x0gzdudypuaca5r7d5elfe4q9da4p9",
        "datum": null,
        "datumhash": null,
        "inlineDatum": null,
        "inlineDatumRaw": null,
        "referenceScript": null,
        "value": {
            "lovelace": 9995190983
        }
    }
```

We can retrieve the updated value stored in the datum with the cardano cli:

The full utxo json representation:

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH --out-file temp.json && cat temp.json | jq '.[] | select(.inlineDatum | . != null and . != "")'
```

```bash
{
  "address": "addr_test1qrcym4tvqjdntjvv0pdsp6keenwrk4xe7gq9exqqeh2x2p6gm9mtgjyvcvps92vzd3j2x0gzdudypuaca5r7d5elfe4q9da4p9",
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

The parsed protocol configuration markers json representation:

```bash
$CARDANO_CLI $CARDANO_ERA query utxo --address $(cat $CARDANO_WALLET_PATH/payment.addr) $CARDANO_NETWORK_MAGIC --socket-path $CARDANO_NODE_SOCKET_PATH --out-file temp.json && cat temp.json | jq -r '.[] | select(.inlineDatum | . != null and . != "")| .inlineDatum.fields[].bytes' | tr '\n' ' ' | xxd -r -p | jq
```

```json
{
  "markers": [
    {
      "epoch": 1386,
      "configuration": "a47370726f746f636f6c5f706172616d6574657273a3616b190798616d194234657068695f66fb3fc999999999999a781b656e61626c65645f7369676e65645f656e746974795f74797065738578184d69746872696c5374616b65446973747269627574696f6e781843617264616e6f5374616b65446973747269627574696f6e6f43617264616e6f44617461626173657343617264616e6f5472616e73616374696f6e73781943617264616e6f426c6f636b735472616e73616374696f6e737463617264616e6f5f7472616e73616374696f6e73a27273656375726974795f706172616d657465720064737465700f781b63617264616e6f5f626c6f636b735f7472616e73616374696f6e73a27273656375726974795f706172616d6574657218646473746570181e"
    }
  ],
  "signature": "6310e8eab0261643a5115cfe331d78c1826d5637c2cf28ae0e4df72cc11b95657c6948ff468227ffc2f16471bb3fc3e44973ec30a78a8ef0de2295454171e706"
}
```
