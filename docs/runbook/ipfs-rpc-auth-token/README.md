# IPFS RPC authentication token

## Introduction

When IPFS is enabled on a Mithril network, the aggregator uploads the immutable files archives through the RPC API of its IPFS node.
This RPC API gives admin-level access to the node, so it is protected by a bearer token that only the aggregator uses.

The token is provided to the deployment by the `IPFS_RPC_AUTH_TOKEN` secret of the GitHub environment of the network.
At each start, the IPFS node sets it in its Kubo [`API.Authorizations`](https://github.com/ipfs/kubo/blob/master/docs/config.md#apiauthorizations) setting, and the aggregator sends it with each RPC request.

This secret is optional, and the RPC API of the IPFS node is not protected when it is not set.
Only the networks with IPFS enabled use it (`mithril_ipfs_enabled: true` in the deployment workflows).

> [!NOTE]
> The RPC port of the IPFS node is not published outside the Docker network of the VM.
> The token restricts its use to the aggregator, among the containers of this network.
> Only the `/api/v0` routes are protected.
> The metrics and Web UI routes of the RPC port stay open.

## Create a token

> [!IMPORTANT]
> :fire: The token gives admin access to the RPC API of the IPFS node, including the publication under the IPNS name of the network. It must not be stored anywhere other than the GitHub environment secret, the IPFS node and the aggregator.

Generate a new random token:

```bash
openssl rand -hex 32
```

> [!IMPORTANT]
> The token must only contain alphanumeric characters, which is enforced by the validation of the `mithril_ipfs_rpc_auth_token` Terraform variable.

## Register the token

Copy the token into the `IPFS_RPC_AUTH_TOKEN` secret of the GitHub environment of the network.

The IPFS node and the aggregator use it at the next deployment of the network.

## Rotate the token

Create a new token and register it as described above.

At the next deployment, the IPFS node replaces its authorization with the new token, and the aggregator is restarted with it.

## Disable the authentication

Delete the `IPFS_RPC_AUTH_TOKEN` secret of the GitHub environment of the network.

At the next deployment, the IPFS node removes its authorization, and the RPC API is no longer protected.

> [!WARNING]
> If a repository secret with the same name exists, the deployment uses it instead of the deleted environment secret.

## Check the protection

Export the environment variables:

```bash
export MITHRIL_VM=**MITHRIL_VM**
```

Here is an example for the `testing-preview` network:

```bash
export MITHRIL_VM=aggregator.testing-preview.api.mithril.network
```

Connect to the aggregator VM:

```bash
ssh curry@$MITHRIL_VM
```

Query the RPC API of the IPFS node without the token:

```bash
docker exec ipfs-node-aggregator ipfs --api=/ip4/127.0.0.1/tcp/5001 id
```

The query must be refused when the authentication is enabled.
