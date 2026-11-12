# Prepare artifacts for an unreleased Cardano node

## Introduction

When a new version of the Cardano node is not yet published on the official registry (`ghcr.io/intersectmbo/cardano-node`), it is necessary to build a local Docker image from the integration build and publish it to a private GCP Artifact Registry repository. The Cardano node configuration files also need to be prepared and uploaded to a GCP Cloud Storage bucket so that the Mithril infrastructure can use them for testing.

This runbook covers:

- Creating a GCP Cloud Storage bucket to host the Cardano node configuration artifacts
- Creating a GCP Artifact Registry Docker repository to host the test Docker image
- Checking out the integration branch or commit from the Cardano node repository
- Building and publishing the wrapped Cardano node Docker image
- Preparing and uploading the Cardano node configuration files

## Pre-requisites

- [`gcloud` CLI](https://cloud.google.com/sdk/docs/install) installed and authenticated
- `docker` installed
- `git` installed
- `nix` installed with flakes enabled
- Access to the GCP project used by the Mithril infrastructure

## Configure environment variables

```bash
export GCP_PROJECT_ID=**GCP_PROJECT_ID**
export GCP_REGION=europe-west1
export GCP_DOCKER_REPOSITORY=mithril-cardano-node-docker-test
export GCP_ARTIFACTS_BUCKET=mithril-cardano-node-artifacts-test
export CARDANO_NODE_VERSION=**CARDANO_NODE_VERSION**
export CARDANO_NODE_REF=**CARDANO_NODE_REF**
export GCP_CARDANO_IMAGE_REGISTRY=${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${GCP_DOCKER_REPOSITORY}/cardano-node
```

Here is an example for version `11.0.1-integration`:

```bash
export GCP_PROJECT_ID=iog-hydra
export GCP_REGION=europe-west1
export GCP_DOCKER_REPOSITORY=mithril-cardano-node-docker-test
export GCP_ARTIFACTS_BUCKET=mithril-cardano-node-artifacts-test
export CARDANO_NODE_VERSION=11.0.1-integration
export CARDANO_NODE_REF=release/11.0
export GCP_CARDANO_IMAGE_REGISTRY=${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${GCP_DOCKER_REPOSITORY}/cardano-node
```

## Step 1: Create a GCP Cloud Storage bucket for configuration artifacts (Optional)

Create a dedicated bucket to host the Cardano node configuration files:

```bash
gcloud storage buckets create gs://${GCP_ARTIFACTS_BUCKET} \
    --project=${GCP_PROJECT_ID} \
    --location=${GCP_REGION} \
    --uniform-bucket-level-access
```

Make the bucket publicly readable so that the infrastructure can download the configuration files:

```bash
gcloud storage buckets add-iam-policy-binding gs://${GCP_ARTIFACTS_BUCKET} \
    --member=allUsers \
    --role=roles/storage.objectViewer
```

## Step 2: Create a GCP Artifact Registry Docker repository (Optional)

Create a dedicated Docker repository in Artifact Registry to host the test Cardano node image:

```bash
gcloud artifacts repositories create ${GCP_DOCKER_REPOSITORY} \
    --project=${GCP_PROJECT_ID} \
    --repository-format=docker \
    --location=${GCP_REGION} \
    --description="Test repository for unreleased Cardano node images"
```

Make the repository publicly readable so that the infrastructure can pull the image without authentication:

```bash
gcloud artifacts repositories add-iam-policy-binding ${GCP_DOCKER_REPOSITORY} \
    --project=${GCP_PROJECT_ID} \
    --location=${GCP_REGION} \
    --member=allUsers \
    --role=roles/artifactregistry.reader
```

Verify the repository was created:

```bash
gcloud artifacts repositories describe ${GCP_DOCKER_REPOSITORY} \
    --project=${GCP_PROJECT_ID} \
    --location=${GCP_REGION}
```

## Step 3: Checkout the Cardano node repository

Clone the [Cardano node repository](https://github.com/IntersectMBO/cardano-node) and checkout the target branch, tag, or commit:

```bash
git clone https://github.com/IntersectMBO/cardano-node.git
cd cardano-node
git checkout ${CARDANO_NODE_REF}
export CARDANO_NODE_SHORT_COMMIT=$(git rev-parse --short HEAD)
```

The Cardano node configuration files for all networks are available in the `configuration/` directory of the repository. They will be used in [Step 5](#step-5-upload-the-cardano-node-artifacts).

### Build the Docker image

Build the Cardano node Docker image locally and load it into Docker, tagged for the GCP Artifact Registry:

```bash
nix build .#dockerImage/node \
  && RES=$(docker load -i result) \
  && LOADED="${RES##Loaded image: }" \
  && docker tag "$LOADED" ${GCP_CARDANO_IMAGE_REGISTRY}:${CARDANO_NODE_VERSION}-${CARDANO_NODE_SHORT_COMMIT} \
  && docker rmi "$LOADED"
```

Verify the image is available locally:

```bash
docker image ls ${GCP_CARDANO_IMAGE_REGISTRY}:${CARDANO_NODE_VERSION}-${CARDANO_NODE_SHORT_COMMIT}
```

### Build the binary artifacts

Build the Cardano node Linux binary artifacts. The result is a tar.gz archive produced in the `result` directory:

```bash
nix build -L .#hydraJobs.musl.cardano-node-linux
```

## Step 4: Publish the Cardano node Docker image

### Authenticate Docker with the Artifact Registry

```bash
gcloud auth configure-docker ${GCP_REGION}-docker.pkg.dev
```

### Push the image to Artifact Registry

```bash
docker push ${GCP_CARDANO_IMAGE_REGISTRY}:${CARDANO_NODE_VERSION}-${CARDANO_NODE_SHORT_COMMIT}
```

Verify the image is available:

```bash
gcloud artifacts docker images list \
    ${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${GCP_DOCKER_REPOSITORY} \
    --project=${GCP_PROJECT_ID}
```

## Step 5: Upload the Cardano node artifacts

### In the Cardano node repository

#### Upload the artifacts to Cloud Storage

Upload the tar.gz archive to the GCP bucket for future reference:

```bash
gcloud storage cp result/*.tar.gz \
    gs://${GCP_ARTIFACTS_BUCKET}/cardano-node/${CARDANO_NODE_VERSION}/
```

#### Extract the binary artifacts

The nix build produces a tar.gz archive in the `result` directory. Extract it to access the configuration files bundled in its `share/` directory:

```bash
mkdir -p cardano-node-artifacts
tar -xzf result/*.tar.gz -C cardano-node-artifacts
```

The extracted archive has the following structure (adapt the directory name to the actual version):

```
cardano-node-artifacts
├── bin
└── share
    ├── mainnet
    ├── preprod
    └── preview
```

Export the path to the share directory:

```bash
export CARDANO_SHARE_DIR=$(realpath cardano-node-artifacts/share)
echo $CARDANO_SHARE_DIR
```

### In the Mithril repository

#### Create the configuration directory for the new version

The Cardano node configuration files are stored under `mithril-infra/assets/docker/cardano/config/`. The version folder name can omit the patch version if the configuration is valid for all patch versions of the minor release (e.g. use `11.0` instead of `11.0.1`):

```bash
export CARDANO_CONFIG_VERSION=**CARDANO_CONFIG_VERSION**
```

```bash
mkdir -p mithril-infra/assets/docker/cardano/config/${CARDANO_CONFIG_VERSION}/{mainnet,preprod,preview}/cardano-node
```

#### Copy the configuration files

The Cardano release archive bundles configuration files under `share/{network}/`. Mithril expects them one level deeper, under `{network}/cardano-node/`. Copy them with the following command, run from the root of the Mithril repository:

```bash
for NETWORK in mainnet preprod preview; do
  cp ${CARDANO_SHARE_DIR}/${NETWORK}/*.json \
    mithril-infra/assets/docker/cardano/config/${CARDANO_CONFIG_VERSION}/${NETWORK}/cardano-node/
done
```

> [!NOTE]
> The `submit-api-config.json` file present in the Cardano release archive is not used by Mithril and can be removed:
>
> ```bash
> find mithril-infra/assets/docker/cardano/config/${CARDANO_CONFIG_VERSION} -name submit-api-config.json -delete
> ```

## Step 6: Display links to GCP resources

Display the links to the GCP resources created in the previous steps:

```bash
echo "Artifact Registry: https://console.cloud.google.com/artifacts/docker/${GCP_PROJECT_ID}/${GCP_REGION}/${GCP_DOCKER_REPOSITORY}/cardano-node?project=${GCP_PROJECT_ID}"
echo "Cloud Storage: https://console.cloud.google.com/storage/browser/${GCP_ARTIFACTS_BUCKET}/cardano-node?project=${GCP_PROJECT_ID}"
echo "Docker image: ${GCP_CARDANO_IMAGE_REGISTRY}:${CARDANO_NODE_VERSION}-${CARDANO_NODE_SHORT_COMMIT}"
echo "Artifact: https://storage.googleapis.com/${GCP_ARTIFACTS_BUCKET}/cardano-node/${CARDANO_NODE_VERSION}/$(basename result/*.tar.gz)"
```

## Step 7: Test the unreleased Cardano node artifacts (Optional)

### Run the end-to-end tests

Run the end-to-end tests against the unreleased Cardano node binary artifacts, either locally or by triggering the CI manual workflow with the following options:

```bash
--cardano-binary-url=https://storage.googleapis.com/${GCP_ARTIFACTS_BUCKET}/cardano-node/${CARDANO_NODE_VERSION}/$(basename result/*.tar.gz) \
--cardano-node-version=${CARDANO_NODE_VERSION}
```

### Deploy a test Mithril network with the unreleased Docker image

Update the following GitHub environment variables of the target test or dev network and redeploy the Mithril network infrastructure via the corresponding terraform deployment workflow:

- `CARDANO_NODE_DOCKER_REGISTRY` to `${GCP_CARDANO_IMAGE_REGISTRY}`
- `CARDANO_NODE_VERSION` to `${CARDANO_NODE_VERSION}-${CARDANO_NODE_SHORT_COMMIT}`

The following GitHub environments can be used for testing:

- `dev-preview`
- `dev-follower-preview`
- `dev-mainnet`
- `dev-dijkstranet`
- `testing-preview`

> [!IMPORTANT]
> The Cardano node release archive does not ship the Dijkstranet configuration: before testing with `dev-dijkstranet`, add the configuration files from the [Dijkstranet environment](https://book.play.dev.cardano.org/environments-pre/dijkstra/) to `mithril-infra/assets/docker/cardano/config/${CARDANO_CONFIG_VERSION}/dijkstranet/cardano-node`.

## Step 8: Cleanup (Optional)

Once the testing is complete and the official Cardano node image has been released, remove the temporary GCP resources:

```bash
gcloud artifacts repositories delete ${GCP_DOCKER_REPOSITORY} \
    --project=${GCP_PROJECT_ID} \
    --location=${GCP_REGION}

gcloud storage rm -r gs://${GCP_ARTIFACTS_BUCKET}
```
