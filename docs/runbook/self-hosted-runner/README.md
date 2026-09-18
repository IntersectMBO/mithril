# Set up a GitHub self-hosted runner

## Introduction

This guide sets up a GCP virtual machine registered as a GitHub self-hosted runner, to run
workloads too heavy for the GitHub hosted runners.

The runner is registered once with a token taken from the repository settings, so no GitHub
credential is stored on the machine, and the registration persists across jobs and reboots. The
machine stays stopped between runs, so only its disk is billed: the workflow starts the machine
before the job and stops it once the job completes.

All the commands of this guide run on your local machine, except in the sections explicitly
named `On the virtual machine`, which start by connecting to the machine with SSH.

## Prerequisites

- The `gcloud` CLI authenticated on the GCP project of the Mithril infrastructure, with compute
  administration permissions
- Administration access to the GitHub repository

## Export the environment variables

Export the environment variables:

```bash
export GCP_PROJECT=**GCP_PROJECT**
export GCP_ZONE=**GCP_ZONE**
export RUNNER_NAME=**RUNNER_NAME**
export RUNNER_LABEL=**RUNNER_LABEL**
export RUNNER_MACHINE_TYPE=**RUNNER_MACHINE_TYPE**
export RUNNER_VERSION=**RUNNER_VERSION**
```

Here is an example:

```bash
export GCP_PROJECT=mithril-infrastructure
export GCP_ZONE=europe-west1-b
export RUNNER_NAME=mithril-e2e-runner
export RUNNER_LABEL=e2e-ivc-16core
export RUNNER_MACHINE_TYPE=e2-standard-16
export RUNNER_VERSION=2.328.0
```

## Create the virtual machine

Create a machine sized for the workload, with an Ubuntu 24.04 image:

```bash
gcloud compute instances create $RUNNER_NAME \
  --project=$GCP_PROJECT \
  --zone=$GCP_ZONE \
  --machine-type=$RUNNER_MACHINE_TYPE \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=200GB \
  --boot-disk-type=pd-balanced
```

## On the virtual machine: install the tools and the runner user

Connect to the machine:

```bash
gcloud compute ssh $RUNNER_NAME --project=$GCP_PROJECT --zone=$GCP_ZONE
```

Once connected, install the tools used by the jobs and create a dedicated user for the runner:

```bash
sudo apt-get update && sudo apt-get install -y curl jq git
sudo useradd --create-home --shell /bin/bash runner
```

## On the virtual machine: install and register the runner agent

Still connected to the machine, switch to the `runner` user:

```bash
sudo -iu runner
```

`sudo -iu` starts a fresh environment, so export the environment variables again:

```bash
export RUNNER_VERSION=**RUNNER_VERSION**
export RUNNER_NAME=**RUNNER_NAME**
export RUNNER_LABEL=**RUNNER_LABEL**
```

Here is an example:

```bash
export RUNNER_VERSION=2.328.0
export RUNNER_NAME=mithril-e2e-runner
export RUNNER_LABEL=e2e-ivc-16core
```

Download the latest [runner agent](https://github.com/actions/runner/releases) release:

```bash
mkdir ~/actions-runner && cd ~/actions-runner
curl --fail -o actions-runner.tar.gz -L https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz
tar xzf actions-runner.tar.gz && rm actions-runner.tar.gz
```

Open the [new self-hosted runner page](https://github.com/IntersectMBO/mithril/settings/actions/runners/new?arch=x64&os=linux)
of the repository, copy the registration token shown in the `Configure` step (it is valid for
about one hour), and export it:

```bash
export REGISTRATION_TOKEN=**REGISTRATION_TOKEN**
```

Still as the `runner` user, register the runner:

```bash
cd ~/actions-runner
./config.sh --unattended \
  --url https://github.com/IntersectMBO/mithril \
  --token $REGISTRATION_TOKEN \
  --name $RUNNER_NAME \
  --labels $RUNNER_LABEL \
  --replace
exit
```

Back as the administrator user on the machine, install the service provided by the agent, so the
runner starts at every boot:

```bash
sudo bash -c 'cd /home/runner/actions-runner && ./svc.sh install runner && ./svc.sh start'
exit
```

## Verify the setup

Back on your local machine, restart the machine and check that the runner appears with its label
in the `Settings > Actions > Runners` page of the repository, with the `Idle` status (it shows
`Offline` whenever the machine is stopped):

```bash
gcloud compute instances stop $RUNNER_NAME --project=$GCP_PROJECT --zone=$GCP_ZONE
gcloud compute instances start $RUNNER_NAME --project=$GCP_PROJECT --zone=$GCP_ZONE
```

A job targeting the runner label is then picked by the runner. The machine does not stop by
itself: the workflow stops it once the job completes, and after a manual start, stop it yourself:

```bash
gcloud compute instances stop $RUNNER_NAME --project=$GCP_PROJECT --zone=$GCP_ZONE
```

## Create the service account for the CI (when needed)

The workflow starting and stopping the machine authenticates with a dedicated service account,
restricted to operating this single instance through a minimal custom role bound on the instance
(the binding requires the machine to exist):

```bash
gcloud iam service-accounts create mithril-e2e-runner-ci \
  --project=$GCP_PROJECT \
  --display-name="Mithril e2e runner start and stop for CI"

gcloud iam roles create e2eRunnerInstanceOperator \
  --project=$GCP_PROJECT \
  --title="E2E runner instance operator" \
  --permissions=compute.instances.start,compute.instances.stop,compute.instances.get,compute.zoneOperations.get

gcloud compute instances add-iam-policy-binding $RUNNER_NAME \
  --project=$GCP_PROJECT \
  --zone=$GCP_ZONE \
  --member="serviceAccount:mithril-e2e-runner-ci@${GCP_PROJECT}.iam.gserviceaccount.com" \
  --role="projects/${GCP_PROJECT}/roles/e2eRunnerInstanceOperator"

gcloud iam service-accounts keys create e2e-runner-ci-key.json \
  --iam-account=mithril-e2e-runner-ci@${GCP_PROJECT}.iam.gserviceaccount.com
```

Store the content of `e2e-runner-ci-key.json` in the `E2E_RUNNER_GCP_CREDENTIALS` GitHub secret
of the repository, then delete the local file.

## Remove the runner

Connect to the machine, stop and uninstall the runner service, then unregister the runner with a
removal token copied from the `Remove runner` dialog of the
[runners page](https://github.com/IntersectMBO/mithril/settings/actions/runners) of the
repository, replacing `**REMOVAL_TOKEN**` with it:

```bash
gcloud compute ssh $RUNNER_NAME --project=$GCP_PROJECT --zone=$GCP_ZONE
```

```bash
sudo bash -c 'cd /home/runner/actions-runner && ./svc.sh stop && ./svc.sh uninstall'
sudo -u runner bash -c 'cd /home/runner/actions-runner && ./config.sh remove --token **REMOVAL_TOKEN**'
exit
```

Back on your local machine, delete the machine when it is no longer needed:

```bash
gcloud compute instances delete $RUNNER_NAME --project=$GCP_PROJECT --zone=$GCP_ZONE
```

## Security considerations

- The registration is persistent: the runner reuses its work directory between jobs, and the
  machine is stopped by the workflow once the job completes, never by itself.
- Self-hosted runners of a public repository must never be exposed to code from fork pull
  requests: jobs targeting the runner label must only run on `schedule` and `workflow_dispatch`
  triggers.
- An ephemeral registration (`config.sh --ephemeral`, one job per boot with a clean state and a
  self-shutdown) is preferable when the organization allows fine-grained personal access tokens
  with the `Administration` repository permission, which are required to mint a fresh registration
  token at every boot.
