## SOPS-KMS-FLUX for the Kubernetes secret manifest

### This project implements the SOPS-KMS-FLUX scheme for the Kubernetes secret manifest containing API telegram token
---
### In the current context:
- the GKE cluster, Flux, KMS, and the infrastructure 'flux-gitops' repo is deployed via Terraform
- secret-manifest is generated and encrypted using the GitHub Actions pipeline, and the token is stored in the GCP Secret Manager.
- for implementation of the secret's update or rotation, the following scheme has been developed: <br>

   ***GCP Secret-Manager secret update*** --> ***GCP Pub/Sub*** --> ***CloudFunction with POST request*** --> ***GitHub Actions*** --> ***Updated secret manifest in the infrastructure 'flux-gitops' repo***
---
## Stages:

 **1.** To deploy the GKE cluster, Flux, KMS, and the infrastructure 'flux-gitops' repo, Terraform was applied
```.hcl
module "tls_private_key" {
  source = "github.com/SVestor/tf-hashicorp-tls-keys"
  algorithm   = var.algorithm
}

module "gke_cluster" {
  source           = "github.com/SVestor/tf-google-gke-cluster?ref=gke-kbot"
  GOOGLE_REGION    = var.GOOGLE_REGION
  GOOGLE_PROJECT   = var.GOOGLE_PROJECT
  GKE_NUM_NODES    = var.GKE_NUM_NODES
  GKE_CLUSTER_NAME = var.GKE_CLUSTER_NAME
  GKE_MACHINE_TYPE = var.GKE_MACHINE_TYPE
}

module "github_repository" {
  source                   = "github.com/SVestor/tf-github-repository"
  github_owner             = var.GITHUB_OWNER
  github_token             = var.GITHUB_TOKEN
  repository_name          = var.FLUX_GITHUB_REPO
  public_key_openssh       = module.tls_private_key.public_key_openssh
  public_key_openssh_title = "flux"
  commit_message           = var.commit_message
  commit_author            = var.commit_author
  commit_email             = var.commit_email
}

module "gke_auth" {
  depends_on = [
    module.gke_cluster
  ]
  source               = "terraform-google-modules/kubernetes-engine/google//modules/auth"
  version              = ">= 24.0.0"
  project_id           = var.GOOGLE_PROJECT
  cluster_name         = var.GKE_CLUSTER_NAME
  location             = var.GOOGLE_REGION
}

module "flux_bootstrap" {
  source            = "github.com/SVestor/tf-fluxcd-flux-bootstrap"
  github_repository = "${var.GITHUB_OWNER}/${var.FLUX_GITHUB_REPO}"
  private_key       = module.tls_private_key.private_key_pem
  github_token      = var.GITHUB_TOKEN
  target_path       = var.target_path
  config_host       = module.gke_auth.host
  config_token      = module.gke_auth.token
  config_ca         = module.gke_auth.cluster_ca_certificate
}

module "gke-workload-identity" {
  source              = "terraform-google-modules/kubernetes-engine/google//modules/workload-identity"
  use_existing_k8s_sa = true
  name                = "kustomize-controller"
  namespace           = "flux-system"
  project_id          = var.GOOGLE_PROJECT
  cluster_name        = var.GKE_CLUSTER_NAME
  location            = var.GOOGLE_REGION
  annotate_k8s_sa     = true
  roles               = ["roles/cloudkms.cryptoKeyEncrypterDecrypter"]
}

module "kms" {
  source              = "github.com/SVestor/terraform-google-kms"
  project_id          = var.GOOGLE_PROJECT
  keyring             = "sops-flux"
  location            = "global"
  keys                = ["sops-flux-key"]
  prevent_destroy     = false 
}
```
- **KMS** is an encryption key service that applies a symmetric key that can be used to encrypt and decrypt data that allows us to encrypt and decrypt data using these keys. In this case, we will use it to encrypt and decrypt secrets.
- **Workload Identity (WI)** - allows applications in GKE clusters to identify themselves under a specific service account of the Identity Access Management (IAM) service to access Google cloud services. In this case, we will use it for authorization into KMS
- ***module "gke-workload-identity"*** will use the already existing Kubernetes service account. With the name 'kustomize-controller' in the namespace 'flux-system' on the existing cluster, add the annotation **'roles/cloudkms.cryptoKeyEncrypterDecrypter'**
- for the ***module "kms"***  it will be two arbitrary names for the keyring and the key
- a ***'key ring'*** organizes keys in a specific Google Cloud location and allows you to manage access control on groups of keys. Must be unique within a given location. After creation, a key ring cannot be deleted. 
> In the current context, WI, in its turn, through annotations in the manifest of the already existing flux service account named kustomization controller, will set up access to KMS, this will allow the controller to decrypt the secrets that we will encrypt using the KMS key.

![wi-kms](/images/wi-kms.png)

#### Let's check the annotation, keyring, and KMS key:
```bash
alias k=kubectl
gcloud auth login
gcloud config list project
gcloud config set project k8s-k3s-8
gcloud config set compute/zone us-central1-f
export PROJECT_ID=k8s-k3s-8
export ZONE=$(gcloud config get-value compute/zone)
gcloud container clusters get-credentials flux-demo --location $ZONE --project $PROJECT_ID

k get sa -n flux-system kustomize-controller -o yaml | grep -A5 anno
gcloud kms keys list --location global --keyring sops-flux
```
> The annotation has disappeared, this is because we set the annotation imperatively from Terraform, and the Flux is synchronized to the infrastructure repository, which does not contain information about the annotation of the service account.

#### Let's fix this with the help of two patches:
> ***- sa-patch.yaml***<br>
> ***- sops-patch.yaml***

- We will create these files in the infrastructure repository and populate them with the following data:
```.yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kustomize-controller
  namespace: flux-system
  annotations:
    iam.gke.io/gcp-service-account: kustomize-controller@k8s-k3s-8.iam.gserviceaccount.com
```
- The second patch will provide decryption provider **SOPS** rights for flux kustomization - this will allow Flux to decrypt the secrets that we encrypt using the KMS key automatically:
```.yaml
---
apiVersion: kustomize.toolkit.fluxcd.io/v1beta2
kind: Kustomization
metadata:
  name: flux-system
  namespace: flux-system
spec:
  interval: 10m0s
  path: ./clusters
  prune: true
  sourceRef:
    kind: GitRepository
    name: flux-system
  decryption:
    provider: sops
```
- We need to add these two files to kustomize config ('kustomization.yaml') and this means that Flux will use these two files to patch the resources it deploys and monitors. <br>
**Kustomize** is the **Kubernetes Native Configuration Management** enabled by default with kubectl and Flux is used for resource patching.

```.yaml
---
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- gotk-components.yaml
- gotk-sync.yaml
patches:
- path: sops-patch.yaml
  target:
    kind: Kustomization
- path: sa-patch.yaml
  target:
    kind: ServiceAccount
    name: kustomize-controller
```
> The flux log shows that it successfully reconciled and applied our patches.
```.bash
k get sa -n flux-system kustomize-controller -o yaml | grep -A5 anno
```
![anno](/images/anno.png)

> The annotation is in place again - it means that Flux uses the kustomization controller service account for authorization into KMS
---
**2.** Creating the GitHub Actions workflow for the 'secret-manifest.yaml' to be generated and encrypted using the GitHub Actions pipeline
#### So, what іs our expectations here:
- Our token is added and stored to the GCP Secret Manager 
- Our GitHub Action workflow must connect to the GCP Secret Manager, fetch our token from, create the 'secret-manifest.yaml' via SOPS which encrypt it with the KMS key  
- Then GitHub Action must push the 'secret-manifest.yaml' file into the Flux infrastructure repository 'flux-gitops'. 
The Flux controller must decrypt the secret using the KMS key, access to which is provided by the annotated service account and Workload Identity (WI), and then a native Kubernetes secret will be created, which we will use to access the Telegram API.

#### We will use Mozilla **SOPS** to generate a 'secret-manifest.yaml' for the 'TELE_TOKEN' key
> In order to store secrets safely in a public or private Git repository, you can use Mozilla’s SOPS CLI to encrypt Kubernetes secrets with OpenPGP, AWS KMS, GCP KMS and Azure Key Vault

#### For setting up the connection between our GCP with GitHub we will use the workload identity federation
> With identity federation, you can use Identity and Access Management (IAM) to grant external identities IAM roles, including the ability to impersonate service accounts. This approach eliminates the maintenance and security burden associated with service account keys.<br> You can use identity federation with any identity provider (IdP) that supports 'OpenID Connect (OIDC)'

#### Workload identity pools
> A workload identity pool is an entity that lets you manage external identities.

- In general, we must create a new pool and provider on the GCP side for our non-Google Cloud environment that needs to access Google Cloud resources, such as development, staging, or production environments.

#### Workload identity pool providers
> A workload identity pool provider is an entity that describes a relationship between Google Cloud and your identity provider IdP <br>
> Workload identity federation follows the 'OAuth 2.0' token exchange specification. <br>
> You provide a credential from your IdP to the Security Token Service, which verifies the identity on the credential, and then returns a federated token in exchange.

#### Attribute mappings
> The tokens issued by your external identity provider contain one or more attributes. Some identity providers refer to these attributes as claims. <br>
Google STS tokens also contain one or more attributes, as listed in the following table:
![wi-attr](/images/wi-attr.png)

#### Attribute conditions
> An attribute condition is a CEL expression that can check assertion attributes and target attributes. If the attribute condition evaluates to true for a given credential, the credential is accepted. Otherwise, the credential is rejected. <br>
You can use an attribute condition to restrict which identities can authenticate using your workload identity pool.

> For a more detailed understanding of how to configure WIF, you can familiarize yourself with the following resources:<br>
> - [Workload identity federation](https://cloud.google.com/iam/docs/workload-identity-federation) <br>
> - [Configure workload identity federation](https://cloud.google.com/iam/docs/workload-identity-federation-with-other-providers)

> ![wif-provider](/images/wif-provider.png)
> ![attr-map](/images/attr-map.png)

- Now we need to grant 'iam.workloadIdentityUser' and 'secretmanager.secretAccessor' roles to our GCP service account to bind it with our WIF and Secret Manager, and associate it with a specific workload identified by the member value.
- This allows our 'gh user' to authenticate using the credentials of the service account within the specified GCP project. We will use it next in our github workflow: 
```.bash
gcloud iam service-accounts add-iam-policy-binding "gh-actions@k8s-k3s-8.iam.gserviceaccount.com" \
  --project=${PROJECT_ID} \
  --role="roles/iam.workloadIdentityUser" \
  --role="roles/secretmanager.secretAccessor" \
  --member="principalSet://iam.googleapis.com/projects/740260502653/locations/global/workloadIdentityPools/gh-actions/attribute.repository/SVestor/flux-cmp"
```
> So, after the configuration of WIF is done we should add the necessary environment variables to our 'github actions', such as:
> - FLUX_PRIVATE --> what defines our infrastructure repo
> - WIF_PROVIDER --> what defines our WIF provider
> - SA_EMAIL --> what defines our GCP gh service account
> - GH_PAT --> what defines our GH PAT to access the infra repo    
> - then we can start implementing a code into our workflow

- The code is looking as follows:
```.yaml
name: kbot update-secret

on:
  repository_dispatch:
    types:
      - gcp_secret_changed
  
  # workflow_dispatch

env:
  SOPS_REPO: "mozilla/sops"
  OS: "linux"
  ARCH: "amd64"
  
jobs:
  get-secret:
    name: get-secret
    runs-on: ubuntu-20.04
    
   # Add "id-token" with the intended permissions.
    permissions:
      contents: 'read'
      id-token: 'write'

    steps: 
   # Clonning repos
      - name: Checkout source repo
        uses: 'actions/checkout@v3'
        
      - name: Checkout dest repo
        uses: actions/checkout@v3
        with:
          repository: ${{ secrets.FLUX_PRIVATE }}
          token: ${{ secrets.GH_PAT }}
          path: destination_repo  

    # Configure Workload Identity Federation via a credentials file
      - id: 'auth'
        name: 'Authenticate to GCP'
        uses: 'google-github-actions/auth@v1'
        with:
          token_format: 'access_token'
          workload_identity_provider: '${{ secrets.WIF_PROVIDER }}'
          service_account: '${{ secrets.SA_EMAIL }}'
        
    # Install gcloud 'setup-gcloud' automatically picks up authentication from 'auth'
      - name: 'Setting up Cloud SDK'
        uses: 'google-github-actions/setup-gcloud@v1'
      
    # 'Setting up' kubectl
      - name: 'Setting up kubectl'
        uses: azure/setup-kubectl@v3
        with:
          version: 'latest'
        id: install  
      
    # 'Setting up' sops
      - name: 'Setting up sops'
        run: |-
          export BIN_URL="https://api.github.com/repos/${SOPS_REPO}/releases/latest"
          curl -Lo sops "$(curl -Ls ${BIN_URL} | grep 'browser_download_url' | cut -d '"' -f 4 | grep "${OS}.${ARCH}$")"
          chmod +x sops

    # Now you can run gcloud commands authenticated as the impersonated service account
    # 'Getting & encrypting' a secret
      - id: 'secret'
        name: 'Getting & encrypting'
        env: 
          SOPS_KEY: '${{ secrets.SOPS_KEY }}'
        run: |-
          export SECRET_VALUE="$(gcloud secrets versions access latest --secret=TELE_TOKEN)" 
          kubectl -n kbot-demo create secret generic kbot-secret --from-literal=token=${SECRET_VALUE} --dry-run=client -o yaml > secret.yaml
          ./sops -e -gcp-kms ${SOPS_KEY} --encrypted-regex '^(token)$' secret.yaml > secret-enc.yaml
          mv secret-enc.yaml destination_repo/clusters/kbot-demo
   
   # 'Pushing a secret' to the REPO-flux-cluster
      - name: 'Pushing a secret'
        run: |-
          cd destination_repo
          git config user.name flux-cmp
          git config user.email flux-cmp@github.com
          git commit -am "update secret"
          git push origin main
```
---
**3.** The final one. Implementation of the secret's update or rotation
#### Set of principles:
- The function subscribes to a 'Cloud Pub/Sub' topic that is published when a secret changes in 'GCP Secret Manager'.
- The function makes a POST request to the GitHub API, which activates the 'repository_dispatch' 'gcp-secret-changed' event in our repository and thereby triggers our GitHub Actions Workflow.
- This function provides monitoring of secret value changes in 'GCP Secret Manager', as it receives a secret change notification whenever the secret changes.
- The function is written in Python and deployed on the Google Cloud Platform with 'Cloud Run' service.

> Now we need to create a ***service agent*** identity for each project that requires secrets with event notifications.
To create a service identity with Google Cloud CLI, run the following command:
```.bash
gcloud beta services identity create \ 
--service "secretmanager.googleapis.com" \ 
--project $PROJECT_ID

# The previous command returns a service account name, using the following format:
Service identity created: service-740260502653@gcp-sa-secretmanager.iam.gserviceaccount.com

# You will grant this service account permission to publish on the Pub/Sub topics which will be configured on your secrets.
# Save the service account name as an environment variable:

export SM_SERVICE_ACCOUNT=service-740260502653@gcp-sa-secretmanager.iam.gserviceaccount.com
```
> Create Pub/Sub topic:
```.bash
# Follow the Pub/Sub quickstart to create topics in your Pub/Sub project in the Google Cloud console.
# Alternatively, you can create topics with Google Cloud CLI as in this example:

gcloud pubsub topics create "projects/$PROJECT_ID/topics/gcp_secrets_TEST_SECRET"

# Grant the service account for Secret Manager permission to publish on the topics just created. This can be done through the Google Cloud console or with Google Cloud CLI. # The following command grants the Pub/Sub Publisher role (roles/pubsub.publisher) on the 'my-topic' Pub/Sub topic to the service account.

gcloud pubsub topics add-iam-policy-binding gcp_secrets_TEST_SECRET \ 
--member "serviceAccount:${SM_SERVICE_ACCOUNT}" \ 
--role "roles/pubsub.publisher"

# Note: To grant the service account permission to publish on a topic, you must have resourcemanager.projects.setIamPolicy permission. This permission is included in the Project Owner, Project IAM Admin, and Organization Administrator roles.
```
> Create Pub/Sub subscriptions
```.bash
# In order to view the messages published to a topic, you must also create a subscription to the topic.
# Follow the Pub/Sub quickstart to create subscriptions in your Pub/Sub project in the Google Cloud console.
# Alternatively, you can create subscriptions with Google Cloud CLI as in this example

gcloud pubsub subscriptions create "projects/$PROJECT_ID/subscriptions/gcp_secrets_TEST_SECRET" \
    --topic "projects/$PROJECT_ID/topics/gcp_secrets_TEST_SECRET"
```
> Update secret topic
```.bash
# Modify the Pub/Sub topics configured on a secret by updating the secret with the new Pub/Sub topic resource names.
# With Google Cloud CLI you can add or remove one or more topics from a secret, as well as clear all topics from the secret.
# Add topics
# Adds one or more topics to a secret. Adding a topic which is already present will have no effect.

gcloud secrets update "SECRET_ID" \
    --project "PROJECT_ID" \
    --add-topics "projects/PUBSUB_PROJECT_ID/topics/gcp_secrets_TEST_SECRET"
```
> Consume event notifications with Cloud Functions
> - Event notifications can be used to trigger arbitrary workflows by creating cloud functions to consume the Pub/Sub messages. 
> - See the [Cloud Functions documentation](https://cloud.google.com/functions/docs/tutorials/pubsub)  for a full guide
```.bash
# Create and Deploy CloudFunction
gcloud functions deploy python-test-secret-function \
--gen2 \
--runtime=python311 \
--region=us-central1 \
--source=. \
--entry-point=subscribe \
--trigger-topic=gcp_secrets_TEST_SECRET
```
> The function_code looks as follows:
```.py
import base64
from cloudevents.http import CloudEvent
import functions_framework
import requests
import os

# Triggered from a message on a Cloud Pub/Sub topic.
@functions_framework.cloud_event
def subscribe(cloud_event: CloudEvent) -> None:
    # Print out the data from Pub/Sub, to prove that it worked
    print(
        "secret update, " + base64.b64decode(cloud_event.data["message"]["data"]).decode() + "!"
    )
# Calling the github 'trigger_github_workflow' func after receiving a message in the topic
    trigger_github_workflow()
	
def trigger_github_workflow():
    github_api_url = 'https://api.github.com/repos/{owner}/{repo}/dispatches'

    owner = os.environ['OWNER'] 
    repo = os.environ['REPO'] 
    github_webhook_token = os.environ['GH_PAT'] 

    # Headers for a POST request to GitHub (token authentication)
    headers = {
        'Authorization': f'Bearer {github_webhook_token}',
        'Accept': 'application/vnd.github.everest-preview+json'
    }

    # The body of the POST request to generate the "repository_dispatch" event
    data = {
        'event_type': 'gcp_secret_changed',  # Event type
        'client_payload': {}  # You can pass additional data in the payload if needed
    }

    response = requests.post(github_api_url.format(owner=owner, repo=repo), json=data, headers=headers)

    if response.status_code == 204:
        print('GitHub Workflow triggered successfully')
    else:
        print('Error triggering GitHub Workflow')
``` 
> Granting access to secrets inside the function such as 'GH_PAT'
- Our function can access secrets that reside in the same project as the function as well as secrets that reside in another project. To access a secret, the function's runtime service account must be granted access to the secret.
- By default, Cloud Functions uses the [App Engine default service account](https://cloud.google.com/functions/docs/securing/function-identity) to authenticate with Secret Manager. For production use, Google recommends that you configure your function to authenticate using a [user-managed service account](https://cloud.google.com/iam/docs/service-account-types) that is assigned the least-permissive set of roles required to accomplish that function's tasks.
- To use Secret Manager with Cloud Functions, assign the 'roles/secretmanager.secretAccessor' role to the service account associated with your function:
  ![sm-function.png](/images/sm-function.png)

> Preparing your function to access secrets
> There are two ways of making a secret available to your function:
> - passing the secret as an environment variable.
> - mounting the secret as a volume.
  ![prep-sec.png](/images/prep-sec.png)
  ![prep-sec1.png](/images/prep-sec1.png)
  ![prep-sec2.png](/images/prep-sec2.png)

> - ***! Now we need to redeploy our function for the changes to take effect !*** <br>

---

**Once all of the above is done, we can manually update the version and secret value to test all the processes of automating the launch of our workflow. Once it updated:** <br>
> - The 'Cloud Pub/Sub' topic through the received notification from Cloud Secret Manager triggers the CloudFunction <br>
> - The function makes a POST request to the GitHub API, which activates the 'repository_dispatch' 'gcp-secret-changed' event in our repository and thereby triggers our GitHub Actions Workflow <br>
> - GitHub Actions pushes the updated 'secret-manifest.yaml' file into the Flux infrastructure repository 'flux-gitops' <br>
> - The Flux controller must decrypt the secret using the KMS key, access to which is provided by the annotated service account and Workload Identity (WI), and then a native Kubernetes secret will be created, which we will use to access the Telegram API.

```.bash

echo -n "<paste the token value here>" > secret_update.txt
gcloud secrets versions add TELE_TOKEN --data-file="./secret_update.txt"
```

***GCP Secret-Manager secret update*** --> ***GCP Pub/Sub*** --> ***CloudFunction with POST request*** --> ***GitHub Actions*** --> ***Updated secret manifest in the infrastructure 'flux-gitops' repo***

```.bash
➜  ~ exit
```

> For a more detailed understanding, you can familiarize yourself with the following resources:<br>
> - [Configure workload identity federation with other identity providers](https://cloud.google.com/iam/docs/workload-identity-federation-with-other-providers) <br>
> - [Set up notifications on a secret](https://cloud.google.com/secret-manager/docs/event-notifications) <br>
> - [Add a secret version](https://cloud.google.com/secret-manager/docs/add-secret-version#secretmanager-add-secret-version-gcloud)<br>
> - [gcloud secret update](https://cloud.google.com/sdk/gcloud/reference/secrets/update)<br>
> - [Making secret accessible to a function](https://cloud.google.com/functions/docs/configuring/secrets#console)
> - [What is Pub/Sub](https://cloud.google.com/pubsub/docs/overview) <br>
> - [Cloud Pub/Sub Tutorial (2nd gen)](https://cloud.google.com/functions/docs/tutorials/pubsub#functions-change-directory-python) <br>
> - [Service agents](https://cloud.google.com/iam/docs/service-agents) <br>
> - [What is Cloud Run](https://cloud.google.com/run/docs/overview/what-is-cloud-run)
