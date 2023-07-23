## SOPS-KMS-FLUX for the Kubernetes secret manifest

### This project implements the SOPS-KMS-FLUX scheme for the Kubernetes secret manifest containing API telegram token
---
### In the current context:
- the GKE cluster, Flux, KMS, and the infrastructure 'flux-gitops' repo is deployed via Terraform
- secret-manifest is generated and encrypted using the GitHub Actions pipeline, and the token is stored in the GCP Secret Manager.
- for implementation of the secret's update or rotation, the following scheme has been developed: <br>

   ***GCP Secret-Manager*** --> ***GCP Pub/Sub*** --> ***Cloud Function with POST request*** --> ***GitHub Actions*** --> ***Updated secret manifest in the infrastructure 'flux-gitops' repo***
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
