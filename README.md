## SOPS-KMS-FLUX for the Kubernetes secret manifest

### This project implements the SOPS-KMS-FLUX scheme for the Kubernetes secret manifest containing API telegram token
---
### In the current context:
- the GKE cluster, Flux, KMS, and the infrastructure 'flux-gitops' repo is deployed via Terraform
- secret-manifest is generated and encrypted using the GitHub Actions pipeline, and the token is stored in the GCP Secret Manager.
- for implementation of the secret's update or rotation, the following scheme has been developed: <br>
   GCP Secret-Manager --> GCP Pub/Sub --> Cloud Function with POST request --> GitHub Actions --> Updated secret manifest in the infrastructure 'flux-gitops' repo
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
---
**2.** Creating the GitHub Actions workflow for the 'secret-manifest.yaml' to be generated and encrypted using the GitHub Actions pipeline
We will use Mozilla **SOPS** to generate a 'secret-manifest.yaml' for the 'TELE_TOKEN' key


