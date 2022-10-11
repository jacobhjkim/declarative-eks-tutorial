<p align="center">
  <a href="https://github.com/jacobhjkim/declarative-eks-tutorial/tree/main/kubernetes">
    <img src="../docs/images/kubernetes.svg" height="128">
    <h1 align="center">Kubernetes</h1>
  </a>
</p>

- [🚢 Current Deployments](#-current-deployments)
- [👍 How to Deploy to Kubernetes](#-how-to-deploy-to-kubernetes)

---

## 🚢 Current Deployments
Whenever you deploy a new chart, please add it to the table below.

### Central `ap-northeast-2`

| Deployment                                                            | Status                                                                                                                                                                                               |
|-----------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [actions-runner-controller](./charts/actions-runner-controller)       | [![actions-runner-controller](https://argocd.jacobkim.io/api/badge?name=actions-runner-controller-central&revision=true)](https://argocd.jacobkim.io/applications/actions-runner-controller-central) |
| [argocd](./charts/argocd)                                             | Deployed via Helm                                                                                                                                                                                    |
| [argocd-gitops](./charts/argocd-gitops)                               | [![argocd-gitops](https://argocd.jacobkim.io/api/badge?name=argocd-central-apps&revision=true)](https://argocd.jacobkim.io/applications/argocd-central-apps)                                         |
| [argocd-setup](./charts/argocd-setup)                                 | [![argocd-setup](https://argocd.jacobkim.io/api/badge?name=argocd-bootstrap-central&revision=true)](https://argocd.jacobkim.io/applications/argocd-bootstrap-central)                                |
| [atlantis](./charts/atlantis)                                         | [![atlantis](https://argocd.jacobkim.io/api/badge?name=atlantis-central&revision=true)](https://argocd.jacobkim.io/applications/atlantis-central)                                                    |
| [aws-ebs-csi-driver](./charts/aws-ebs-csi-driver)                     | Deployed via Helm                                                                                                                                                                                    |
| [aws-load-balancer-controller](./charts/aws-load-balancer-controller) | Deployed via Helm                                                                                                                                                                                    |
| [cert-manager](./charts/cert-manager)                                 | [![cert-manager](https://argocd.jacobkim.io/api/badge?name=cert-manager-central&revision=true)](https://argocd.jacobkim.io/applications/cert-manager-central)                                        |
| [echo-server](./charts/echo-server)                                   | Deployed via Helm                                                                                                                                                                                    |
| [external-dns](./charts/external-dns)                                 | Deployed via Helm                                                                                                                                                                                    |
| [external-secrets-operator](./charts/external-secrets-operator)       | Deployed via Helm                                                                                                                                                                                    |
| [karpenter](./charts/karpenter)                                       | Deployed via Helm                                                                                                                                                                                    |

### Dev `ap-northeast-2`

| Deployment                                                            | Status                                                                                                                                                                                                |
|-----------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [aws-ebs-csi-driver](./charts/aws-ebs-csi-driver)                     | [![aws-ebs-csi-driver](https://argocd.jacobkim.io/api/badge?name=aws-ebs-csi-driver-dev&revision=true)](https://argocd.jacobkim.io/applications/aws-ebs-csi-driver-dev)                               |
| [aws-load-balancer-controller](./charts/aws-load-balancer-controller) | [![aws-load-balancer-controller](https://argocd.jacobkim.io/api/badge?name=aws-load-balancer-controller-dev&revision=true)](https://argocd.jacobkim.io/applications/aws-load-balancer-controller-dev) |
| [cert-manager](./charts/cert-manager)                                 | [![cert-manager](https://argocd.jacobkim.io/api/badge?name=cert-manager-dev&revision=true)](https://argocd.jacobkim.io/applications/cert-manager-dev)                                                 |
| [echo-server](./charts/echo-server)                                   | [![echo-server](https://argocd.jacobkim.io/api/badge?name=echo-server-dev&revision=true)](https://argocd.jacobkim.io/applications/echo-server-dev)                                                    |
| [external-dns](./charts/external-dns)                                 | [![external-dns](https://argocd.jacobkim.io/api/badge?name=external-dns-dev&revision=true)](https://argocd.jacobkim.io/applications/external-dns-dev)                                                 |
| [external-secrets-operator](./charts/external-secrets-operator)       | [![external-secrets-operator](https://argocd.jacobkim.io/api/badge?name=external-secrets-operator-dev&revision=true)](https://argocd.jacobkim.io/applications/external-secrets-operator-dev)          |
| [karpenter](./charts/karpenter)                                       | [![karpenter](https://argocd.jacobkim.io/api/badge?name=karpenter-dev&revision=true)](https://argocd.jacobkim.io/applications/karpenter-dev)                                                          |
| [web-app](./charts/web-app)                                           | [![web-app](https://argocd.jacobkim.io/api/badge?name=web-app-dev&revision=true)](https://argocd.jacobkim.io/applications/web-app-dev)                                                                |

### Prod `us-east-1`

| Deployment                                                      | Status                                                                                                                                                                                                             |
|-----------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

## 👍 How to Deploy a new Chart to Kubernetes

1. Add a new chart to `charts` directory.
2. Update values file with name like `vaules-${CLUSTER}.yaml`.
3. Update the [argocd-gitops](./charts/argocd-gitops) chart's `values-${CLUSTER}.yaml` file appropriately.
