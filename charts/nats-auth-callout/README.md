# nats-auth-callout Helm chart

Deploys [nats-auth-callout](../../README.md): a NATS auth callout service that authenticates
clients with OIDC access tokens (e.g. from Keycloak).

The chart only deploys the callout. The NATS server needs a matching `auth_callout` block, the OIDC
provider needs a client and roles, and the Secret with the nkey seeds has to exist.
See the [deployment guide](../../docs/deployment.md) for the complete setup.

## Install

```sh
# Secret with the issuer seed, xkey seed and the password of the callout user.
kubectl create secret generic nats-auth-callout \
  --from-file=issuer-seed --from-file=xkey-seed --from-file=password

helm install nats-auth-callout oci://ghcr.io/pflege-de-labs/charts/nats-auth-callout \
  --version <release> -f values.yaml
```

Minimal `values.yaml`:

```yaml
nats:
  url: nats://nats.nats.svc:4222
secret:
  existingSecret: nats-auth-callout
permissions:
  issuers:
    - url: https://keycloak.example.com/realms/myrealm
      audience: nats
      roleClient: nats
  roles:
    events-read:
      sub:
        allow: ["events.>"]
```

Released charts pin the image to the same version (`appVersion`). A chart from a git checkout
uses the floating `main` image unless `image.tag` is set.

## Values

| Value | Default | Description |
|---|---|---|
| `replicaCount` | `2` | Replicas; requests are spread over a queue group |
| `image.repository` / `image.tag` / `image.pullPolicy` | `ghcr.io/pflege-de-labs/nats-auth-callout` / chart `appVersion` / `IfNotPresent` | Image |
| `imagePullSecrets` | `[]` | Pull secrets, needed if the package is private |
| `nats.url` | `nats://nats:4222` | NATS server to connect to |
| `nats.authUser` | `auth-callout` | User listed in `auth_callout.auth_users` |
| `secret.existingSecret` | `""` | Secret with the seeds and password (required unless `secret.create`) |
| `secret.keys.issuerSeed` / `xkeySeed` / `password` | `issuer-seed` / `xkey-seed` / `password` | Key names in an existing Secret |
| `secret.create`, `secret.values.*` | `false` | Create the Secret from values (testing only, seeds end up in the release) |
| `xkey.enabled` | `true` | Set to `false` if the server has no `auth_callout.xkey` |
| `permissions` | `{}` | Content of the permissions file (issuers, roles); required unless `existingConfigMap` |
| `existingConfigMap` | `""` | ConfigMap with the permissions file under `permissions.yaml` |
| `config.debug` | `false` | Debug logging |
| `service.port` | `8088` | Port for probes and metrics |
| `resources` | 10m/32Mi requests, 128Mi memory limit | Container resources |
| `spreadAcrossNodes` | `true` | Prefer different nodes for the replicas |
| `affinity`, `nodeSelector`, `tolerations`, `priorityClassName` | empty | Scheduling |
| `podDisruptionBudget.enabled` / `minAvailable` | `true` / `1` | Only rendered with more than one replica |
| `serviceMonitor.enabled` | `false` | Prometheus Operator ServiceMonitor for `/metrics` |
| `podSecurityContext`, `securityContext` | non-root, read-only root filesystem, no capabilities | Security settings |
| `serviceAccount.*`, `podAnnotations`, `podLabels`, `extraEnv` | | Misc |

Changes to the permissions ConfigMap (and to a Secret created by the chart) roll the pods through a
checksum annotation. With `existingConfigMap` or `secret.existingSecret` you have to restart the
deployment yourself.
