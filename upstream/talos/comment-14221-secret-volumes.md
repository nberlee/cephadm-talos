Target: comment on https://github.com/siderolabs/talos/issues/14221 (ConfigMap-style volumes and matching container mounts)

---

Could these config volumes also support secret contents? Per-file modes, read-only tmpfs mounts, live updates and atomic replacement are already discussed above. The addition would be secret marking, and Talos already has the mechanism for it: documents with secrets implement [`config.SecretDocument`](https://github.com/siderolabs/talos/blob/edbfe07754a3dc6008cc8caa7b78782e99a81be2/pkg/machinery/config/config/document.go#L32-L36), and [`Container.RedactSecrets`](https://github.com/siderolabs/talos/blob/edbfe07754a3dc6008cc8caa7b78782e99a81be2/pkg/machinery/config/container/container.go#L1243-L1258) redacts all of them. `RawVolumeConfig` and `UserVolumeConfig` (encryption keys), `RegistryAuthConfig`, `WireguardConfig` and `SideroLinkConfig` implement it today; `EtcFileConfig` and `ContainerConfig` do not, so a password delivered through them today is never redacted.

**Use cases**

- Any service with a password, token or TLS key: databases, VPN daemons, reverse proxies, monitoring agents. #14656 shows a password in `EtcFileConfig` and a key in `args`.
- Images that expect secrets as files (`*_FILE` conventions, `.pem` files, keyrings), without a wrapper entrypoint that writes `environment` values to disk.
- Certificate or key rotation without a container restart, for services that re-read their files.

**What it would add to the config volume**

```yaml
kind: ConfigVolume      # name TBD
name: app-credentials
secret: true            # or a separate SecretVolume kind
contents:
  tls.key:
    mode: 0o400
    contents: |
      -----BEGIN PRIVATE KEY-----
      ...
```

- The volume document (or its files marked `secret: true`) implements `config.SecretDocument`, so its contents are redacted wherever Talos and its clients redact config today, like the documents above. (PR #14726 separately introduces opt-in redaction for resource reads; any new resource exposing these contents would need its own redaction support there.)
- Owner of the mounted files follows the container's `runAs`, like #14728 asks for user volumes.

This keeps secrets in the machine config, as discussed in #13596 and discussion #11238; it only gives them a marked, file-shaped home.

**Our case**: we run Ceph on Talos containers ([cephadm-talos](https://github.com/nberlee/cephadm-talos)). Every Ceph daemon needs a cephx keyring and some need TLS keys; today they are base64 env vars that our entrypoints write to disk. Henk Kraal (@hkraal, Exonet) lists the same need ("Secrets") in "Ceph on Talos without Kubernetes" (October 2026).
