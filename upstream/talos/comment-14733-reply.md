Target: reply on https://github.com/siderolabs/talos/issues/14733 to https://github.com/siderolabs/talos/issues/14733#issuecomment-6440142915

---

Agreed, that is fair: durable one-shot belongs to the workload, and our jobs already check the on-disk state (an initialized OSD is skipped). Let's drop point 1.

The rest still stands without it:

- `never` and `on-failure` with a terminal state and exit code in `ContainerStatus` for the current run, so a client or a dependent container can see that a run finished and how. After a reboot it simply runs again.
- Configurable backoff instead of the fixed 5s.
- `dependsOn` with `condition: succeeded`, for init-style containers that run on every boot before the main one.
