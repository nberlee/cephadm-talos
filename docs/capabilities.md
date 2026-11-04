# Capability matrix

What cephadm-talos provides of the Ceph orchestrator interface, for Ceph v21.2.0 (commit `b060042deb05d33e6cc358970cfb8221240bcf3e` of the `umbrella` branch, the release image's `CEPH_SHA1` label; the release has no git tag). Status is `implemented`, `milestone N` (planned in that [roadmap](../ROADMAP.md) milestone) or `unsupported`. The `implemented` rows are the read path of [plan 02](plans/02-agents-and-read-path.md) and the write path of [plan 03](plans/03-write-path.md): a mgr module installed as `cephadm` (Ceph accepts only `cephadm`, `rook` and `test_orchestrator` as backend), with the leader in the active mgr's cephadm-talos agent carrying the operations out. A note on an `implemented` row names what of it is supported; anything else of that command is refused. [docs/architecture.md](architecture.md) ("The ledger") lists every accepted form.

The first four sections are checked against the Ceph source by `hack/capabilities.py <ceph source>`; the last two are maintained by hand.

## Orchestrator methods

| Name | Status | Note |
|---|---|---|
| `add_daemon` | implemented | write path (plan 03): mon and mgr on a host; rgw `default`, one per host, with a port and the operator's certificate; no other service |
| `add_host` | implemented | write path (plan 03): a node the CLI enrolled (`cephadm-talos host add`), with labels stored only |
| `add_host_label` | milestone 5 |  |
| `apply` | implemented | write path (plan 03): one keepalived-only ingress (`apply -i`), and host specs of enrolled nodes (to `add_host`); no other service spec |
| `apply_alertmanager` | milestone 5 |  |
| `apply_alloy` | milestone 5 |  |
| `apply_ceph_exporter` | milestone 5 |  |
| `apply_crash` | milestone 5 |  |
| `apply_drivegroups` | milestone 5 |  |
| `apply_grafana` | milestone 5 |  |
| `apply_ingress` | milestone 5 |  |
| `apply_iscsi` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `apply_loki` | milestone 5 |  |
| `apply_mds` | milestone 5 |  |
| `apply_mgmt_gateway` | milestone 5 |  |
| `apply_mgr` | milestone 5 |  |
| `apply_mon` | milestone 5 |  |
| `apply_nfs` | milestone 5 |  |
| `apply_node_exporter` | milestone 5 |  |
| `apply_nvmeof` | milestone 5 | needs draft 08 (memlock) |
| `apply_oauth2_proxy` | milestone 5 |  |
| `apply_prometheus` | milestone 5 |  |
| `apply_promtail` | milestone 5 |  |
| `apply_rbd_mirror` | milestone 5 |  |
| `apply_rgw` | milestone 5 |  |
| `apply_smb` | milestone 5 | needs draft 07 (shared namespaces) |
| `apply_snmp_gateway` | milestone 5 |  |
| `apply_tuned_profiles` | milestone 5 |  |
| `available` | implemented | read path (plan 02): the talos mgr module, installed as `cephadm` |
| `blink_device_light` | milestone 5 | to validate on Talos (lsmcli in a privileged job) |
| `cancel_completions` | milestone 3 |  |
| `cert_store_bindings_ls` | milestone 5 |  |
| `cert_store_cert_check` | milestone 5 |  |
| `cert_store_cert_ls` | milestone 5 |  |
| `cert_store_get_cert` | milestone 5 |  |
| `cert_store_get_key` | milestone 5 |  |
| `cert_store_key_ls` | milestone 5 |  |
| `cert_store_reload` | milestone 5 |  |
| `cert_store_rm_cert` | milestone 5 |  |
| `cert_store_rm_key` | milestone 5 |  |
| `cert_store_set_cert` | milestone 5 |  |
| `cert_store_set_key` | milestone 5 |  |
| `cert_store_set_pair` | milestone 5 |  |
| `create_osds` | implemented | write path (plan 03): one disk on one host, nothing else of a drive group; the disk approved by the operator |
| `daemon_action` | implemented | write path (plan 03): restart and redeploy (without an image); not start, stop, reconfig or rotate-key |
| `describe_service` | milestone 5 |  |
| `drain_host` | implemented | plan 04 step 5: every OSD out at once, each OSD removed after its drain, then the RGW, the mgr (failed over first), the mon (while the rest keep quorum), one step at a time; `--zap-osd-devices`; not with `--force` or `--keep-conf-keyring`; refused for a host of the ingress, the last mgr's, a mon host leaving fewer than three mons, and while a host's move is unfinished; again on a paused drain resumes it |
| `enter_host_maintenance` | implemented | write path (plan 03): with `--force`; not with `--yes-i-really-mean-it` |
| `exit_host_maintenance` | implemented | write path (plan 03): not with `--force` or `--offline` |
| `generate_certificates` | milestone 5 |  |
| `get_alertmanager_access_info` | milestone 5 |  |
| `get_facts` | milestone 5 |  |
| `get_feature_set` | milestone 3 |  |
| `get_hosts` | implemented | read path (plan 02): the talos mgr module, installed as `cephadm` |
| `get_inventory` | milestone 5 |  |
| `get_nvmeof_tls_bundle` | milestone 5 |  |
| `get_prometheus_access_info` | milestone 5 |  |
| `get_security_config` | milestone 5 |  |
| `hardware_light` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `hardware_powercycle` | implemented | write path (plan 03): maintenance enter, a Talos reboot, maintenance exit; no BMC |
| `hardware_shutdown` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `hardware_status` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `host_ok_to_stop` | milestone 5 |  |
| `is_orchestrator_module` | milestone 3 |  |
| `list_daemons` | implemented | read path (plan 02): the talos mgr module, installed as `cephadm` |
| `node_proxy_common` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node_proxy_criticals` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node_proxy_firmware` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node_proxy_firmwares` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node_proxy_fullreport` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node_proxy_summary` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `pause` | milestone 5 |  |
| `plan` | milestone 5 |  |
| `preview_osdspecs` | milestone 5 |  |
| `remove_daemons` | implemented | write path (plan 03): mons, mgrs and RGWs (not the active mgr, not the last mon or mgr) |
| `remove_host` | implemented | write path (plan 03): a host without daemons that does not run the active mgr; not `--offline` or `--rm-crush-entry` |
| `remove_host_label` | milestone 5 |  |
| `remove_osds` | implemented | write path (plan 03): with `--zap` and `--force`; not `--replace` or `--no-destroy` |
| `remove_osds_status` | implemented | write path (plan 03): the phase, without PG counts |
| `remove_prometheus_remote_write` | milestone 5 |  |
| `remove_prometheus_target` | milestone 5 |  |
| `remove_service` | milestone 5 |  |
| `replace_device` | milestone 5 |  |
| `rescan_host` | milestone 5 |  |
| `resume` | milestone 5 |  |
| `rm_tuned_profile` | milestone 5 |  |
| `service_action` | milestone 5 |  |
| `set_alertmanager_access_info` | milestone 5 |  |
| `set_custom_prometheus_alerts` | milestone 5 |  |
| `set_osd_spec` | milestone 5 |  |
| `set_prometheus_access_info` | milestone 5 |  |
| `set_prometheus_remote_write` | milestone 5 |  |
| `set_prometheus_target` | milestone 5 |  |
| `set_unmanaged` | milestone 5 |  |
| `set_unmanaged_flag` | milestone 5 |  |
| `stop_drain_host` | implemented | plan 04 step 5: no new step starts, a step in progress finishes; OSDs marked out stay out |
| `stop_remove_osds` | milestone 5 |  |
| `tuned_profile_add_setting` | milestone 5 |  |
| `tuned_profile_add_settings` | milestone 5 |  |
| `tuned_profile_ls` | milestone 5 |  |
| `tuned_profile_rm_setting` | milestone 5 |  |
| `tuned_profile_rm_settings` | milestone 5 |  |
| `update_host_addr` | implemented | plan 04 step 5: an IP of the same family, confirmed on the node through its agent at the new address before it becomes the host's; then the RGW (keepalived back last, after its peers), the mgr (failed over first), the OSDs (under noout), the mon (out of the monmap, back with a fresh store), `mon_host` everywhere, the agent's and mgr's certificates; refused in maintenance, during a drain of any host, an upgrade, an agent upgrade, an ingress apply, an RGW certificate renewal or RGW add, or another move, for another host's address, a mon host with fewer than three mons, the active mgr's host without a standby; again on a paused move resumes it. cephadm only records the address its SSH connection uses |
| `update_service` | milestone 5 |  |
| `upgrade_available` | milestone 5 |  |
| `upgrade_check` | milestone 5 |  |
| `upgrade_ls` | milestone 5 |  |
| `upgrade_pause` | implemented | write path (plan 03) |
| `upgrade_resume` | implemented | write path (plan 03) |
| `upgrade_start` | implemented | write path (plan 03): by digest, an image of the operator's approval, the cluster's repository; no other option |
| `upgrade_status` | implemented | write path (plan 03): the upgrade with the leader's progress |
| `upgrade_stop` | implemented | write path (plan 03) |
| `zap_device` | milestone 5 |  |

## ceph orch commands

| Name | Status | Note |
|---|---|---|
| `device light` | milestone 5 | to validate on Talos (lsmcli in a privileged job) |
| `device ls-lights` | milestone 5 | to validate on Talos (lsmcli in a privileged job) |
| `orch` | milestone 5 | service action: start, stop, restart, redeploy, reconfig of a whole service |
| `orch alertmanager get-credentials` | milestone 5 |  |
| `orch alertmanager set-credentials` | milestone 5 |  |
| `orch apply` | implemented | write path (plan 03): `-i` with one keepalived-only ingress, or host specs of enrolled nodes |
| `orch apply iscsi` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `orch apply jaeger` | milestone 5 |  |
| `orch apply mds` | milestone 5 |  |
| `orch apply mgmt-gateway` | milestone 5 |  |
| `orch apply nfs` | milestone 5 |  |
| `orch apply nvmeof` | milestone 5 | needs draft 08 (memlock) |
| `orch apply oauth2-proxy` | milestone 5 |  |
| `orch apply osd` | milestone 5 |  |
| `orch apply rgw` | milestone 5 |  |
| `orch apply smb` | milestone 5 | needs draft 07 (shared namespaces) |
| `orch apply snmp-gateway` | milestone 5 |  |
| `orch cancel` | milestone 3 |  |
| `orch certmgr bindings ls` | milestone 5 |  |
| `orch certmgr cert check` | milestone 5 |  |
| `orch certmgr cert get` | milestone 5 |  |
| `orch certmgr cert ls` | milestone 5 |  |
| `orch certmgr cert rm` | milestone 5 |  |
| `orch certmgr cert set` | milestone 5 |  |
| `orch certmgr cert-key set` | milestone 5 |  |
| `orch certmgr generate-certificates` | milestone 5 |  |
| `orch certmgr key get` | milestone 5 |  |
| `orch certmgr key ls` | milestone 5 |  |
| `orch certmgr key rm` | milestone 5 |  |
| `orch certmgr key set` | milestone 5 |  |
| `orch certmgr reload` | milestone 5 |  |
| `orch client-keyring ls` | milestone 5 |  |
| `orch client-keyring rm` | milestone 5 |  |
| `orch client-keyring set` | milestone 5 |  |
| `orch daemon` | implemented | write path (plan 03): `restart` and `redeploy` of one daemon |
| `orch daemon add` | implemented | write path (plan 03): `mon` and `mgr` on a host; `-i` with an RGW spec carrying the operator's certificate |
| `orch daemon add iscsi` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `orch daemon add mds` | milestone 5 |  |
| `orch daemon add nfs` | milestone 5 |  |
| `orch daemon add nvmeof` | milestone 5 | needs draft 08 (memlock) |
| `orch daemon add osd` | implemented | write path (plan 03): `<host>:/dev/<disk>`, one disk |
| `orch daemon add rgw` | implemented | write path (plan 03): `default <host> [--port N]` |
| `orch daemon redeploy` | implemented | write path (plan 03): without `--image` |
| `orch daemon rm` | implemented | write path (plan 03): mons, mgrs and RGWs |
| `orch device ls` | milestone 5 |  |
| `orch device replace` | milestone 5 |  |
| `orch device zap` | milestone 5 |  |
| `orch get-security-config` | milestone 5 |  |
| `orch hardware light` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `orch hardware powercycle` | implemented | write path (plan 03): maintenance enter, a Talos reboot, maintenance exit; no BMC |
| `orch hardware shutdown` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `orch hardware status` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `orch host add` | implemented | write path (plan 03): a node the CLI enrolled |
| `orch host drain` | implemented | plan 04 step 5 (see `drain_host`) |
| `orch host drain stop` | implemented | plan 04 step 5 (see `stop_drain_host`) |
| `orch host label add` | milestone 5 |  |
| `orch host label rm` | milestone 5 |  |
| `orch host ls` | implemented | read path (plan 02): the talos mgr module, installed as `cephadm` |
| `orch host maintenance enter` | implemented | write path (plan 03) |
| `orch host maintenance exit` | implemented | write path (plan 03) |
| `orch host ok-to-stop` | milestone 5 |  |
| `orch host rescan` | milestone 5 |  |
| `orch host rm` | implemented | write path (plan 03): a host without daemons |
| `orch host set-addr` | implemented | plan 04 step 5 (see `update_host_addr`) |
| `orch ls` | milestone 5 |  |
| `orch osd rm` | implemented | write path (plan 03): with `--zap` and `--force` |
| `orch osd rm status` | implemented | write path (plan 03) |
| `orch osd rm stop` | milestone 5 |  |
| `orch osd set-spec-affinity` | milestone 5 |  |
| `orch pause` | milestone 5 |  |
| `orch prometheus get-credentials` | milestone 5 |  |
| `orch prometheus remove-remote-write` | milestone 5 |  |
| `orch prometheus remove-target` | milestone 5 |  |
| `orch prometheus set-credentials` | milestone 5 |  |
| `orch prometheus set-custom-alerts` | milestone 5 |  |
| `orch prometheus set-remote-write` | milestone 5 |  |
| `orch prometheus set-target` | milestone 5 |  |
| `orch ps` | implemented | read path (plan 02): the talos mgr module, installed as `cephadm` |
| `orch resume` | milestone 5 |  |
| `orch rm` | milestone 5 |  |
| `orch set backend` | implemented | read path (plan 02): the talos mgr module, installed as `cephadm` |
| `orch set-managed` | milestone 5 |  |
| `orch set-unmanaged` | milestone 5 |  |
| `orch status` | implemented | read path (plan 02): the talos mgr module, installed as `cephadm` |
| `orch tuned-profile add-setting` | milestone 5 |  |
| `orch tuned-profile add-settings` | milestone 5 |  |
| `orch tuned-profile apply` | milestone 5 |  |
| `orch tuned-profile ls` | milestone 5 |  |
| `orch tuned-profile rm` | milestone 5 |  |
| `orch tuned-profile rm-setting` | milestone 5 |  |
| `orch tuned-profile rm-settings` | milestone 5 |  |
| `orch unpause` | milestone 5 |  |
| `orch update service` | milestone 5 |  |
| `orch upgrade check` | milestone 5 |  |
| `orch upgrade ls` | milestone 5 |  |
| `orch upgrade pause` | implemented | write path (plan 03) |
| `orch upgrade resume` | implemented | write path (plan 03) |
| `orch upgrade start` | implemented | write path (plan 03): `--image <repository>@sha256:<hex>` |
| `orch upgrade status` | implemented | write path (plan 03) |
| `orch upgrade stop` | implemented | write path (plan 03) |

## Service types

| Name | Status | Note |
|---|---|---|
| `agent` | unsupported | deliberately excluded: the cephadm agent is replaced by the cephadm-talos agent |
| `alertmanager` | milestone 5 |  |
| `alloy` | milestone 5 |  |
| `ceph-exporter` | milestone 5 |  |
| `cephfs-mirror` | milestone 5 |  |
| `container` | milestone 5 |  |
| `crash` | milestone 5 |  |
| `elasticsearch` | milestone 5 |  |
| `grafana` | milestone 5 |  |
| `ingress` | implemented | write path (plan 03): keepalived only, `rgw.default` in front of `rgw.default` |
| `iscsi` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `jaeger-agent` | milestone 5 |  |
| `jaeger-collector` | milestone 5 |  |
| `jaeger-query` | milestone 5 |  |
| `jaeger-tracing` | milestone 5 |  |
| `loki` | milestone 5 |  |
| `mds` | milestone 5 |  |
| `mgmt-gateway` | milestone 5 |  |
| `mgr` | milestone 5 |  |
| `mon` | milestone 5 |  |
| `nfs` | milestone 5 |  |
| `node-exporter` | milestone 5 |  |
| `node-proxy` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `nvmeof` | milestone 5 | needs draft 08 (memlock) |
| `oauth2-proxy` | milestone 5 |  |
| `osd` | milestone 5 |  |
| `prometheus` | milestone 5 |  |
| `promtail` | milestone 5 |  |
| `rbd-mirror` | milestone 5 |  |
| `rgw` | milestone 5 |  |
| `smb` | milestone 5 | needs draft 07 (shared namespaces) |
| `snmp-gateway` | milestone 5 |  |

## Spec fields

| Name | Status | Note |
|---|---|---|
| `agent.certificate_source` | unsupported | follows its service type |
| `agent.config` | unsupported | follows its service type |
| `agent.count` | unsupported | follows its service type |
| `agent.custom_configs` | unsupported | follows its service type |
| `agent.custom_sans` | unsupported | follows its service type |
| `agent.extra_container_args` | unsupported | follows its service type |
| `agent.extra_entrypoint_args` | unsupported | follows its service type |
| `agent.ip_addrs` | unsupported | follows its service type |
| `agent.networks` | unsupported | follows its service type |
| `agent.placement` | unsupported | follows its service type |
| `agent.preview_only` | unsupported | follows its service type |
| `agent.remote_write_allowed_metrics` | unsupported | follows its service type |
| `agent.remote_write_url` | unsupported | follows its service type |
| `agent.service_id` | unsupported | follows its service type |
| `agent.ssl` | unsupported | follows its service type |
| `agent.ssl_ca_cert` | unsupported | follows its service type |
| `agent.ssl_cert` | unsupported | follows its service type |
| `agent.ssl_key` | unsupported | follows its service type |
| `agent.targets` | unsupported | follows its service type |
| `agent.termination_grace_period_seconds` | unsupported | follows its service type |
| `agent.unmanaged` | unsupported | follows its service type |
| `alertmanager.certificate_source` | milestone 5 |  |
| `alertmanager.config` | milestone 5 |  |
| `alertmanager.custom_configs` | milestone 5 |  |
| `alertmanager.extra_container_args` | milestone 5 |  |
| `alertmanager.extra_entrypoint_args` | milestone 5 |  |
| `alertmanager.networks` | milestone 5 |  |
| `alertmanager.only_bind_port_on_networks` | milestone 5 |  |
| `alertmanager.placement` | milestone 5 |  |
| `alertmanager.port` | milestone 5 |  |
| `alertmanager.preview_only` | milestone 5 |  |
| `alertmanager.secure` | milestone 5 |  |
| `alertmanager.service_id` | milestone 5 |  |
| `alertmanager.ssl` | milestone 5 |  |
| `alertmanager.unmanaged` | milestone 5 |  |
| `alertmanager.user_data` | milestone 5 |  |
| `alloy.certificate_source` | milestone 5 |  |
| `alloy.config` | milestone 5 |  |
| `alloy.custom_configs` | milestone 5 |  |
| `alloy.extra_container_args` | milestone 5 |  |
| `alloy.extra_entrypoint_args` | milestone 5 |  |
| `alloy.networks` | milestone 5 |  |
| `alloy.placement` | milestone 5 |  |
| `alloy.port` | milestone 5 |  |
| `alloy.preview_only` | milestone 5 |  |
| `alloy.remote_write_allowed_metrics` | milestone 5 |  |
| `alloy.remote_write_url` | milestone 5 |  |
| `alloy.service_id` | milestone 5 |  |
| `alloy.ssl` | milestone 5 |  |
| `alloy.targets` | milestone 5 |  |
| `alloy.unmanaged` | milestone 5 |  |
| `ceph-exporter.addrs` | milestone 5 |  |
| `ceph-exporter.certificate_source` | milestone 5 |  |
| `ceph-exporter.extra_container_args` | milestone 5 |  |
| `ceph-exporter.extra_entrypoint_args` | milestone 5 |  |
| `ceph-exporter.placement` | milestone 5 |  |
| `ceph-exporter.port` | milestone 5 |  |
| `ceph-exporter.preview_only` | milestone 5 |  |
| `ceph-exporter.prio_limit` | milestone 5 |  |
| `ceph-exporter.sock_dir` | milestone 5 |  |
| `ceph-exporter.ssl` | milestone 5 |  |
| `ceph-exporter.stats_period` | milestone 5 |  |
| `ceph-exporter.unmanaged` | milestone 5 |  |
| `cephfs-mirror.certificate_source` | milestone 5 |  |
| `cephfs-mirror.config` | milestone 5 |  |
| `cephfs-mirror.count` | milestone 5 |  |
| `cephfs-mirror.custom_configs` | milestone 5 |  |
| `cephfs-mirror.custom_sans` | milestone 5 |  |
| `cephfs-mirror.extra_container_args` | milestone 5 |  |
| `cephfs-mirror.extra_entrypoint_args` | milestone 5 |  |
| `cephfs-mirror.ip_addrs` | milestone 5 |  |
| `cephfs-mirror.networks` | milestone 5 |  |
| `cephfs-mirror.placement` | milestone 5 |  |
| `cephfs-mirror.preview_only` | milestone 5 |  |
| `cephfs-mirror.remote_write_allowed_metrics` | milestone 5 |  |
| `cephfs-mirror.remote_write_url` | milestone 5 |  |
| `cephfs-mirror.service_id` | milestone 5 |  |
| `cephfs-mirror.ssl` | milestone 5 |  |
| `cephfs-mirror.ssl_ca_cert` | milestone 5 |  |
| `cephfs-mirror.ssl_cert` | milestone 5 |  |
| `cephfs-mirror.ssl_key` | milestone 5 |  |
| `cephfs-mirror.targets` | milestone 5 |  |
| `cephfs-mirror.termination_grace_period_seconds` | milestone 5 |  |
| `cephfs-mirror.unmanaged` | milestone 5 |  |
| `container.args` | milestone 5 |  |
| `container.bind_mounts` | milestone 5 |  |
| `container.config` | milestone 5 |  |
| `container.custom_configs` | milestone 5 |  |
| `container.dirs` | milestone 5 |  |
| `container.entrypoint` | milestone 5 |  |
| `container.envs` | milestone 5 |  |
| `container.extra_container_args` | milestone 5 |  |
| `container.extra_entrypoint_args` | milestone 5 |  |
| `container.files` | milestone 5 |  |
| `container.gid` | milestone 5 |  |
| `container.image` | milestone 5 |  |
| `container.init_containers` | milestone 5 |  |
| `container.networks` | milestone 5 |  |
| `container.placement` | milestone 5 |  |
| `container.ports` | milestone 5 |  |
| `container.preview_only` | milestone 5 |  |
| `container.privileged` | milestone 5 |  |
| `container.service_id` | milestone 5 |  |
| `container.uid` | milestone 5 |  |
| `container.unmanaged` | milestone 5 |  |
| `container.volume_mounts` | milestone 5 |  |
| `crash.certificate_source` | milestone 5 |  |
| `crash.config` | milestone 5 |  |
| `crash.count` | milestone 5 |  |
| `crash.custom_configs` | milestone 5 |  |
| `crash.custom_sans` | milestone 5 |  |
| `crash.extra_container_args` | milestone 5 |  |
| `crash.extra_entrypoint_args` | milestone 5 |  |
| `crash.ip_addrs` | milestone 5 |  |
| `crash.networks` | milestone 5 |  |
| `crash.placement` | milestone 5 |  |
| `crash.preview_only` | milestone 5 |  |
| `crash.remote_write_allowed_metrics` | milestone 5 |  |
| `crash.remote_write_url` | milestone 5 |  |
| `crash.service_id` | milestone 5 |  |
| `crash.ssl` | milestone 5 |  |
| `crash.ssl_ca_cert` | milestone 5 |  |
| `crash.ssl_cert` | milestone 5 |  |
| `crash.ssl_key` | milestone 5 |  |
| `crash.targets` | milestone 5 |  |
| `crash.termination_grace_period_seconds` | milestone 5 |  |
| `crash.unmanaged` | milestone 5 |  |
| `elasticsearch.config` | milestone 5 |  |
| `elasticsearch.es_nodes` | milestone 5 |  |
| `elasticsearch.networks` | milestone 5 |  |
| `elasticsearch.placement` | milestone 5 |  |
| `elasticsearch.preview_only` | milestone 5 |  |
| `elasticsearch.service_id` | milestone 5 |  |
| `elasticsearch.unmanaged` | milestone 5 |  |
| `elasticsearch.without_query` | milestone 5 |  |
| `grafana.anonymous_access` | milestone 5 |  |
| `grafana.certificate_source` | milestone 5 |  |
| `grafana.config` | milestone 5 |  |
| `grafana.custom_configs` | milestone 5 |  |
| `grafana.extra_container_args` | milestone 5 |  |
| `grafana.extra_entrypoint_args` | milestone 5 |  |
| `grafana.initial_admin_password` | milestone 5 |  |
| `grafana.networks` | milestone 5 |  |
| `grafana.only_bind_port_on_networks` | milestone 5 |  |
| `grafana.placement` | milestone 5 |  |
| `grafana.port` | milestone 5 |  |
| `grafana.preview_only` | milestone 5 |  |
| `grafana.protocol` | milestone 5 |  |
| `grafana.service_id` | milestone 5 |  |
| `grafana.ssl` | milestone 5 |  |
| `grafana.unmanaged` | milestone 5 |  |
| `ingress.backend_service` | implemented | write path (plan 03): `rgw.default` |
| `ingress.certificate_source` | milestone 5 |  |
| `ingress.config` | milestone 5 |  |
| `ingress.custom_configs` | milestone 5 |  |
| `ingress.custom_sans` | milestone 5 |  |
| `ingress.enable_haproxy_protocol` | milestone 5 |  |
| `ingress.enable_stats` | milestone 5 |  |
| `ingress.extra_container_args` | milestone 5 |  |
| `ingress.extra_entrypoint_args` | milestone 5 |  |
| `ingress.first_virtual_router_id` | implemented | write path (plan 03) |
| `ingress.frontend_port` | milestone 5 |  |
| `ingress.haproxy_peer_communication_port` | milestone 5 |  |
| `ingress.health_check_interval` | milestone 5 |  |
| `ingress.keepalive_only` | implemented | write path (plan 03): `true` |
| `ingress.keepalived_password` | implemented | write path (plan 03): 1 to 8 letters and digits |
| `ingress.monitor_cert_source` | milestone 5 |  |
| `ingress.monitor_ip_addrs` | milestone 5 |  |
| `ingress.monitor_networks` | milestone 5 |  |
| `ingress.monitor_password` | milestone 5 |  |
| `ingress.monitor_port` | milestone 5 |  |
| `ingress.monitor_ssl` | milestone 5 |  |
| `ingress.monitor_ssl_cert` | milestone 5 |  |
| `ingress.monitor_ssl_key` | milestone 5 |  |
| `ingress.monitor_user` | milestone 5 |  |
| `ingress.networks` | milestone 5 |  |
| `ingress.placement` | implemented | write path (plan 03): 1 to 15 named hosts with an RGW |
| `ingress.service_id` | implemented | write path (plan 03): `rgw.default` |
| `ingress.ssl` | milestone 5 |  |
| `ingress.ssl_cert` | milestone 5 |  |
| `ingress.ssl_ciphers` | milestone 5 |  |
| `ingress.ssl_dh_param` | milestone 5 |  |
| `ingress.ssl_key` | milestone 5 |  |
| `ingress.ssl_options` | milestone 5 |  |
| `ingress.unmanaged` | milestone 5 |  |
| `ingress.use_keepalived_multicast` | milestone 5 |  |
| `ingress.use_tcp_mode_over_rgw` | milestone 5 |  |
| `ingress.virtual_interface_networks` | milestone 5 |  |
| `ingress.virtual_ip` | implemented | write path (plan 03): one IPv4 address with its prefix length |
| `ingress.virtual_ips_list` | milestone 5 |  |
| `ingress.vrrp_interface_network` | milestone 5 |  |
| `iscsi.api_password` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.api_port` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.api_secure` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.api_user` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.certificate_source` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.config` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.custom_configs` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.custom_sans` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.extra_container_args` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.extra_entrypoint_args` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.networks` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.placement` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.pool` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.preview_only` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.service_id` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.ssl` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.ssl_cert` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.ssl_key` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.trusted_ip_list` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.unmanaged` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `jaeger-agent.config` | milestone 5 |  |
| `jaeger-agent.es_nodes` | milestone 5 |  |
| `jaeger-agent.networks` | milestone 5 |  |
| `jaeger-agent.placement` | milestone 5 |  |
| `jaeger-agent.preview_only` | milestone 5 |  |
| `jaeger-agent.service_id` | milestone 5 |  |
| `jaeger-agent.unmanaged` | milestone 5 |  |
| `jaeger-agent.without_query` | milestone 5 |  |
| `jaeger-collector.config` | milestone 5 |  |
| `jaeger-collector.es_nodes` | milestone 5 |  |
| `jaeger-collector.networks` | milestone 5 |  |
| `jaeger-collector.placement` | milestone 5 |  |
| `jaeger-collector.preview_only` | milestone 5 |  |
| `jaeger-collector.service_id` | milestone 5 |  |
| `jaeger-collector.unmanaged` | milestone 5 |  |
| `jaeger-collector.without_query` | milestone 5 |  |
| `jaeger-query.config` | milestone 5 |  |
| `jaeger-query.es_nodes` | milestone 5 |  |
| `jaeger-query.networks` | milestone 5 |  |
| `jaeger-query.placement` | milestone 5 |  |
| `jaeger-query.preview_only` | milestone 5 |  |
| `jaeger-query.service_id` | milestone 5 |  |
| `jaeger-query.unmanaged` | milestone 5 |  |
| `jaeger-query.without_query` | milestone 5 |  |
| `jaeger-tracing.config` | milestone 5 |  |
| `jaeger-tracing.es_nodes` | milestone 5 |  |
| `jaeger-tracing.networks` | milestone 5 |  |
| `jaeger-tracing.placement` | milestone 5 |  |
| `jaeger-tracing.preview_only` | milestone 5 |  |
| `jaeger-tracing.service_id` | milestone 5 |  |
| `jaeger-tracing.unmanaged` | milestone 5 |  |
| `jaeger-tracing.without_query` | milestone 5 |  |
| `loki.certificate_source` | milestone 5 |  |
| `loki.config` | milestone 5 |  |
| `loki.custom_configs` | milestone 5 |  |
| `loki.extra_container_args` | milestone 5 |  |
| `loki.extra_entrypoint_args` | milestone 5 |  |
| `loki.networks` | milestone 5 |  |
| `loki.placement` | milestone 5 |  |
| `loki.port` | milestone 5 |  |
| `loki.preview_only` | milestone 5 |  |
| `loki.remote_write_allowed_metrics` | milestone 5 |  |
| `loki.remote_write_url` | milestone 5 |  |
| `loki.service_id` | milestone 5 |  |
| `loki.ssl` | milestone 5 |  |
| `loki.targets` | milestone 5 |  |
| `loki.unmanaged` | milestone 5 |  |
| `mds.config` | milestone 5 |  |
| `mds.custom_configs` | milestone 5 |  |
| `mds.extra_container_args` | milestone 5 |  |
| `mds.extra_entrypoint_args` | milestone 5 |  |
| `mds.placement` | milestone 5 |  |
| `mds.preview_only` | milestone 5 |  |
| `mds.service_id` | milestone 5 |  |
| `mds.unmanaged` | milestone 5 |  |
| `mgmt-gateway.certificate_source` | milestone 5 |  |
| `mgmt-gateway.config` | milestone 5 |  |
| `mgmt-gateway.custom_configs` | milestone 5 |  |
| `mgmt-gateway.custom_sans` | milestone 5 |  |
| `mgmt-gateway.enable_auth` | milestone 5 |  |
| `mgmt-gateway.enable_health_check_endpoint` | milestone 5 |  |
| `mgmt-gateway.extra_container_args` | milestone 5 |  |
| `mgmt-gateway.extra_entrypoint_args` | milestone 5 |  |
| `mgmt-gateway.networks` | milestone 5 |  |
| `mgmt-gateway.placement` | milestone 5 |  |
| `mgmt-gateway.port` | milestone 5 |  |
| `mgmt-gateway.preview_only` | milestone 5 |  |
| `mgmt-gateway.server_tokens` | milestone 5 |  |
| `mgmt-gateway.service_id` | milestone 5 |  |
| `mgmt-gateway.ssl` | milestone 5 |  |
| `mgmt-gateway.ssl_cert` | milestone 5 |  |
| `mgmt-gateway.ssl_ciphers` | milestone 5 |  |
| `mgmt-gateway.ssl_key` | milestone 5 |  |
| `mgmt-gateway.ssl_prefer_server_ciphers` | milestone 5 |  |
| `mgmt-gateway.ssl_protocols` | milestone 5 |  |
| `mgmt-gateway.ssl_session_cache` | milestone 5 |  |
| `mgmt-gateway.ssl_session_tickets` | milestone 5 |  |
| `mgmt-gateway.ssl_session_timeout` | milestone 5 |  |
| `mgmt-gateway.ssl_stapling` | milestone 5 |  |
| `mgmt-gateway.ssl_stapling_verify` | milestone 5 |  |
| `mgmt-gateway.unmanaged` | milestone 5 |  |
| `mgmt-gateway.virtual_ip` | milestone 5 |  |
| `mgr.certificate_source` | milestone 5 |  |
| `mgr.config` | milestone 5 |  |
| `mgr.count` | milestone 5 |  |
| `mgr.custom_configs` | milestone 5 |  |
| `mgr.custom_sans` | milestone 5 |  |
| `mgr.extra_container_args` | milestone 5 |  |
| `mgr.extra_entrypoint_args` | milestone 5 |  |
| `mgr.ip_addrs` | milestone 5 |  |
| `mgr.networks` | milestone 5 |  |
| `mgr.placement` | milestone 5 |  |
| `mgr.preview_only` | milestone 5 |  |
| `mgr.remote_write_allowed_metrics` | milestone 5 |  |
| `mgr.remote_write_url` | milestone 5 |  |
| `mgr.service_id` | milestone 5 |  |
| `mgr.ssl` | milestone 5 |  |
| `mgr.ssl_ca_cert` | milestone 5 |  |
| `mgr.ssl_cert` | milestone 5 |  |
| `mgr.ssl_key` | milestone 5 |  |
| `mgr.targets` | milestone 5 |  |
| `mgr.termination_grace_period_seconds` | milestone 5 |  |
| `mgr.unmanaged` | milestone 5 |  |
| `mon.config` | milestone 5 |  |
| `mon.count` | milestone 5 |  |
| `mon.crush_locations` | milestone 5 |  |
| `mon.custom_configs` | milestone 5 |  |
| `mon.extra_container_args` | milestone 5 |  |
| `mon.extra_entrypoint_args` | milestone 5 |  |
| `mon.networks` | milestone 5 |  |
| `mon.placement` | milestone 5 |  |
| `mon.preview_only` | milestone 5 |  |
| `mon.service_id` | milestone 5 |  |
| `mon.unmanaged` | milestone 5 |  |
| `nfs.certificate_source` | milestone 5 |  |
| `nfs.cluster_qos_config` | milestone 5 |  |
| `nfs.cluster_qos_port` | milestone 5 |  |
| `nfs.colocation_ports` | milestone 5 |  |
| `nfs.config` | milestone 5 |  |
| `nfs.custom_configs` | milestone 5 |  |
| `nfs.custom_sans` | milestone 5 |  |
| `nfs.enable_haproxy_protocol` | milestone 5 |  |
| `nfs.enable_nfsv3` | milestone 5 |  |
| `nfs.enable_nlm` | milestone 5 |  |
| `nfs.enable_rdma` | milestone 5 |  |
| `nfs.extra_container_args` | milestone 5 |  |
| `nfs.extra_entrypoint_args` | milestone 5 |  |
| `nfs.idmap_conf` | milestone 5 |  |
| `nfs.ip_addrs` | milestone 5 |  |
| `nfs.monitoring_ip_addrs` | milestone 5 |  |
| `nfs.monitoring_networks` | milestone 5 |  |
| `nfs.monitoring_port` | milestone 5 |  |
| `nfs.networks` | milestone 5 |  |
| `nfs.placement` | milestone 5 |  |
| `nfs.port` | milestone 5 |  |
| `nfs.preview_only` | milestone 5 |  |
| `nfs.rdma_port` | milestone 5 |  |
| `nfs.service_id` | milestone 5 |  |
| `nfs.ssl` | milestone 5 |  |
| `nfs.ssl_ca_cert` | milestone 5 |  |
| `nfs.ssl_cert` | milestone 5 |  |
| `nfs.ssl_key` | milestone 5 |  |
| `nfs.tls_ciphers` | milestone 5 |  |
| `nfs.tls_debug` | milestone 5 |  |
| `nfs.tls_ktls` | milestone 5 |  |
| `nfs.tls_min_version` | milestone 5 |  |
| `nfs.unmanaged` | milestone 5 |  |
| `nfs.virtual_ip` | milestone 5 |  |
| `node-exporter.certificate_source` | milestone 5 |  |
| `node-exporter.config` | milestone 5 |  |
| `node-exporter.custom_configs` | milestone 5 |  |
| `node-exporter.extra_container_args` | milestone 5 |  |
| `node-exporter.extra_entrypoint_args` | milestone 5 |  |
| `node-exporter.networks` | milestone 5 |  |
| `node-exporter.placement` | milestone 5 |  |
| `node-exporter.port` | milestone 5 |  |
| `node-exporter.preview_only` | milestone 5 |  |
| `node-exporter.remote_write_allowed_metrics` | milestone 5 |  |
| `node-exporter.remote_write_url` | milestone 5 |  |
| `node-exporter.service_id` | milestone 5 |  |
| `node-exporter.ssl` | milestone 5 |  |
| `node-exporter.targets` | milestone 5 |  |
| `node-exporter.unmanaged` | milestone 5 |  |
| `node-proxy.certificate_source` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.custom_configs` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.extra_container_args` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.extra_entrypoint_args` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.placement` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.preview_only` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.ssl` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.unmanaged` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `nvmeof.abort_discovery_on_errors` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.abort_on_errors` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.abort_on_update_error` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.addr` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.addr_map` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.allowed_consecutive_spdk_ping_failures` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.bdevs_per_cluster` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.break_update_interval_sec` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.certificate_source` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.client_cert` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.client_key` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.cluster_connections` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.cnc_chunk_blocks` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.cnc_enable` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.cnc_parallel_chunks` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.cnc_rate_limiter_bytes` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.config` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.conn_retries` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.custom_configs` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.custom_sans` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.degrade_namespace_on_kmip_error` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.discovery_addr` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.discovery_addr_map` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.discovery_bind_retries_limit` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.discovery_bind_sleep_interval` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.discovery_port` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.enable_auth` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.enable_dsa_acceleration` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.enable_monitor_client` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.enable_prometheus_exporter` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.enable_spdk_discovery_controller` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.encryption_key` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.extra_container_args` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.extra_entrypoint_args` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.flat_bdevs_per_cluster` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.force_tls` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.group` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.io_stats_enabled` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.iobuf_options` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.kmip_cert_dir` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.log_directory` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.log_files_enabled` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.log_files_rotation_enabled` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.log_level` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.max_gws_in_grp` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.max_hosts` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.max_hosts_per_namespace` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.max_hosts_per_subsystem` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.max_log_directory_backups` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.max_log_file_size_in_mb` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.max_log_files_count` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.max_message_length_in_mb` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.max_namespaces` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.max_namespaces_per_subsystem` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.max_namespaces_with_netmask` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.max_ns_to_change_lb_grp` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.max_subsystems` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.monitor_client_log_file_dir` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.monitor_timeout` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.name` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.networks` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.notifications_interval` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.omap_file_ignore_unlock_errors` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.omap_file_lock_duration` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.omap_file_lock_on_read` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.omap_file_lock_retries` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.omap_file_lock_retry_sleep_interval` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.omap_file_update_attempts` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.omap_file_update_reloads` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.ping_spdk_under_lock` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.placement` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.pool` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.port` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.preview_only` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.prometheus_connection_list_cache_expiration` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.prometheus_cycles_to_adjust_speed` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.prometheus_frequency_slow_down_factor` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.prometheus_port` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.prometheus_startup_delay` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.prometheus_stats_interval` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.qos_timeslice_in_usecs` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.rbd_with_crc32c` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.rebalance_period_sec` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.root_ca_cert` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.rpc_socket_dir` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.rpc_socket_name` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.server_cert` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.server_key` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.service_id` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.spdk_huge_pages` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.spdk_log_file_dir` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.spdk_log_level` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.spdk_mem_size` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.spdk_path` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.spdk_ping_interval_in_seconds` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.spdk_protocol_log_level` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.spdk_timeout` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.ssl` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.ssl_cert` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.ssl_key` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.state_update_interval_sec` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.state_update_notify` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.subsystem_cache_expiration` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.tgt_cmd_extra_args` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.tgt_path` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.transport_tcp_options` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.transports` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.unmanaged` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.verbose_log_messages` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.verify_keys` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.verify_listener_ip` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.verify_nqns` | milestone 5 | needs draft 08 (memlock) |
| `oauth2-proxy.allowlist_domains` | milestone 5 |  |
| `oauth2-proxy.certificate_source` | milestone 5 |  |
| `oauth2-proxy.client_id` | milestone 5 |  |
| `oauth2-proxy.client_secret` | milestone 5 |  |
| `oauth2-proxy.config` | milestone 5 |  |
| `oauth2-proxy.cookie_secret` | milestone 5 |  |
| `oauth2-proxy.custom_configs` | milestone 5 |  |
| `oauth2-proxy.custom_sans` | milestone 5 |  |
| `oauth2-proxy.email_domains` | milestone 5 |  |
| `oauth2-proxy.extra_container_args` | milestone 5 |  |
| `oauth2-proxy.extra_entrypoint_args` | milestone 5 |  |
| `oauth2-proxy.https_address` | milestone 5 |  |
| `oauth2-proxy.networks` | milestone 5 |  |
| `oauth2-proxy.oidc_issuer_url` | milestone 5 |  |
| `oauth2-proxy.placement` | milestone 5 |  |
| `oauth2-proxy.provider_display_name` | milestone 5 |  |
| `oauth2-proxy.redirect_url` | milestone 5 |  |
| `oauth2-proxy.scope` | milestone 5 |  |
| `oauth2-proxy.service_id` | milestone 5 |  |
| `oauth2-proxy.ssl` | milestone 5 |  |
| `oauth2-proxy.ssl_cert` | milestone 5 |  |
| `oauth2-proxy.ssl_insecure_skip_verify` | milestone 5 |  |
| `oauth2-proxy.ssl_key` | milestone 5 |  |
| `oauth2-proxy.unmanaged` | milestone 5 |  |
| `osd.block_db_size` | milestone 5 |  |
| `osd.block_wal_size` | milestone 5 |  |
| `osd.config` | milestone 5 |  |
| `osd.crush_device_class` | milestone 5 |  |
| `osd.custom_configs` | milestone 5 |  |
| `osd.data_allocate_fraction` | milestone 5 |  |
| `osd.data_devices` | milestone 5 |  |
| `osd.data_directories` | milestone 5 |  |
| `osd.db_devices` | milestone 5 |  |
| `osd.db_slots` | milestone 5 |  |
| `osd.encrypted` | milestone 5 |  |
| `osd.extra_container_args` | milestone 5 |  |
| `osd.extra_entrypoint_args` | milestone 5 |  |
| `osd.filter_logic` | milestone 5 |  |
| `osd.journal_devices` | milestone 5 |  |
| `osd.journal_size` | milestone 5 |  |
| `osd.method` | milestone 5 |  |
| `osd.objectstore` | milestone 5 |  |
| `osd.osd_id_claims` | milestone 5 |  |
| `osd.osd_type` | milestone 5 |  |
| `osd.osds_per_device` | milestone 5 |  |
| `osd.placement` | milestone 5 |  |
| `osd.preview_only` | milestone 5 |  |
| `osd.service_id` | milestone 5 |  |
| `osd.termination_grace_period_seconds` | milestone 5 |  |
| `osd.tpm2` | milestone 5 |  |
| `osd.unmanaged` | milestone 5 |  |
| `osd.wal_devices` | milestone 5 |  |
| `osd.wal_slots` | milestone 5 |  |
| `placement.count` | milestone 5 |  |
| `placement.count_per_host` | milestone 5 |  |
| `placement.host_pattern` | milestone 5 |  |
| `placement.hosts` | milestone 5 |  |
| `placement.label` | milestone 5 |  |
| `prometheus.certificate_source` | milestone 5 |  |
| `prometheus.config` | milestone 5 |  |
| `prometheus.custom_configs` | milestone 5 |  |
| `prometheus.extra_container_args` | milestone 5 |  |
| `prometheus.extra_entrypoint_args` | milestone 5 |  |
| `prometheus.networks` | milestone 5 |  |
| `prometheus.only_bind_port_on_networks` | milestone 5 |  |
| `prometheus.placement` | milestone 5 |  |
| `prometheus.port` | milestone 5 |  |
| `prometheus.preview_only` | milestone 5 |  |
| `prometheus.remote_write_allowed_metrics` | milestone 5 |  |
| `prometheus.remote_write_url` | milestone 5 |  |
| `prometheus.retention_size` | milestone 5 |  |
| `prometheus.retention_time` | milestone 5 |  |
| `prometheus.service_id` | milestone 5 |  |
| `prometheus.ssl` | milestone 5 |  |
| `prometheus.targets` | milestone 5 |  |
| `prometheus.unmanaged` | milestone 5 |  |
| `promtail.certificate_source` | milestone 5 |  |
| `promtail.config` | milestone 5 |  |
| `promtail.custom_configs` | milestone 5 |  |
| `promtail.extra_container_args` | milestone 5 |  |
| `promtail.extra_entrypoint_args` | milestone 5 |  |
| `promtail.networks` | milestone 5 |  |
| `promtail.placement` | milestone 5 |  |
| `promtail.port` | milestone 5 |  |
| `promtail.preview_only` | milestone 5 |  |
| `promtail.remote_write_allowed_metrics` | milestone 5 |  |
| `promtail.remote_write_url` | milestone 5 |  |
| `promtail.service_id` | milestone 5 |  |
| `promtail.ssl` | milestone 5 |  |
| `promtail.targets` | milestone 5 |  |
| `promtail.unmanaged` | milestone 5 |  |
| `rbd-mirror.certificate_source` | milestone 5 |  |
| `rbd-mirror.config` | milestone 5 |  |
| `rbd-mirror.count` | milestone 5 |  |
| `rbd-mirror.custom_configs` | milestone 5 |  |
| `rbd-mirror.custom_sans` | milestone 5 |  |
| `rbd-mirror.extra_container_args` | milestone 5 |  |
| `rbd-mirror.extra_entrypoint_args` | milestone 5 |  |
| `rbd-mirror.ip_addrs` | milestone 5 |  |
| `rbd-mirror.networks` | milestone 5 |  |
| `rbd-mirror.placement` | milestone 5 |  |
| `rbd-mirror.preview_only` | milestone 5 |  |
| `rbd-mirror.remote_write_allowed_metrics` | milestone 5 |  |
| `rbd-mirror.remote_write_url` | milestone 5 |  |
| `rbd-mirror.service_id` | milestone 5 |  |
| `rbd-mirror.ssl` | milestone 5 |  |
| `rbd-mirror.ssl_ca_cert` | milestone 5 |  |
| `rbd-mirror.ssl_cert` | milestone 5 |  |
| `rbd-mirror.ssl_key` | milestone 5 |  |
| `rbd-mirror.targets` | milestone 5 |  |
| `rbd-mirror.termination_grace_period_seconds` | milestone 5 |  |
| `rbd-mirror.unmanaged` | milestone 5 |  |
| `rgw.certificate_source` | milestone 5 |  |
| `rgw.config` | milestone 5 |  |
| `rgw.custom_configs` | milestone 5 |  |
| `rgw.custom_sans` | milestone 5 |  |
| `rgw.d3n_cache` | milestone 5 |  |
| `rgw.data_pool_attributes` | milestone 5 |  |
| `rgw.disable_multisite_sync_traffic` | milestone 5 |  |
| `rgw.extra_container_args` | milestone 5 |  |
| `rgw.extra_entrypoint_args` | milestone 5 |  |
| `rgw.generate_cert` | milestone 5 |  |
| `rgw.networks` | milestone 5 |  |
| `rgw.only_bind_port_on_networks` | milestone 5 |  |
| `rgw.placement` | milestone 5 |  |
| `rgw.preview_only` | milestone 5 |  |
| `rgw.qat` | milestone 5 |  |
| `rgw.rgw_bucket_counters_cache` | milestone 5 |  |
| `rgw.rgw_bucket_counters_cache_size` | milestone 5 |  |
| `rgw.rgw_exit_timeout_secs` | milestone 5 |  |
| `rgw.rgw_frontend_extra_args` | milestone 5 |  |
| `rgw.rgw_frontend_port` | implemented | write path (plan 03): one port for every RGW |
| `rgw.rgw_frontend_ssl_certificate` | implemented | write path (plan 03): the operator's certificate and key (`daemon add -i`) |
| `rgw.rgw_frontend_type` | milestone 5 |  |
| `rgw.rgw_realm` | milestone 5 |  |
| `rgw.rgw_realm_token` | milestone 5 |  |
| `rgw.rgw_user_counters_cache` | milestone 5 |  |
| `rgw.rgw_user_counters_cache_size` | milestone 5 |  |
| `rgw.rgw_zone` | milestone 5 |  |
| `rgw.rgw_zonegroup` | milestone 5 |  |
| `rgw.service_id` | milestone 5 |  |
| `rgw.ssl` | implemented | write path (plan 03): an RGW always serves HTTPS; `ssl: false` does not turn TLS off |
| `rgw.ssl_cert` | milestone 5 |  |
| `rgw.ssl_key` | milestone 5 |  |
| `rgw.subcluster` | milestone 5 |  |
| `rgw.unmanaged` | milestone 5 |  |
| `rgw.update_endpoints` | milestone 5 |  |
| `rgw.wildcard_enabled` | milestone 5 |  |
| `rgw.zone_endpoints` | milestone 5 |  |
| `rgw.zonegroup_hostnames` | milestone 5 |  |
| `smb.bind_addrs` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.ceph_cluster_configs` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.cluster_id` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.cluster_lock_uri` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.cluster_meta_uri` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.cluster_public_addrs` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.config` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.config_uri` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.count` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.custom_configs` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.custom_dns` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.custom_ports` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.extra_container_args` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.extra_entrypoint_args` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.features` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.include_ceph_users` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.join_sources` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.keybridge_kmip_ca_cert` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.keybridge_kmip_ssl_cert` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.keybridge_kmip_ssl_key` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.networks` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.placement` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.preview_only` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.remote_control_ca_cert` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.remote_control_ssl_cert` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.remote_control_ssl_key` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.service_id` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.tunables` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.unmanaged` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.user_sources` | milestone 5 | needs draft 07 (shared namespaces) |
| `snmp-gateway.auth_protocol` | milestone 5 |  |
| `snmp-gateway.credentials` | milestone 5 |  |
| `snmp-gateway.custom_configs` | milestone 5 |  |
| `snmp-gateway.engine_id` | milestone 5 |  |
| `snmp-gateway.extra_container_args` | milestone 5 |  |
| `snmp-gateway.extra_entrypoint_args` | milestone 5 |  |
| `snmp-gateway.placement` | milestone 5 |  |
| `snmp-gateway.port` | milestone 5 |  |
| `snmp-gateway.preview_only` | milestone 5 |  |
| `snmp-gateway.privacy_protocol` | milestone 5 |  |
| `snmp-gateway.snmp_destination` | milestone 5 |  |
| `snmp-gateway.snmp_version` | milestone 5 |  |
| `snmp-gateway.unmanaged` | milestone 5 |  |

## Dashboard pages

The dashboard's orchestrator-backed pages (`src/pybind/mgr/dashboard/frontend/src/app/ceph/cluster`).

| Page | Status | Note |
|---|---|---|
| Hosts | milestone 5 | host list, labels, maintenance, drain |
| Physical disks (inventory) | milestone 5 | from Talos disk inventory |
| OSDs: create, remove, replace | milestone 5 | |
| Services | milestone 5 | |
| Upgrade | milestone 5 | |
| Expand cluster (create-cluster) | milestone 5 | |

## CLI commands

What the `cephadm-talos` CLI does. Before the handoff it is the only writer and changes the cluster itself; after it (`handoff`), it refuses its own changes and the cluster is changed through `ceph orch`.

| Command | After the handoff | Closest cephadm command |
|---|---|---|
| `bootstrap` | | `cephadm bootstrap` |
| `handoff` | resumes an interrupted handoff | none (the agents take their nodes, the leader the state) |
| `host add` | enrolls the node, then `orch host add` | `orch host add` |
| `host ls` | yes | `orch host ls` |
| `host rm`, `host maintenance enter`, `host maintenance exit`, `host reboot` | refused: `orch host rm`, `orch host maintenance`, `orch hardware powercycle` | `orch host rm`, `orch host maintenance enter`, `orch host maintenance exit` |
| `deploy mon`, `deploy mgr`, `deploy osd`, `deploy rgw`, `deploy vip` | refused: `orch daemon add`, `orch apply -i` (ingress) | `orch daemon add`, `orch apply ingress` |
| `restart`, `redeploy`, `rm`, `upgrade` | refused: `orch daemon restart`, `orch daemon redeploy`, `orch daemon rm`, `orch osd rm`, `orch upgrade start` | the same `orch` commands |
| `ps`, `ls`, `logs`, `conf` | yes | `orch ps`, `cephadm logs` |
| `shell` | yes, through exec into a mgr or mon container; without a mgr or the mons into a mon | `cephadm shell` |
| `orch` | yes: a `ceph orch` command once per request uuid | none |
| `approve` | yes: the operator's signed approval of images and disks | none |
| `suspend`, `recover mons`, `resume` | yes: recovery after the handoff | none |
| `rm-cluster` | yes, after suspending the agents | `cephadm rm-cluster` |
