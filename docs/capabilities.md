# Capability matrix

What cephadm-talos provides of the Ceph orchestrator interface, for Ceph v20.2.4 (tag `v20.2.4`, commit `7f793731f1b39eb4f465e960113d2363c311b964`). Status is `implemented`, `milestone N` (planned in that [roadmap](../ROADMAP.md) milestone) or `unsupported`. Nothing is `implemented` yet: the PoC CLI is not a `ceph orch` backend.

The first four sections are checked against the Ceph source by `hack/capabilities.py <ceph source>`; the last two are maintained by hand.

## Orchestrator methods

| Name | Status | Note |
|---|---|---|
| `add_daemon` | milestone 5 |  |
| `add_host` | milestone 5 |  |
| `add_host_label` | milestone 5 |  |
| `apply` | milestone 5 |  |
| `apply_alertmanager` | milestone 5 |  |
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
| `available` | milestone 3 |  |
| `blink_device_light` | milestone 5 | to validate on Talos (lsmcli in a privileged job) |
| `cancel_completions` | milestone 3 |  |
| `cert_store_cert_check` | milestone 5 |  |
| `cert_store_cert_ls` | milestone 5 |  |
| `cert_store_entity_ls` | milestone 5 |  |
| `cert_store_get_cert` | milestone 5 |  |
| `cert_store_get_key` | milestone 5 |  |
| `cert_store_key_ls` | milestone 5 |  |
| `cert_store_reload` | milestone 5 |  |
| `cert_store_rm_cert` | milestone 5 |  |
| `cert_store_rm_key` | milestone 5 |  |
| `cert_store_set_cert` | milestone 5 |  |
| `cert_store_set_key` | milestone 5 |  |
| `cert_store_set_pair` | milestone 5 |  |
| `create_osds` | milestone 5 |  |
| `daemon_action` | milestone 5 |  |
| `describe_service` | milestone 5 |  |
| `drain_host` | milestone 5 |  |
| `enter_host_maintenance` | milestone 5 |  |
| `exit_host_maintenance` | milestone 5 |  |
| `generate_certificates` | milestone 5 |  |
| `get_alertmanager_access_info` | milestone 5 |  |
| `get_facts` | milestone 5 |  |
| `get_feature_set` | milestone 3 |  |
| `get_hosts` | milestone 5 |  |
| `get_inventory` | milestone 5 |  |
| `get_prometheus_access_info` | milestone 5 |  |
| `get_security_config` | milestone 5 |  |
| `hardware_light` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `hardware_powercycle` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `hardware_shutdown` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `hardware_status` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `host_ok_to_stop` | milestone 5 |  |
| `is_orchestrator_module` | milestone 3 |  |
| `list_daemons` | milestone 5 |  |
| `node_proxy_common` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node_proxy_criticals` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node_proxy_firmware` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node_proxy_firmwares` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node_proxy_fullreport` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node_proxy_summary` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `pause` | milestone 5 |  |
| `plan` | milestone 5 |  |
| `preview_osdspecs` | milestone 5 |  |
| `remove_daemons` | milestone 5 |  |
| `remove_host` | milestone 5 |  |
| `remove_host_label` | milestone 5 |  |
| `remove_osds` | milestone 5 |  |
| `remove_osds_status` | milestone 5 |  |
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
| `set_prometheus_target` | milestone 5 |  |
| `set_unmanaged` | milestone 5 |  |
| `set_unmanaged_flag` | milestone 5 |  |
| `stop_drain_host` | milestone 5 |  |
| `stop_remove_osds` | milestone 5 |  |
| `tuned_profile_add_setting` | milestone 5 |  |
| `tuned_profile_add_settings` | milestone 5 |  |
| `tuned_profile_ls` | milestone 5 |  |
| `tuned_profile_rm_setting` | milestone 5 |  |
| `tuned_profile_rm_settings` | milestone 5 |  |
| `update_host_addr` | milestone 5 |  |
| `update_service` | milestone 5 |  |
| `upgrade_available` | milestone 5 |  |
| `upgrade_check` | milestone 5 |  |
| `upgrade_ls` | milestone 5 |  |
| `upgrade_pause` | milestone 5 |  |
| `upgrade_resume` | milestone 5 |  |
| `upgrade_start` | milestone 5 |  |
| `upgrade_status` | milestone 5 |  |
| `upgrade_stop` | milestone 5 |  |
| `zap_device` | milestone 5 |  |

## ceph orch commands

| Name | Status | Note |
|---|---|---|
| `device light` | milestone 5 | to validate on Talos (lsmcli in a privileged job) |
| `device ls-lights` | milestone 5 | to validate on Talos (lsmcli in a privileged job) |
| `orch` | milestone 5 | service action: start, stop, restart, redeploy, reconfig of a whole service |
| `orch alertmanager get-credentials` | milestone 5 |  |
| `orch alertmanager set-credentials` | milestone 5 |  |
| `orch apply` | milestone 5 |  |
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
| `orch certmgr cert check` | milestone 5 |  |
| `orch certmgr cert get` | milestone 5 |  |
| `orch certmgr cert ls` | milestone 5 |  |
| `orch certmgr cert rm` | milestone 5 |  |
| `orch certmgr cert set` | milestone 5 |  |
| `orch certmgr cert-key set` | milestone 5 |  |
| `orch certmgr entity ls` | milestone 5 |  |
| `orch certmgr generate-certificates` | milestone 5 |  |
| `orch certmgr key get` | milestone 5 |  |
| `orch certmgr key ls` | milestone 5 |  |
| `orch certmgr key rm` | milestone 5 |  |
| `orch certmgr key set` | milestone 5 |  |
| `orch certmgr reload` | milestone 5 |  |
| `orch client-keyring ls` | milestone 5 |  |
| `orch client-keyring rm` | milestone 5 |  |
| `orch client-keyring set` | milestone 5 |  |
| `orch daemon` | milestone 5 |  |
| `orch daemon add` | milestone 5 |  |
| `orch daemon add iscsi` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `orch daemon add mds` | milestone 5 |  |
| `orch daemon add nfs` | milestone 5 |  |
| `orch daemon add nvmeof` | milestone 5 | needs draft 08 (memlock) |
| `orch daemon add osd` | milestone 5 |  |
| `orch daemon add rgw` | milestone 5 |  |
| `orch daemon redeploy` | milestone 5 |  |
| `orch daemon rm` | milestone 5 |  |
| `orch device ls` | milestone 5 |  |
| `orch device replace` | milestone 5 |  |
| `orch device zap` | milestone 5 |  |
| `orch get-security-config` | milestone 5 |  |
| `orch hardware light` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `orch hardware powercycle` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `orch hardware shutdown` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `orch hardware status` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `orch host add` | milestone 5 |  |
| `orch host drain` | milestone 5 |  |
| `orch host drain stop` | milestone 5 |  |
| `orch host label add` | milestone 5 |  |
| `orch host label rm` | milestone 5 |  |
| `orch host ls` | milestone 5 |  |
| `orch host maintenance enter` | milestone 5 |  |
| `orch host maintenance exit` | milestone 5 |  |
| `orch host ok-to-stop` | milestone 5 |  |
| `orch host rescan` | milestone 5 |  |
| `orch host rm` | milestone 5 |  |
| `orch host set-addr` | milestone 5 |  |
| `orch ls` | milestone 5 |  |
| `orch osd rm` | milestone 5 |  |
| `orch osd rm status` | milestone 5 |  |
| `orch osd rm stop` | milestone 5 |  |
| `orch osd set-spec-affinity` | milestone 5 |  |
| `orch pause` | milestone 5 |  |
| `orch prometheus get-credentials` | milestone 5 |  |
| `orch prometheus remove-target` | milestone 5 |  |
| `orch prometheus set-credentials` | milestone 5 |  |
| `orch prometheus set-custom-alerts` | milestone 5 |  |
| `orch prometheus set-target` | milestone 5 |  |
| `orch ps` | milestone 5 |  |
| `orch resume` | milestone 5 |  |
| `orch rm` | milestone 5 |  |
| `orch set backend` | milestone 3 |  |
| `orch set-managed` | milestone 5 |  |
| `orch set-unmanaged` | milestone 5 |  |
| `orch status` | milestone 3 |  |
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
| `orch upgrade pause` | milestone 5 |  |
| `orch upgrade resume` | milestone 5 |  |
| `orch upgrade start` | milestone 5 |  |
| `orch upgrade status` | milestone 5 |  |
| `orch upgrade stop` | milestone 5 |  |

## Service types

| Name | Status | Note |
|---|---|---|
| `agent` | unsupported | deliberately excluded: the cephadm agent is replaced by the cephadm-talos agent |
| `alertmanager` | milestone 5 |  |
| `ceph-exporter` | milestone 5 |  |
| `cephfs-mirror` | milestone 5 |  |
| `container` | milestone 5 |  |
| `crash` | milestone 5 |  |
| `elasticsearch` | milestone 5 |  |
| `grafana` | milestone 5 |  |
| `ingress` | milestone 5 |  |
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
| `agent.config` | unsupported | follows its service type |
| `agent.count` | unsupported | follows its service type |
| `agent.custom_configs` | unsupported | follows its service type |
| `agent.extra_container_args` | unsupported | follows its service type |
| `agent.extra_entrypoint_args` | unsupported | follows its service type |
| `agent.networks` | unsupported | follows its service type |
| `agent.placement` | unsupported | follows its service type |
| `agent.preview_only` | unsupported | follows its service type |
| `agent.service_id` | unsupported | follows its service type |
| `agent.targets` | unsupported | follows its service type |
| `agent.unmanaged` | unsupported | follows its service type |
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
| `alertmanager.unmanaged` | milestone 5 |  |
| `alertmanager.user_data` | milestone 5 |  |
| `ceph-exporter.addrs` | milestone 5 |  |
| `ceph-exporter.extra_container_args` | milestone 5 |  |
| `ceph-exporter.extra_entrypoint_args` | milestone 5 |  |
| `ceph-exporter.placement` | milestone 5 |  |
| `ceph-exporter.port` | milestone 5 |  |
| `ceph-exporter.preview_only` | milestone 5 |  |
| `ceph-exporter.prio_limit` | milestone 5 |  |
| `ceph-exporter.sock_dir` | milestone 5 |  |
| `ceph-exporter.stats_period` | milestone 5 |  |
| `ceph-exporter.unmanaged` | milestone 5 |  |
| `cephfs-mirror.config` | milestone 5 |  |
| `cephfs-mirror.count` | milestone 5 |  |
| `cephfs-mirror.custom_configs` | milestone 5 |  |
| `cephfs-mirror.extra_container_args` | milestone 5 |  |
| `cephfs-mirror.extra_entrypoint_args` | milestone 5 |  |
| `cephfs-mirror.networks` | milestone 5 |  |
| `cephfs-mirror.placement` | milestone 5 |  |
| `cephfs-mirror.preview_only` | milestone 5 |  |
| `cephfs-mirror.service_id` | milestone 5 |  |
| `cephfs-mirror.targets` | milestone 5 |  |
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
| `crash.config` | milestone 5 |  |
| `crash.count` | milestone 5 |  |
| `crash.custom_configs` | milestone 5 |  |
| `crash.extra_container_args` | milestone 5 |  |
| `crash.extra_entrypoint_args` | milestone 5 |  |
| `crash.networks` | milestone 5 |  |
| `crash.placement` | milestone 5 |  |
| `crash.preview_only` | milestone 5 |  |
| `crash.service_id` | milestone 5 |  |
| `crash.targets` | milestone 5 |  |
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
| `grafana.unmanaged` | milestone 5 |  |
| `ingress.backend_service` | milestone 5 |  |
| `ingress.config` | milestone 5 |  |
| `ingress.custom_configs` | milestone 5 |  |
| `ingress.enable_haproxy_protocol` | milestone 5 |  |
| `ingress.enable_stats` | milestone 5 |  |
| `ingress.extra_container_args` | milestone 5 |  |
| `ingress.extra_entrypoint_args` | milestone 5 |  |
| `ingress.first_virtual_router_id` | milestone 5 |  |
| `ingress.frontend_port` | milestone 5 |  |
| `ingress.health_check_interval` | milestone 5 |  |
| `ingress.keepalive_only` | milestone 5 |  |
| `ingress.keepalived_password` | milestone 5 |  |
| `ingress.monitor_password` | milestone 5 |  |
| `ingress.monitor_port` | milestone 5 |  |
| `ingress.monitor_user` | milestone 5 |  |
| `ingress.networks` | milestone 5 |  |
| `ingress.placement` | milestone 5 |  |
| `ingress.service_id` | milestone 5 |  |
| `ingress.ssl` | milestone 5 |  |
| `ingress.ssl_cert` | milestone 5 |  |
| `ingress.ssl_ciphers` | milestone 5 |  |
| `ingress.ssl_dh_param` | milestone 5 |  |
| `ingress.ssl_key` | milestone 5 |  |
| `ingress.ssl_options` | milestone 5 |  |
| `ingress.unmanaged` | milestone 5 |  |
| `ingress.use_keepalived_multicast` | milestone 5 |  |
| `ingress.virtual_interface_networks` | milestone 5 |  |
| `ingress.virtual_ip` | milestone 5 |  |
| `ingress.virtual_ips_list` | milestone 5 |  |
| `ingress.vrrp_interface_network` | milestone 5 |  |
| `iscsi.api_password` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.api_port` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.api_secure` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.api_user` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.config` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.custom_configs` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.extra_container_args` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.extra_entrypoint_args` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.networks` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.placement` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.pool` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.preview_only` | milestone 5 | to validate on Talos (configfs, kernel modules) |
| `iscsi.service_id` | milestone 5 | to validate on Talos (configfs, kernel modules) |
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
| `loki.config` | milestone 5 |  |
| `loki.custom_configs` | milestone 5 |  |
| `loki.extra_container_args` | milestone 5 |  |
| `loki.extra_entrypoint_args` | milestone 5 |  |
| `loki.networks` | milestone 5 |  |
| `loki.placement` | milestone 5 |  |
| `loki.port` | milestone 5 |  |
| `loki.preview_only` | milestone 5 |  |
| `loki.service_id` | milestone 5 |  |
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
| `mgmt-gateway.config` | milestone 5 |  |
| `mgmt-gateway.custom_configs` | milestone 5 |  |
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
| `mgr.config` | milestone 5 |  |
| `mgr.count` | milestone 5 |  |
| `mgr.custom_configs` | milestone 5 |  |
| `mgr.extra_container_args` | milestone 5 |  |
| `mgr.extra_entrypoint_args` | milestone 5 |  |
| `mgr.networks` | milestone 5 |  |
| `mgr.placement` | milestone 5 |  |
| `mgr.preview_only` | milestone 5 |  |
| `mgr.service_id` | milestone 5 |  |
| `mgr.targets` | milestone 5 |  |
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
| `nfs.config` | milestone 5 |  |
| `nfs.custom_configs` | milestone 5 |  |
| `nfs.enable_haproxy_protocol` | milestone 5 |  |
| `nfs.enable_nfsv3` | milestone 5 |  |
| `nfs.enable_nlm` | milestone 5 |  |
| `nfs.extra_container_args` | milestone 5 |  |
| `nfs.extra_entrypoint_args` | milestone 5 |  |
| `nfs.idmap_conf` | milestone 5 |  |
| `nfs.monitoring_port` | milestone 5 |  |
| `nfs.networks` | milestone 5 |  |
| `nfs.placement` | milestone 5 |  |
| `nfs.port` | milestone 5 |  |
| `nfs.preview_only` | milestone 5 |  |
| `nfs.service_id` | milestone 5 |  |
| `nfs.unmanaged` | milestone 5 |  |
| `nfs.virtual_ip` | milestone 5 |  |
| `node-exporter.config` | milestone 5 |  |
| `node-exporter.custom_configs` | milestone 5 |  |
| `node-exporter.extra_container_args` | milestone 5 |  |
| `node-exporter.extra_entrypoint_args` | milestone 5 |  |
| `node-exporter.networks` | milestone 5 |  |
| `node-exporter.placement` | milestone 5 |  |
| `node-exporter.port` | milestone 5 |  |
| `node-exporter.preview_only` | milestone 5 |  |
| `node-exporter.service_id` | milestone 5 |  |
| `node-exporter.targets` | milestone 5 |  |
| `node-exporter.unmanaged` | milestone 5 |  |
| `node-proxy.config` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.count` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.custom_configs` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.extra_container_args` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.extra_entrypoint_args` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.networks` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.placement` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.preview_only` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.service_id` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.targets` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `node-proxy.unmanaged` | milestone 5 | to validate on Talos (node-proxy talks to the BMC over Redfish) |
| `nvmeof.abort_discovery_on_errors` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.abort_on_errors` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.abort_on_update_error` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.addr` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.addr_map` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.allowed_consecutive_spdk_ping_failures` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.bdevs_per_cluster` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.break_update_interval_sec` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.client_cert` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.client_key` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.cluster_connections` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.config` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.conn_retries` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.custom_configs` | milestone 5 | needs draft 08 (memlock) |
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
| `nvmeof.omap_file_update_reloads` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.ping_spdk_under_lock` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.placement` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.pool` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.port` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.preview_only` | milestone 5 | needs draft 08 (memlock) |
| `nvmeof.prometheus_connection_list_cache_expiration` | milestone 5 | needs draft 08 (memlock) |
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
| `oauth2-proxy.client_id` | milestone 5 |  |
| `oauth2-proxy.client_secret` | milestone 5 |  |
| `oauth2-proxy.config` | milestone 5 |  |
| `oauth2-proxy.cookie_secret` | milestone 5 |  |
| `oauth2-proxy.custom_configs` | milestone 5 |  |
| `oauth2-proxy.extra_container_args` | milestone 5 |  |
| `oauth2-proxy.extra_entrypoint_args` | milestone 5 |  |
| `oauth2-proxy.https_address` | milestone 5 |  |
| `oauth2-proxy.networks` | milestone 5 |  |
| `oauth2-proxy.oidc_issuer_url` | milestone 5 |  |
| `oauth2-proxy.placement` | milestone 5 |  |
| `oauth2-proxy.provider_display_name` | milestone 5 |  |
| `oauth2-proxy.redirect_url` | milestone 5 |  |
| `oauth2-proxy.service_id` | milestone 5 |  |
| `oauth2-proxy.ssl_cert` | milestone 5 |  |
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
| `osd.osds_per_device` | milestone 5 |  |
| `osd.placement` | milestone 5 |  |
| `osd.preview_only` | milestone 5 |  |
| `osd.service_id` | milestone 5 |  |
| `osd.tpm2` | milestone 5 |  |
| `osd.unmanaged` | milestone 5 |  |
| `osd.wal_devices` | milestone 5 |  |
| `osd.wal_slots` | milestone 5 |  |
| `placement.count` | milestone 5 |  |
| `placement.count_per_host` | milestone 5 |  |
| `placement.host_pattern` | milestone 5 |  |
| `placement.hosts` | milestone 5 |  |
| `placement.label` | milestone 5 |  |
| `prometheus.config` | milestone 5 |  |
| `prometheus.custom_configs` | milestone 5 |  |
| `prometheus.extra_container_args` | milestone 5 |  |
| `prometheus.extra_entrypoint_args` | milestone 5 |  |
| `prometheus.networks` | milestone 5 |  |
| `prometheus.only_bind_port_on_networks` | milestone 5 |  |
| `prometheus.placement` | milestone 5 |  |
| `prometheus.port` | milestone 5 |  |
| `prometheus.preview_only` | milestone 5 |  |
| `prometheus.retention_size` | milestone 5 |  |
| `prometheus.retention_time` | milestone 5 |  |
| `prometheus.service_id` | milestone 5 |  |
| `prometheus.targets` | milestone 5 |  |
| `prometheus.unmanaged` | milestone 5 |  |
| `promtail.config` | milestone 5 |  |
| `promtail.custom_configs` | milestone 5 |  |
| `promtail.extra_container_args` | milestone 5 |  |
| `promtail.extra_entrypoint_args` | milestone 5 |  |
| `promtail.networks` | milestone 5 |  |
| `promtail.placement` | milestone 5 |  |
| `promtail.port` | milestone 5 |  |
| `promtail.preview_only` | milestone 5 |  |
| `promtail.service_id` | milestone 5 |  |
| `promtail.targets` | milestone 5 |  |
| `promtail.unmanaged` | milestone 5 |  |
| `rbd-mirror.config` | milestone 5 |  |
| `rbd-mirror.count` | milestone 5 |  |
| `rbd-mirror.custom_configs` | milestone 5 |  |
| `rbd-mirror.extra_container_args` | milestone 5 |  |
| `rbd-mirror.extra_entrypoint_args` | milestone 5 |  |
| `rbd-mirror.networks` | milestone 5 |  |
| `rbd-mirror.placement` | milestone 5 |  |
| `rbd-mirror.preview_only` | milestone 5 |  |
| `rbd-mirror.service_id` | milestone 5 |  |
| `rbd-mirror.targets` | milestone 5 |  |
| `rbd-mirror.unmanaged` | milestone 5 |  |
| `rgw.config` | milestone 5 |  |
| `rgw.custom_configs` | milestone 5 |  |
| `rgw.data_pool_attributes` | milestone 5 |  |
| `rgw.disable_multisite_sync_traffic` | milestone 5 |  |
| `rgw.extra_container_args` | milestone 5 |  |
| `rgw.extra_entrypoint_args` | milestone 5 |  |
| `rgw.generate_cert` | milestone 5 |  |
| `rgw.networks` | milestone 5 |  |
| `rgw.only_bind_port_on_networks` | milestone 5 |  |
| `rgw.placement` | milestone 5 |  |
| `rgw.preview_only` | milestone 5 |  |
| `rgw.rgw_bucket_counters_cache` | milestone 5 |  |
| `rgw.rgw_bucket_counters_cache_size` | milestone 5 |  |
| `rgw.rgw_exit_timeout_secs` | milestone 5 |  |
| `rgw.rgw_frontend_extra_args` | milestone 5 |  |
| `rgw.rgw_frontend_port` | milestone 5 |  |
| `rgw.rgw_frontend_ssl_certificate` | milestone 5 |  |
| `rgw.rgw_frontend_type` | milestone 5 |  |
| `rgw.rgw_realm` | milestone 5 |  |
| `rgw.rgw_realm_token` | milestone 5 |  |
| `rgw.rgw_user_counters_cache` | milestone 5 |  |
| `rgw.rgw_user_counters_cache_size` | milestone 5 |  |
| `rgw.rgw_zone` | milestone 5 |  |
| `rgw.rgw_zonegroup` | milestone 5 |  |
| `rgw.service_id` | milestone 5 |  |
| `rgw.ssl` | milestone 5 |  |
| `rgw.subcluster` | milestone 5 |  |
| `rgw.unmanaged` | milestone 5 |  |
| `rgw.update_endpoints` | milestone 5 |  |
| `rgw.wildcard_enabled` | milestone 5 |  |
| `rgw.zone_endpoints` | milestone 5 |  |
| `rgw.zonegroup_hostnames` | milestone 5 |  |
| `smb.bind_addrs` | milestone 5 | needs draft 07 (shared namespaces) |
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
| `smb.networks` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.placement` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.preview_only` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.remote_control_ca_cert` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.remote_control_ssl_cert` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.remote_control_ssl_key` | milestone 5 | needs draft 07 (shared namespaces) |
| `smb.service_id` | milestone 5 | needs draft 07 (shared namespaces) |
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

## PoC CLI commands

What the PoC `cephadm-talos` CLI does today. These commands work but are not a `ceph orch` interface.

| Command | Closest `ceph orch` command |
|---|---|
| `bootstrap` | `cephadm bootstrap` |
| `host add`, `host ls`, `host rm` | `orch host add`, `orch host ls`, `orch host rm` |
| `host maintenance enter`, `host maintenance exit` | `orch host maintenance enter`, `orch host maintenance exit` |
| `host reboot` | none (maintenance enter, Talos reboot, maintenance exit) |
| `deploy mon`, `deploy mgr`, `deploy osd`, `deploy rgw`, `deploy vip` | `orch daemon add` |
| `ps`, `ls` | `orch ps` |
| `logs` | `cephadm logs` |
| `restart`, `redeploy` | `orch daemon restart`, `orch daemon redeploy` |
| `rm` | `orch daemon rm`, `orch osd rm` |
| `upgrade` | `orch upgrade start` |
| `shell` | `cephadm shell` |
| `rm-cluster` | `cephadm rm-cluster` |
| `conf` | none (prints ceph.conf and the admin keyring) |
