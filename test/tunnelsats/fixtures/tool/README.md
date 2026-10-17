# Tool documents for the contract-call tests

| File | Source |
| :-- | :-- |
| `detect_none.json`, `detect_legacy.json`, `detect_managed.json` | `generate.sh`: real `detect --json` documents of the pinned `tunnelsats.sh`, produced by its own unprivileged harness (no install; a standard v3 install after #204; a managed install). `uname` and `wg --version` are stubbed so no data of the generating machine appears. |
| `install_ok.json`, `install_ok_stopped.json` | hand-written with the field list of `cmd_install_managed` at the pinned commit (`managed`, `profile`, `impl`, `unit`, `node_user`, `uid_backstop`, `iface`, `slice`, `tunnel_started`, `ln_was_active`, `ln_restarted`, `node_config`, `other_ln_units`) |
| `install_capability.json`, `install_managed_present.json` | hand-written failure documents (`ts_fail` envelope) for exit 6 and exit 7 (`E_MANAGED_PRESENT`) |
| `uninstall_disabled.json`, `uninstall_incomplete.json`, `uninstall_not_installed.json` | hand-written with the field list of `cmd_uninstall_managed` at the pinned commit (`managed`, `unit`, `remaining`, `ln_was_active`, `ln_started`, `ln_disabled`, `node_config`, `action_required`); on RaspiBlitz the start-guard variable in `ExecStart` makes `node_config` `unknown`, so the unit is disabled |
