# Example nkeys — DO NOT USE IN REAL DEPLOYMENTS

These seeds are published in this repository. They exist only so the devcontainer
and the e2e tests work out of the box. Anyone can use them to impersonate the
callout issuer or connect as these users.

Generate fresh keys for every real environment and keep them in a secret store.

| File        | Type    | Public key                                                 | Used as                         |
|-------------|---------|------------------------------------------------------------|---------------------------------|
| `issuer.nk` | account | `AARWWQ5UIPIIBO5OES5YXQV2HOOUCP6SA7EKKZFDTYICW4U4UETT3XLS` | `auth_callout.issuer`           |
| `xkey.nk`   | curve   | `XCNO6QXNYUOBP7WSTRTL24BYVF7QGQLSKTH5LFELCUHLUFB2BDVF2CRD` | `auth_callout.xkey`             |
| `user.nk`   | user    | `UDZV37JYJ25PCIY7GFWE2U2ZE6XDJSHI67FRUANOCAX5MUMLOFMJJ76R` | static nkey user in `$G`        |
| `sys.nk`    | user    | `UC64VAZFUIL3XLNHGO7PB7YSV3XZ2NOR4THWA5D2CYK7EGVXYN7QHSCD` | `$SYS` account user             |
