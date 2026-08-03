# CottenDNS Config Presets

These paired configs are bundled for common network conditions:

- `speed`: lower base duplication, MTU-weighted resolver selection, LZ4, and loss-aware MTU probing for faster clean or moderately lossy DNS paths.
- `survival`: more duplication, smaller/stubbier DNS shape, lower MTU ceilings, and earlier auto-FEC for restrictive lossy UDP networks.
- `tcp-survival`: forces DNS-over-TCP/53 on the client and keeps the server TCP listener tuned for long-lived fallback connections.

Use matching pairs:

```text
client_config.speed.toml        + server_config.speed.toml
client_config.survival.toml     + server_config.survival.toml
client_config.tcp-survival.toml + server_config.tcp-survival.toml
```

Fill the delegated domain on both sides and paste the generated server key into
the client config. The client files expect `client_resolvers.txt` beside the
config, same as `client_config.toml.simple`.
