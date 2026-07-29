# Optimization Notes

- Keep endpoint input user-supplied or user-approved. Do not add subnet expansion or passive discovery.
- Prefer bounded concurrency over raw parallelism. Heavy censorship networks often amplify timeouts; high fan-out makes measurements less accurate and drains battery.
- Use repeated attempts and rolling stability before showing an endpoint as tunnel-ready.
- Persist raw JSON for forensic comparison between runs.
- For thousands of endpoints, batch scans should expose pause/resume by keeping a durable pending queue in Room.
- For encrypted local storage, replace the Room builder with SQLCipher or AndroidX Security-backed key management. This is optional and should remain user-controlled.
- Community feeds should support signatures or encryption, but must stay opt-in and visible to the user.
