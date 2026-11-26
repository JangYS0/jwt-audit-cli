# jwt-audit-cli

Zero-dependency offline Node.js (`>=18`) CLI and module to inspect JWTs locally and flag common authentication footguns without ever pasting production tokens into remote web decoders.

## What It Checks

- `alg: "none"` or missing algorithm headers
- Suspicious `kid` header traversal/injection characters and remote `jku`/`x5u` URLs
- Missing or expired `exp`, missing `iss` / `aud` claims
- Sensitive keys (`password`, `secret`, `api_key`) stored in unencrypted JWT payloads
- Oversized tokens (>4 KB) that break reverse proxy header buffers

## Quick Start

```bash
node cli.mjs "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
npm test
```

## Interactive Browser Tools (0B Upload)

- **JWT Decoder (client-side only):** https://global-utils.com/en/jwt-decoder
- **JWK / PEM Key Inspector:** https://global-utils.com/en/jwk-inspector

## License

MIT
