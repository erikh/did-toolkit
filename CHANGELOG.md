- v0.2.1: Update dependencies
- v0.2.0: Pivot JOSE dependencies (jsonwebtoken, jsonwebkey) to use josekit crate.
  - JWK constructors and some methods now return `Result<JWK, anyhow::Error>`
    instead of just `JWK`.
- v0.1.0: Initial Release
