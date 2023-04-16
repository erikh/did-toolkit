## did-toolkit: a toolkit for Decentralized Identity Documents in rust-lang

DID is a relatively new [spec](https://www.w3.org/TR/did-core/) for decentralized
identity. This toolkit aims to support as much of the spec as it can, allowing
you to build services and other tools that are compliant with the
specification.

### Currently Supported Features

-   DID (identifier-only) syntax
    -   Parsing from strings
    -   Generation from pre-populated struct
-   DID URL (different from DID)
    -   Parsing absolute URLs, and mapping relative URLs from absolute ones
    -   Generation from pre-populated struct
-   DID Document (de)serialization
    -   Preliminary support for [registry-supported types](https://www.w3.org/TR/did-spec-registries/)
        -   Types with "issues" were elided for implementation safety's sake

### Planned Features

-   Complete implementation of the [did-method-web specification](https://w3c-ccg.github.io/did-method-web/)
-   Verification Methods
-   Consumption of JSON and JSON-LD

### Author

Erik Hollensbe <erik+github@hollensbe.org>

### License

MIT
