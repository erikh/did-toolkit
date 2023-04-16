## did-toolkit: a toolkit for Distributed Identity Documents in rust-lang

DID is a relatively new [spec](https://www.w3.org/TR/did-core/) for distributed
identity. This toolkit aims to support as much of the spec as it can, allowing
you to build services and other tools that are compliant with the
specification.

### Currently Supported Features

-   DID (identifier-only) syntax
-   DID URL (different from DID)
    -   Parsing absolute URLs, and mapping relative URLs from absolute ones
    -   Generation from pre-populated struct

### Planned Features

-   Complete implementation of the [did-method-web specification](https://w3c-ccg.github.io/did-method-web/)
-   Verification Methods
-   Consumption of JSON and JSON-LD

### Author

Erik Hollensbe <erik+github@hollensbe.org>

### License

MIT
