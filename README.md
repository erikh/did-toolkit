## did-toolkit: a toolkit for Decentralized Identity Documents in rust-lang

DID is a relatively new [spec](https://www.w3.org/TR/did-core/) for decentralized
identity. This toolkit aims to support as much of the spec as it can, allowing
you to build services and other tools that are compliant with the
specification.

The toolkit makes a sincere best-effort to maximize compliance with did-core,
and eventually the did-web spec. Decentralized Identity Foundation specs such
as [DWN](https://identity.foundation/decentralized-web-node/spec/) and other
specs I hope will follow.

### Currently Supported Features

-   DID (identifier-only) syntax
    -   Parsing from strings
    -   Generation from pre-populated struct
    -   Construction of DID URLs from DIDs when provided additional URL properties
-   DID URL (different from DID)
    -   Parsing absolute URLs, and mapping relative URLs from absolute ones
    -   Generation from pre-populated struct
    -   Decomposition into the DID that the URL is made from
-   DID Document serialization to JSON, and de-serialization from JSON
    -   Preliminary support for [registry-supported types](https://www.w3.org/TR/did-spec-registries/)
        -   Types with "issues" were elided for implementation safety's sake
    -   Capable of generating JWK ECDSA keys with the P256 curve. More coming here.
-   Preliminary, basic, in-memory Registry. Provides:
    -   mapping of documents to DIDs
    -   cross-referencing of alsoKnownAs in complimentary DIDs as equivalent
    -   controller verification
    -   Lookup of verification method
    -   Optional caching of remote documents on-demand
-   Command-line tool `did-toolkit` generates documents for fuzz testing your registry or DID-compliant implementation:
    -   Generation of documents that are inter-linked via the `alsoKnownAs` and `controller` properties
    -   Generates verification methods for every attribute that takes them
        -   For attributes that also take a DID URL in place of a verification method, occasionally generates attribute properties which are simply links into other verification methods
    -   It also generates ASCII percent-encoded DIDs that are non-compliant with UTF-8
        -   Should break some implementations that use UTF-8 strings to parse these

### Planned Features

-   Complete implementation of the [did-method-web specification](https://w3c-ccg.github.io/did-method-web/)
-   Implementation of Verification Methods (encryption, signing, etc)

### Regarding support in general:

-   Consumption of formats:
    -   JSON-LD support is _not_ planned due to the existing JSON-LD parser
        implementations requiring non-standard JSON libraries that don't
        integrate with anything else, including reqwest, which is used to locate
        remote documents. If someone designs a JSON-LD implementation I can
        simply consume I will bother. I have some personal and pointed feelings
        about this standard as a former, scar-riddled consumer of XML standards
        that insist I do not attempt to implement this myself.
    -   CBOR ingestion and production should be doable outside of this library,
        but we will attempt to support it as of this writing.

### Author

Erik Hollensbe <erik+github@hollensbe.org>

### License

MIT
