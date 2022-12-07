# id

A bunch of projects for managing the identity with Hivecom services.

## idbin

The identity provider for Hivecom services. Hivecom services will redirect to
this in order to let the user authenticate themselves.

The authentication flow looks something like this:

```mermaid
sequenceDiagram
    actor A as Alice
    participant S as Service
    participant I as idbin
    
    A->>S: GET /protected-resource
        note right of A: Without a JWT cookie.
    S->>A: 302 https://idbin/login?service=Service
    A->>I: GET /login?service=Service

    I->>A: 302 https://idbin/login?service=Service
        note right of A: Contains a JWT cookie.
    A->>S: GET /protected-resource
    S->>A: 200 OK
```

## idlib

A Rust library for the axum web framework for dealing with authentication and
authorization of endpoints.
