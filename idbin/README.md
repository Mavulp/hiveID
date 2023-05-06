# idbin

## Environment variables

- `DB_PATH`: Required. Specifies where the database should be. If it does not
  exist at the given path a new database will be created.

- `IDP_SECRET_KEY`: Required. The secret key for the `idbin` service. Since
  `idbin` is a service in `idbin` itself, it also needs a secret key. This
  environment variable is required by `idlib`.

- `IDP_REFRESH_ADDR`: Required. The address of the refresh endpoint of idbin.
  This environment variable is required by `idlib`.

- `BIND_ADDRESS`: Required. What address the `idbin` webserver will be hosted
  at. Must be a IP address, eg. `127.0.0.1:8080`.

- `SERVE_DIR`: Optional. Specifies a directory which will be hosted on the
  webserver at `BIND_ADDRESS/static`.


