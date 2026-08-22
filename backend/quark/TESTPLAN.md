# Quark Drive backend test plan

The backend is upload-only because the open platform cannot enumerate or
delete files. The standard backend integration suite is therefore not
applicable.

Unit tests use a local HTTP server to cover:

- open-platform request signatures and access-token query parameters;
- idempotent nested directory creation;
- proof fields, multipart SHA-1 contexts, part uploads, hash update, and upload
  completion;
- object-storage retry behavior without leaking the access token;
- access-token rotation and persistence of replacement credentials;
- explicit errors for listing, reading, and deleting.

A credentialed smoke test should upload a small directory with a unique target:

```console
rclone copy ./testdata TestQuark:smoke/UNIQUE-RUN-ID --no-traverse -vv
```

Verify the result in the Quark Drive application. Never reuse the smoke-test
destination, since the backend cannot inspect or remove it.
