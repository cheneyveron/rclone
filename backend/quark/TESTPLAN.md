# Quark Drive backend test plan

The backend cannot enumerate or delete files. It maintains a local path-to-FID
state file so scheduled `copy --no-traverse` jobs can detect and replace files.
The standard backend integration suite is therefore not applicable.

Unit tests use a local HTTP server to cover:

- open-platform request signatures and access-token query parameters;
- idempotent nested directory creation;
- proof fields, multipart SHA-1 contexts, part uploads, hash update, and upload
  completion;
- object-storage retry behavior without leaking the access token;
- access-token rotation and persistence of replacement credentials;
- state persistence across backend restarts;
- replacement through staging and version directories;
- asynchronous move completion and recovery after a failed move without a
  duplicate upload;
- explicit errors for listing, reading, and deleting.

A credentialed smoke test should upload a small directory, change one file,
and upload it again to the same target:

```console
rclone copy ./testdata TestQuark:smoke/stateful-test --no-traverse -vv
# modify ./testdata/file.txt
rclone copy ./testdata TestQuark:smoke/stateful-test --no-traverse -vv
```

Verify that the current directory contains the changed file and that the old
FID is below `.rclone-versions`. Remove the smoke-test data manually in the
Quark Drive application.
