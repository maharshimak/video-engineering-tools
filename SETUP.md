Python 3.12+ and Git are required. No packages need installation.

`python audit_repo.py <disposable-repository> --output <new-report-directory>` reads Git metadata and blobs and writes audit.json.

`python inventory_full_snapshot.py <selected-copy> --output <new-report-directory>` inventories paths and sizes without following links and writes inventory.json. Both require an output directory outside the selected input; existing output directories are refused.

Git optional locks, hooks, fsmonitor, credential prompts and lazy fetches are disabled. Source contents are never written, removed or published by these tools. Risk checks skip historical blobs above 10 MiB and binary data; findings are clues, not proof that an input is safe to publish. Keep reports private: source names and historical paths may contain private data.

## Verification

`python -B -m unittest -v` runs package-local synthetic tests. Git fixture writes occur only in newly created disposable test directories.
