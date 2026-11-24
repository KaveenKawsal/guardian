# Guardian sandbox images

`node24-deps.Dockerfile` is the "prebuilt node:24 image with dependencies preinstalled" used by
remediation validation (`guardian.remediation.validate`). Guardian builds it itself; you do not
need to build it by hand. The same text lives in `guardian.remediation.sandbox.NODE_DEPS_DOCKERFILE`
(a unit test keeps the two identical) so an installed Guardian does not depend on this directory.

How it is built:

1. The post-fix `package.json` is copied (alone, without `.npmrc`) into a disposable directory and
   `npm install --package-lock-only --package-lock=true --ignore-scripts --no-audit --no-fund`
   runs in a `node:24-bookworm-slim` container (network on, non-root, read-only rootfs).
2. A build context containing only this Dockerfile, `package.json` and `package-lock.json` is built
   as `guardian-deps:<sha256(package.json + lockfile)[:12]>`; `npm ci --ignore-scripts` installs
   into `/deps/node_modules` as the `node` user (uid 1000). An existing tag is reused.
3. Build and tests run from that image with `--network none` on a copy of the worktree mounted at
   `/work`; the copy's `node_modules` is a symlink to `/deps/node_modules`.

Install scripts never run (`--ignore-scripts`, `npm_config_ignore_scripts=true`), so native
modules that need a postinstall step are not compiled; Juice Shop's server unit tests do not need
them.

Clean up old dependency images with `docker image prune -a --filter label=guardian.deps-hash`.
