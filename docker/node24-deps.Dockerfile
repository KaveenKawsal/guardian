# Guardian dependency image: one image per (package.json, package-lock.json) pair.
# Built by guardian.remediation.sandbox.DockerSandbox.install_dependencies with a build context
# that contains only this file, package.json and package-lock.json.
FROM node:24-bookworm-slim
ENV CI=true \
    NODE_ENV=test \
    npm_config_ignore_scripts=true \
    npm_config_audit=false \
    npm_config_fund=false \
    npm_config_update_notifier=false
RUN mkdir -p /deps /work && chown node:node /deps /work
USER node
WORKDIR /deps
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund && npm cache clean --force
WORKDIR /work
