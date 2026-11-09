# dsh-umbrel image: one image, two roles.
#   - default entrypoint: the dsh harness (entrypoint.sh) — installs/updates
#     dsh from npm into the /data volume and runs dsh web.
#   - gate role (compose entrypoint override): the password front door
#     (gate/gate.js) — pure node:http, no dependencies.
# The image is deliberately thin and changes rarely; dsh itself is NOT
# baked in, so harness updates never require rebuilding or republishing.
FROM node:26-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY gate/gate.js /usr/local/lib/dsh-gate/gate.js
RUN chmod +x /usr/local/bin/entrypoint.sh

# All durable state lives here (one bind-mounted data dir in Umbrel terms):
#   /data/home/.dsh       -> DSH_HOME: providers, keys, profiles, plugins, sessions
#   /data/home            -> default workspace (mirrors the VM, where ~ is the workspace)
#   /data/home/dsh-link.txt -> current launch link, written by the entrypoint for the gate
#   /data/gate/gate.json  -> the gate's credential record (created at first-run setup)
#   /data/app             -> the dsh program install (swapped atomically on update)
#   /data/app.old         -> previous install, one-generation rollback
#   /data/dsh-version.txt -> tracked version: a dist-tag ("latest") or an exact version
VOLUME ["/data"]
EXPOSE 3080 3081

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
