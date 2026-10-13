# Dot / OpenClaw Bridge Setup

An experimental **guided-setup plugin bundle**, not an automatically running bridge or a hosted connector. It packages instructions for an agent to install the MIT-licensed bridge on the user's own host. Installing this bundle alone does not grant session access or start a service.

From a checkout of [the source repository](https://github.com/e-jung/dot-openclaw-bridge):

```sh
openclaw plugins install ./plugins/dot-openclaw-bridge-setup
```

Then ask: **“Use dot-bridge-setup to connect my own OpenClaw to ChatGPT.”**

Requires Node.js 24+, an OpenClaw Gateway with authenticated Tailscale Serve access, and permission to create a private MCP tunnel/custom connection in your OpenAI account. Supplied service instructions target Linux systemd. Other hosts need separately verified supervision.

Each owner runs their own bridge, approves their own dedicated device, and creates their own tunnel and ChatGPT connection. Do not reuse the author's connection. No credentials, owner settings, session data, runtime dependencies, hooks, or automatic install scripts are included.

ClawHub publication is pending publisher authentication and registry review; no registry install command is claimed yet. Maintainer/source: [e-jung/dot-openclaw-bridge](https://github.com/e-jung/dot-openclaw-bridge). Report issues there without credentials or private session content.
