# OpenCode integration

Add shush to the `plugin` array in your OpenCode config
(`opencode.json` in the project root, or `~/.config/opencode/opencode.json`
for global):

```json
{
  "plugin": [
    "shush"
  ]
}
```

The package is installed automatically via Bun at startup.

<details>
<summary>OpenCode from source</summary>

```bash
git clone https://github.com/rjkaes/shush.git
cd shush
bun install
bun run build
```

Then reference the plugin file directly in your config:

```json
{
  "plugin": [
    "/absolute/path/to/shush/plugins/opencode.ts"
  ]
}
```

Alternatively, copy or symlink `plugins/opencode.ts` into an
auto-loaded plugin directory (`.opencode/plugins/` for project-level,
`~/.config/opencode/plugins/` for global).

OpenCode maps `ask` and `block` decisions to errors that halt tool
execution. The `allow` and `context` levels pass through silently
(OpenCode has no equivalent of Claude Code's "context" level).

</details>
