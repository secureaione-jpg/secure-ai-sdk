# __NAME__

An MCP server with [Secure AI](https://secureai.one) built in.

[![Secured by Secure AI](https://secureai.one/badges/secured-by-secure-ai.svg)](https://secureai.one/developers/mcp)

- **To the model:** every tool result goes through `hide()`, so names, emails, phone numbers, addresses, card and account numbers become believable stand-ins.
- **From the model:** `reveal()` swaps the stand-ins back for the real values, on this server, before your code uses them.
- **Before acting:** `check()` asks your account's rules. Blocked actions never run, and ones that need approval wait for a person.

## Run it

```bash
npm install
cp .env.example .env      # paste your key from secureai.one -> Settings -> Developer
npm run build
```

Add it to Claude Desktop, Cursor or any MCP client:

```json
{
  "mcpServers": {
    "__NAME__": {
      "command": "node",
      "args": ["/full/path/to/__NAME__/dist/index.js"],
      "env": { "SECURE_AI_KEY": "sai_..." }
    }
  }
}
```

## Make it yours

Replace the sample customers in `src/index.ts` with your own systems. Wrap every result with `hide()`, every incoming argument with `reveal()`, and every action with `check()`.
