# create-secure-mcp

Create an MCP server whose tools never hand an AI model your customers' private details.

```bash
npx create-secure-mcp my-server
```

You get a TypeScript MCP server with [Secure AI](https://secureai.one) built in:

- **On the way to the model**, every tool result has names, emails, phone numbers, addresses, card and account numbers swapped for believable stand-ins. The model works with the stand-ins and never sees the real values.
- **On the way back**, when the model asks a tool to act, the stand-ins are swapped back for the real values, on your server, before your code runs.
- **Before anything acts**, the action is checked against your account's rules. A blocked action never runs, and one that needs approval waits for a person.

Get a free key (1,000 requests a month) at secureai.one → Settings → Developer.

MIT licensed.
