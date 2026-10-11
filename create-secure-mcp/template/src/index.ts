#!/usr/bin/env node
// An MCP server with Secure AI built in. Two example tools: one that reads
// customer records (the model gets stand-ins), and one that acts on them (the
// real values come back, after your rules say yes). Replace the sample data
// with your own systems.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { check, hide, reveal } from "./secure.js";

// Sample data. In your server this is your database, CRM or API.
const CUSTOMERS = [
  { id: "c1", name: "Maria Gonzalez", email: "maria@gonzalezlandscaping.com", phone: "(512) 555-0148", balance: 240.5 },
  { id: "c2", name: "Tom Reyes", email: "tom.reyes@example.org", phone: "(312) 555-0199", balance: 0 },
];

const server = new McpServer({ name: "__NAME__", version: "0.1.0" });

server.registerTool(
  "find_customer",
  {
    title: "Find a customer",
    description: "Look up a customer by name or email. Private details come back as stand-ins.",
    inputSchema: { query: z.string().describe("A name or email to search for") },
  },
  async ({ query }) => {
    const q = reveal(query).toLowerCase();
    const found = CUSTOMERS.filter((c) => c.name.toLowerCase().includes(q) || c.email.includes(q));
    const safe = await hide("find_customer", found);
    return { content: [{ type: "text", text: JSON.stringify(safe, null, 2) }] };
  },
);

server.registerTool(
  "send_reminder",
  {
    title: "Send a payment reminder",
    description: "Email a customer a reminder about their balance.",
    inputSchema: {
      email: z.string().describe("The customer's email, as find_customer returned it"),
      message: z.string().describe("The reminder to send"),
    },
  },
  async (args) => {
    const real = reveal(args);
    await check("email.send", real);
    // Your email provider goes here. This sample only logs to stderr,
    // which MCP clients show as the server's log, not to the model.
    console.error(`Would email ${real.email}: ${real.message}`);
    return { content: [{ type: "text", text: "Reminder sent." }] };
  },
);

await server.connect(new StdioServerTransport());
