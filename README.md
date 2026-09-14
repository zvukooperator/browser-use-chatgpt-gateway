# Browser Use Cloud gateway for ChatGPT

A private, single-user OAuth 2.1 MCP gateway. ChatGPT authenticates to this service with authorization-code + PKCE. The gateway forwards MCP traffic to Browser Use Cloud and injects the Browser Use API key server-side.

## Render configuration

- Runtime: Node
- Build command: `npm install`
- Start command: `npm start`
- Health check: `/health`
- Environment variables:
  - `BROWSER_USE_API_KEY`: Browser Use Cloud key beginning with `bu_`
  - `GATEWAY_PASSWORD`: a unique password of at least 16 characters

Never commit either secret to the repository.

After deployment, add `https://YOUR-SERVICE.onrender.com/mcp` as a custom MCP server in ChatGPT developer mode. ChatGPT opens the gateway authorization page; enter `GATEWAY_PASSWORD` there.
