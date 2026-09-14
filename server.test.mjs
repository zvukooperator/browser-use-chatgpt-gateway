import test from "node:test";
import assert from "node:assert/strict";

process.env.GATEWAY_PASSWORD = "correct-horse-battery-staple";
process.env.BROWSER_USE_API_KEY = "bu_test_key";

const { server, signAccessToken, verifyAccessToken, isAllowedClientId, isAllowedRedirect } = await import("./server.mjs");

test.after(() => server.close());

test("accepts ChatGPT OAuth client and callback URLs", () => {
  assert.equal(isAllowedClientId("https://chatgpt.com/oauth/client.json"), true);
  assert.equal(isAllowedClientId("https://chatgpt.com/oauth/abc/client.json"), true);
  assert.equal(isAllowedRedirect("https://chatgpt.com/connector/oauth/abc"), true);
  assert.equal(isAllowedRedirect("https://chatgpt.com/connector_platform_oauth_redirect"), true);
  assert.equal(isAllowedRedirect("https://evil.example/callback"), false);
});

test("signs and verifies access tokens for one resource", () => {
  const now = Math.floor(Date.now() / 1000);
  const audience = "https://gateway.example/mcp";
  const token = signAccessToken({ exp: now + 60, aud: audience, scope: "browser:use" });
  assert.equal(verifyAccessToken(token, audience), true);
  assert.equal(verifyAccessToken(token, "https://other.example/mcp"), false);
  assert.equal(verifyAccessToken(`${token}x`, audience), false);
});
