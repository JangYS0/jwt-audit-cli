import test from "node:test";
import assert from "node:assert/strict";
import { auditJwt } from "./index.mjs";

const b64u = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

test("flags alg:none, missing exp, and sensitive payload keys", () => {
  const tok = `${b64u({ alg: "none", typ: "JWT" })}.${b64u({ sub: "u1", api_key: "sk-123" })}.`;
  const res = auditJwt(tok, 1700000000);
  assert.equal(res.ok, false);
  assert.ok(res.findings.some((f) => f.rule === "alg-none"));
  assert.ok(res.findings.some((f) => f.rule === "missing-exp"));
  assert.ok(res.findings.some((f) => f.rule === "sensitive-payload-keys"));
});

test("passes clean RS256 token with exp, iss, aud", () => {
  const tok = `${b64u({ alg: "RS256", typ: "JWT", kid: "key-2026-11" })}.${b64u({ sub: "u1", iss: "https://auth.example.com", aud: "api", exp: 1800000000 })}.sig`;
  const res = auditJwt(tok, 1700000000);
  assert.equal(res.ok, true);
  assert.equal(res.findings.length, 0);
});
