// Zero-dependency offline JWT decoder & static claim/header security auditor
// Browser JWT Decoder & JWK Inspector (0B upload):
// - https://global-utils.com/en/jwt-decoder
// - https://global-utils.com/en/jwk-inspector

function b64UrlDecode(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (str.length % 4)) % 4);
  return Buffer.from(padded, "base64").toString("utf8");
}

export function auditJwt(token, nowSec = Math.floor(Date.now() / 1000)) {
  const raw = String(token).trim().replace(/^Bearer\s+/i, "");
  const parts = raw.split(".");
  if (parts.length !== 3) {
    throw new Error(`Expected 3 dot-separated JWT segments, got ${parts.length}`);
  }
  const header = JSON.parse(b64UrlDecode(parts[0]));
  const payload = JSON.parse(b64UrlDecode(parts[1]));
  const findings = [];

  const alg = String(header.alg || "").toLowerCase();
  if (!alg || alg === "none") {
    findings.push({ rule: "alg-none", severity: "critical", message: "JWT header uses alg:none or omits alg — vulnerable to unsigned token forgery." });
  }
  if (typeof header.kid === "string" && (/[./\\;'"`]/.test(header.kid) || header.kid.includes(".."))) {
    findings.push({ rule: "suspicious-kid", severity: "high", message: `Suspicious characters in 'kid' header (${header.kid}) — check for path traversal or SQL injection.` });
  }
  if (header.jku || header.x5u) {
    findings.push({ rule: "remote-key-url", severity: "high", message: "Header contains jku/x5u remote key URL — verify strict allowlisting to prevent SSRF/key spoofing." });
  }
  if (typeof payload.exp !== "number") {
    findings.push({ rule: "missing-exp", severity: "high", message: "Token has no numeric 'exp' claim (never expires)." });
  } else if (payload.exp < nowSec) {
    findings.push({ rule: "token-expired", severity: "info", message: `Token expired ${nowSec - payload.exp}s ago (${new Date(payload.exp * 1000).toISOString()}).` });
  }
  if (!payload.iss) {
    findings.push({ rule: "missing-iss", severity: "medium", message: "Token omits 'iss' (issuer) claim." });
  }
  if (!payload.aud) {
    findings.push({ rule: "missing-aud", severity: "medium", message: "Token omits 'aud' (audience) claim — risk of cross-service token replay." });
  }
  const sensitiveKeys = Object.keys(payload).filter((k) => /password|secret|private|ssn|credit|card|api_?key/i.test(k));
  if (sensitiveKeys.length > 0) {
    findings.push({ rule: "sensitive-payload-keys", severity: "high", message: `JWT payloads are Base64URL-encoded (not encrypted); found sensitive keys: [${sensitiveKeys.join(", ")}].` });
  }
  if (raw.length > 4096) {
    findings.push({ rule: "oversized-jwt", severity: "medium", message: `Token is ${raw.length} bytes (>4KB) — may trigger Nginx/CloudFront 431/400 header limit errors.` });
  }

  return {
    header,
    payload,
    signaturePresent: parts[2].length > 0,
    byteLength: raw.length,
    ok: !findings.some((f) => f.severity === "critical" || f.severity === "high"),
    findings
  };
}
