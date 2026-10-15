/** Paths the browser may reach through the proxies. Anything else is a 404. */
const ALLOWED: { method: string; pattern: RegExp }[] = [
  { method: "GET", pattern: /^cases$/ },
  { method: "POST", pattern: /^cases$/ },
  { method: "GET", pattern: /^cases\/case_[a-f0-9]{16}(\/events|\/export)?$/ },
  { method: "POST", pattern: /^cases\/case_[a-f0-9]{16}\/(cancel|retry|resolution)$/ },
  { method: "POST", pattern: /^actions\/act_[a-f0-9]{16}\/(approve|reject|execute)$/ },
  { method: "GET", pattern: /^(context|activity|blocklist)$/ },
  { method: "POST", pattern: /^context$/ },
  { method: "DELETE", pattern: /^context\/ctx_[a-z0-9_]{1,40}$/ },
  // demo only
  { method: "GET", pattern: /^catalog$/ },
  { method: "POST", pattern: /^session\/reset$/ },
];

export function allowedPath(method: string, path: string): boolean {
  return ALLOWED.some((rule) => rule.method === method && rule.pattern.test(path));
}
