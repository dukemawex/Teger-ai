const test = require("node:test");
const assert = require("node:assert");
const { validConsoleBase, pageUrlForCheck } = require("./popup/pagecheck.js");

test("console address must be https (or local http)", () => {
  assert.equal(validConsoleBase("https://console.example.com/app"), "https://console.example.com");
  assert.equal(validConsoleBase("http://localhost:3100"), "http://localhost:3100");
  assert.equal(validConsoleBase("http://console.example.com"), null);
  assert.equal(validConsoleBase("javascript:alert(1)"), null);
});

test("page URL drops fragments, credentials and (by default) the query string", () => {
  assert.equal(pageUrlForCheck("https://a.example/login?token=secret#x", false), "https://a.example/login");
  assert.equal(pageUrlForCheck("https://u:p@a.example/x?y=1", true), "https://a.example/x?y=1");
  assert.equal(pageUrlForCheck("chrome://settings", false), null);
  assert.equal(pageUrlForCheck("file:///etc/passwd", false), null);
});
