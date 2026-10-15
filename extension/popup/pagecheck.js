// Pure helpers for "Check this page" (loaded by popup.html; also unit-tested with node --test).
function validConsoleBase(value) {
  try {
    const url = new URL(value);
    const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
    if (url.protocol !== "https:" && !(local && url.protocol === "http:")) return null;
    return url.origin;
  } catch (_) {
    return null;
  }
}

function pageUrlForCheck(raw, includeQuery) {
  let url;
  try {
    url = new URL(raw);
  } catch (_) {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  url.hash = "";
  url.username = "";
  url.password = "";
  if (!includeQuery) url.search = "";
  return url.toString();
}

if (typeof module !== "undefined") {
  module.exports = { validConsoleBase, pageUrlForCheck };
}
