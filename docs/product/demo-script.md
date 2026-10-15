# Two-minute product demo script

Setup: API and web running (`docs/product/investigation-workspace.md` §4). Open `/`.

**0:00 — The promise (15 s).** “Teger investigates suspicious emails and websites against your
business context and helps your team respond.” Point at the plate: *Plate I, Impersonation*.
Click **Destination** — the redirect chain and a form asking for a password and IBAN. Click
**Identity check** — Northwind Freight is an approved supplier, but `secure-docs.test` is not on
its record. Note the label: recorded run, synthetic evidence.

**0:25 — Run it (30 s).** Click **Try an investigation** → case I → **Investigate**. Watch the tool
activity: read message, deterministic checks, follow redirects, read destination (no scripts, no
form submission), compare business context. The evidence route draws as each stage completes.

**0:55 — Why it decided (25 s).** Assessment: *Malicious — impersonation of approved supplier*.
Click a citation (`ev-13`) to jump to the evidence. Show contradictory evidence and uncertainty
(“no reputation provider was available”). The verdict is deterministic; no model can change it.

**1:20 — Respond (25 s).** Approve **Add secure-docs.test to the blocklist** → **Execute**. Read the
scope out loud: demo-only blocklist; in a real tenant, Teger's blocklist only — not browsers or
mail. Approve **Verify with Northwind Freight** — the phone number comes from the approved record,
not the email. Record the outcome; open **Report**.

**1:45 — Context matters (15 s).** Back to `/demo`, run case II: the invoice link leaves the
supplier's domain, but it is Lumen Print's approved Ledgerly portal → *No threat detected*, with
the off-domain link still listed as contradictory and “not a guarantee of safety”. Mention case IV:
the page hides instructions for AI tools — recorded as evidence, changed nothing.
