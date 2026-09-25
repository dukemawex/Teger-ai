# Teger AI Privacy Policy — MVP v0.2

Last updated: September 25, 2026

Teger AI is designed to analyze suspicious communications only when a user explicitly chooses to scan them.

## What Teger processes

When you trigger a scan, Teger may process:

- the selected message text
- limited context such as the communication platform and displayed sender information
- deterministic security signals derived from that message
- the resulting threat assessment

The selected message is sent to the Teger backend for analysis and may be processed by the configured AI provider as part of that analysis.

## What the MVP stores locally

The Chrome extension and dashboard may store limited scan metadata in your browser, including:

- scan time
- platform or context label
- threat level
- confidence
- detected tactics
- deterministic signals
- optional accuracy feedback

The MVP local scan history intentionally does **not** store the raw message body.

## Backend retention

The MVP backend does not intentionally persist submitted raw message content or completed scan results to a Teger database. Server and infrastructure providers may still generate operational logs according to their own service configuration.

## Anonymous installation identity

The extension and dashboard create an anonymous installation identifier and signed token. This token is used to authenticate scan requests and enforce basic abuse controls. It is not intended to identify a natural person.

## Secrets

Teger provider credentials are kept on the backend and are not shipped inside the browser extension or dashboard source code.

## User control

Scanning is initiated by the user. Removing the extension or clearing browser site/extension storage removes locally stored Teger scan history and installation credentials from that browser.

## Dataset contributions

The public Teger phishing-pattern dataset is designed for sanitized or synthetic examples. Users and contributors should not submit private victim communications, real credentials, personal data, or live malicious links.

## Changes

This policy will be updated as Teger adds persistent accounts, team features, cloud history, or additional integrations.
