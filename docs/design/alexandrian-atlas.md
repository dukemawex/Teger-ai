# Art direction: the Alexandrian Intelligence Atlas

Internal design concept for Teger AI (not a rename). A museum publication meets a precise
investigation desk.

**Public site** — dramatic and authored: ink shell, parchment plates, large Cormorant Garamond
headlines, an asymmetric hero whose right half is a working *campaign-atlas plate*. The plate's
route (Message → Destination → Identity check → Decision) is the product: each node reveals
evidence from a recorded run of the real investigator. The engraved chart beneath it is decorative
and says so. One public-domain artefact — the Met's silver tetradrachm — sits on the plate like a
seal; everything else is original SVG.

**Workspace** — calm: parchment ground, near-white panels, thin rules, small radii, Source Sans 3
for reading, IBM Plex Mono for domains, evidence IDs and timestamps. The theme survives through
typography, rules, the evidence route and the bronze accent, not through texture.

**Tokens** (`src/app/globals.css`): ink `#171A18`, parchment `#EFE8D8`, limestone `#D7CEBB`,
bronze `#987044`, pale metal `#C4AA78`, mineral `#45635B`, oxide `#A4473C`. Text-safe variants were
derived where the brand value fails AA (e.g. bronze text `#6B4D2B` on parchment, 6.6:1). Verdicts
and severities always pair colour with an icon and a word.

**Motion** — only for state: the plate route draws when a case is selected; route legs draw once
when a stage completes; evidence highlights when a citation is followed. `prefers-reduced-motion`
disables all of it.

**Avoided on purpose** — gradients-as-identity, glowing AI imagery, three-card feature rows, fake
logos or metrics, war-game language, maps posing as telemetry.

Visual review: screenshots in `docs/screenshots/` were taken from the running production build at
1440 px and 390 px (plus Playwright checks at 1280 px and 390 px). One refinement pass after the
first screenshots reduced the hero headline so it sets in three lines, shortened plate tabs, added
label halos to the route, enlarged the case route, fixed a 390 px horizontal overflow from long
sender addresses and separated adjacent evidence citations.
