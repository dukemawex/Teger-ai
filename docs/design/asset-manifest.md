# Asset manifest

Every visual and typographic asset shipped by `apps/web`, with its source and licence.
Nothing is hotlinked; all files are served from the app's own origin.

| Asset | File | Source / creator | Licence | Modifications |
|---|---|---|---|---|
| Silver tetradrachm of Alexander the Great, c. 325–319 BCE (Seleucid; head of Herakles in lion skin) | `apps/web/public/assets/tetradrachm-320.webp` | The Metropolitan Museum of Art, object 326395, image `DP-16934-019` — <https://www.metmuseum.org/art/collection/search/326395>. Rights checked through the Met Collection API on 2026-10-15: `isPublicDomain: true` | Met Open Access, CC0 (public domain) | Downloaded `web-large`, cropped to the coin, circular alpha mask, resized to 320 px, WebP q82. Credited in the site footer. |
| Teger mark (engraved roundel, beaded rim, incised T, route arcs) | `apps/web/src/app/icon.svg`, `apps/web/public/assets/teger-mark.svg`, `src/components/Mark.tsx` | Original artwork for this project | Project licence (MIT, see `LICENSE`) | — |
| Meander frieze | `apps/web/public/assets/meander.svg` | Original artwork (traditional Greek key motif drawn from scratch) | MIT | — |
| Decorative campaign chart, compass rose, route geometry | inline SVG in `src/components/public/AtlasPlate.tsx` | Original artwork; deliberately non-geographic and labelled “decorative chart · not telemetry” | MIT | — |
| Evidence-route diagram, verdict glyphs | `src/components/case/CaseRoute.tsx`, `src/components/VerdictSeal.tsx` | Original | MIT | — |
| Social preview image | `apps/web/public/og.png` | Screenshot of this project's own landing page (1200×630) | MIT | — |
| Cormorant Garamond (500, 600, 500 italic) | npm `@fontsource/cormorant-garamond@5.3.0` | Christian Thalmann / Cormorant Project | SIL OFL 1.1 | Self-hosted via Fontsource, bundled by Next.js |
| Source Sans 3 (400, 600) | npm `@fontsource/source-sans-3@5.3.1` | Adobe (Paul D. Hunt) | SIL OFL 1.1 | Self-hosted |
| IBM Plex Mono (400) | npm `@fontsource/ibm-plex-mono@5.3.0` | IBM (Mike Abbink, Bold Monday) | SIL OFL 1.1 | Self-hosted |

Demo fixtures use only fictional organizations, reserved domains (`.example`, `.test`) and the
UK telephone range reserved for drama (020 7946 0xxx).
