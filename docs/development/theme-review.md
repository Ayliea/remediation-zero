# Ayliea theme alignment

Shared theme applies to Overview, My infrastructure, Action list and Activity,
including empty/error states. The approved generated product logo includes the
by Ayliea endorsement. It is bundled locally and embedded in the rendered page;
no external font, image or stylesheet requests are required. The original
judge-facing evidence console remains unchanged.

Brand tokens inspected from Ayliea's published stylesheet on 2026-10-23:
navy heading #1B2A4A, body #2D2D2D, muted #4B5563, action #1D4ED8,
hover #1E3A8A, cyan #06B6D4, accent surface #E8F0F8, background #FFFFFF.
Source: https://ayliea.com/_next/static/chunks/1y5z_37153rsk.css
System fonts keep the local install independent of external font hosting.
Cyan is an accent, not body text on white. Amber denotes incomplete/unknown
review states; reviewed recommendations use a neutral blue badge, not an all-clear.

Overview follows the chosen action-first concept, with coverage limits beside
the first recorded decision. Actual data determines labels and content; it does
not invent the concept image's named assets or claim that no backend changes
have ever occurred. Technical evidence and recorded totals are collapsed by
default. Links navigate to working views; read-only behavior is unchanged.

Visual QA: blocked. Playwright is present but its Chromium executable is absent.
No browser package was installed. Exact mockup fidelity, browser interactions
and responsive visual quality still require browser verification. Automated
render/route, escaping, installer and local-storage checks are recorded separately.

## Settings implementation — 2026-10-24

Approved five-section Settings design implemented for the local edition with
responsive tabs, labeled native forms, visible keyboard focus, status messages,
and collapsed backup/recovery/update instructions. Model and startup preferences
persist; safety limits remain read-only. The separate FastAPI dashboard does not
expose the local settings interface. Local preferences are not cloud settings.
Visual browser QA remains blocked by the missing browser executable; HTTP and
rendered-HTML checks are not a substitute for a screenshot or usability review.
