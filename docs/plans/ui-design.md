# Guardian review console (`guardian ui`): design plan

A local backup for the Jira step of the remediation flow. If Jira is down during the demo, the
presenter opens `guardian ui`, shows each remediation case, records the human decision
(channel `cli`, same strict parser and approver allowlist as `guardian decide`) and watches the
case move to a verified fix.

**Subject.** A supply-chain security tool's remediation review console.
**Audience.** A security engineer deciding on fixes, watched live by hackathon judges on a
projector, possibly offline.
**Primary job.** Make it obvious where a case is in the required flow, what is fact and what is
AI opinion, and let a human record a decision in one clear action.

## The memorable element: the route map

The case's journey is drawn as a transit route map, not a generic stepper:

```
 Prioritized   Recommended   Human        Applied in        Build & test   Rescan   Verified
 risk          fix           decision     isolated branch   (sandboxed)
 ●─────────────●─────────────◎════════════○─────────────────○──────────────○────────○
                              ╲
                               ╲__ Risk accepted / declined (terminal spur)
```

- One continuous line. Stations already passed are filled; the current station pulses once
  per poll (a ring, not a bounce) and is labelled "Now". Stations ahead are hollow.
- **Human decision is an interchange**: a larger double-ring station in signal amber, the
  only station where a person acts. That is the point of the product, so it is the one place
  the map is visually loud.
- **Decline branches off** at the interchange onto a short spur ending in "Risk accepted until
  <date>" or "Declined: <reason>", and the rest of the line is drawn faded.
- **A failed validation** marks the failing station in signal red and draws a return line back
  to the interchange ("Back to review"); earlier attempts are listed under the map.
- On phones the map turns vertical, like a line diagram on a train door.
- Under each passed station: the time it happened, taken from the audit trail.

## Tokens

### Colour (enamel transit signage, light by default)

| Token | Light | Dark | Role |
|---|---|---|---|
| `--paper` | `#F2F4F3` | `#12171C` | Page ground (cool enamel, not cream) |
| `--ink` | `#17202A` | `#E3E8EC` | Text, the route line once passed |
| `--line` | `#2F55B4` | `#7C9BEA` | Route colour (cobalt), links, focus ring |
| `--gate` | `#B87900` | `#F0B43C` | Human decision: the interchange, the decision panel edge |
| `--go` | `#1D7A50` | `#4CC38A` | Verified, passed steps, resolved findings |
| `--stop` | `#B4322A` | `#F07167` | Failed steps, new findings, decline spur |

Supporting neutrals derive from ink at fixed alphas (`--ink-2` 72 %, `--ink-3` 52 %,
`--rule` 16 %, `--wash` 5 %). All text pairs are at least 4.5:1 in both themes.

### Type (system fonts only; the demo may be offline)

- **Signage sans** for everything: `"Avenir Next", "Avenir", "Segoe UI Variable Text",
  "Segoe UI", "Noto Sans", "Cantarell", sans-serif`. Avenir's humanist-geometric shapes read
  like wayfinding signage, which is the metaphor. Station names in Demi Bold.
- **Code face** only for things that are literally code or identifiers (versions, purls,
  candidate ids, commands, branch names): `ui-monospace, "SF Mono", "Cascadia Mono",
  Menlo, Consolas, monospace`.
- Scale (1.25, base 16 px): 13 / 16 / 20 / 25 / 31 px. Line height 1.5 for body, 1.2 for
  headings. Sentence case everywhere; no all-caps labels, no eyebrow text.

### Layout

```
┌───────────── header: Guardian review console · Jira status · audit chain status ─┐
│ banner (only when Jira is not configured / always visible notice about channel)  │
├──────────────┬───────────────────────────────────────────────────────────────────┤
│ case list    │ case title, component, priority, Jira key                         │
│ grouped by   │ ROUTE MAP (full width of the detail pane)                         │
│ priority     ├──────────────────────────────────────┬────────────────────────────┤
│              │ Finding + evidence (Verified)         │ Your decision (sticky)     │
│              │ Risk factors                          │ amber left edge            │
│              │ Fix options (recommended marked)      │                            │
│              │ Guardian's assessment (AI inference)  │                            │
│              ├──────────────────────────────────────┴────────────────────────────┤
│              │ Build & test · Rescan before/after · Audit trail                  │
└──────────────┴───────────────────────────────────────────────────────────────────┘
```

Left-aligned throughout; numbers right-aligned in tables. Below 900 px the case list becomes
a select-like list above the detail and the decision panel follows the options; below 600 px
the route map is vertical. Sections are separated by space and a single rule, not boxed.

### Principles

1. **The line is the story.** Everything else is quiet so the route map carries the demo.
2. **Facts are solid, inference is drafted.** Verified content sits on the plain page with a
   "Verified" tag. AI output sits in a dashed, hatched block titled "Guardian's assessment (AI
   inference)", like a pencil draft on tracing paper; never the same treatment as facts.
3. **Amber means a human.** Only the interchange and the decision panel use `--gate`.
4. **Plain verbs.** Buttons say what happens: "Accept recommended fix", "Accept this
   version", "Decline and record reason". The result toast reuses the same verb.
5. **Hostile text is just text.** Every value is rendered with `textContent`; nothing from
   the API becomes markup.

## Review against the brief (what changed)

- *First draft was a dark navy dashboard with a neon-green accent and a circle-and-check
  stepper.* That is the default "security tool" look (calibration trait 2) and a generic
  stepper says nothing about the flow's shape. Replaced with the light enamel-signage palette
  and the route map, whose branch and return loop show the real state machine (decline is a
  terminal spur, failure returns to review).
- *First draft boxed every section in rounded cards with shadows.* That is the SaaS-card kit.
  Now only two things get a container: the decision panel (the one thing you act on) and the
  AI assessment (to separate inference from fact). Everything else is typography and rules.
- *First draft used a violet "AI" colour.* A sixth hue would compete with the route colours;
  inference is now distinguished by form (dashed outline, hatching, explicit title) instead.
- *First draft put small tracked-out all-caps labels above sections.* Removed; section
  headings are plain sentence-case words at 20 px.
- Kept a monospace face, but only for literal identifiers, not as decoration for labels.

## Motion

One moment only: when a poll reports that a case moved, the newly reached station's ring
expands once (300 ms) and the passed segment fills. Nothing else animates. With
`prefers-reduced-motion: reduce`, the change is instant.

## Critique notes (after building, from headless-Chrome screenshots)

- First render showed `[object HTMLDivElement]` in two sections: the DOM helper flattened child
  arrays only one level. Fixed (`flat(Infinity)`); still text-only, no HTML parsing.
- The Verified station repeated its own name as a note ("Verified / verified"). The note now
  appears only when the verdict differs (partially verified, unverified, failed).
- Checked the hostile-text path: a finding titled `<img src=x onerror=alert(1)>` and a plan
  rationale containing `<script>` render as literal text.
- Kept: the interchange reads clearly at projector distance in both themes; the decline spur
  and the "Back to review" loop make the state machine visible without a legend. Removed
  nothing else: the remaining chrome (one rule per section, two containers) is already minimal.
