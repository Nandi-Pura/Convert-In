# ConfigMorph Design Direction

Canonical tagline: **Visualize. Analyze. Migrate.**

## Product

ConfigMorph is a local firewall configuration engineering workbench. It is not a marketing SaaS, NOC dashboard, AI assistant, SIEM, or consumer application.

## Character

Technical, quiet, precise, professional, neutral, local-first, and dense where useful. Preserve the information density firewall engineers need.

## Workspace and workflow

Use a simple top-level application workspace. Configuration input remains the primary starting point. The workflow is:

1. Import
2. Analyze
3. Visualize
4. Migration
5. Review

Avoid excessive nested cards and decorative blank areas. Establish hierarchy with spacing, typography, and grouping before adding containers.

## Visual style

- Primarily light interface with neutral surfaces and subtle borders.
- One restrained accent color. Status colors only for semantic states.
- No gradients, glassmorphism, glow, cyberpunk styling, unnecessary hero sections, giant marketing headlines, decorative fake terminals, or generic SaaS KPI layouts.
- Use cards only for real structural grouping. Avoid cards inside cards, large radii, and unnecessary shadows.

## Typography and data

Use a system/native sans-serif stack for product UI. Use monospace for configuration text and generated commands. Keep type sizes restrained.

Tables and lists should be dense but readable, clearly aligned, and preferred over decorative tiles for configuration entities.

## Copy

Use plain technical language such as **Analyze Configuration**, **Migration Review**, **Manual Review**, **Candidate Configuration**, **Validation**, and **Dependencies**.

Avoid promotional language such as “Unlock,” “Supercharge,” “Next-generation,” “Revolutionary,” “Seamless,” “Powerful AI,” and “Transform your workflow.” Never invent metrics, claims, or compatibility percentages. Do not imply perfect conversion, production readiness, device validation, safe deployment, or AI intelligence.

Retain safety language including **Candidate Configuration**, **Engineer Review Required**, and **Application-level validation**.

## Motion

Keep motion minimal. Use it only to communicate state or relationships. Do not use decorative floating or pulsing effects.

## Responsive behavior

Desktop engineering workstations are primary. Narrow screens must remain usable through deliberate reflow, not uniform shrinking. Preserve useful technical density at every width.

## Accessibility

Provide visible focus states, keyboard-operable controls, meaningful labels, and adequate contrast. Never communicate status by color alone.