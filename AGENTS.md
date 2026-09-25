<!-- antislop:start -->
## antislop
For UI, copy, people, mobile layout, or code comments work, load the antislop skill for the task:
- Core filter, always on: `antislop`
- UI / visual: `antislop-ui`
- Copy & text: `antislop-copywriting`
- People: `antislop-human`
- Mobile / responsive: `antislop-layoutmobile`
- Code comments: `antislop-code`
Before starting, ask the user when antislop applies: during the work, or after it is done.
<!-- antislop:end -->

## ConfigMorph direction

For UI, copy, responsive layout, and code-comment work, apply the relevant antislop skill together with `DESIGN.md`.

`DESIGN.md` defines the project direction. antislop filters unwanted generic AI patterns. Neither replaces the other.

## Vendor semantics

Do not implement parser, migration, or renderer semantics from model knowledge alone. Locate official vendor documentation, record its reference ID, and associate behavior with an OS version profile. If authoritative evidence is unavailable, do not infer behavior; use `MANUAL_REVIEW` or `VERSION_NOT_VERIFIED`.
