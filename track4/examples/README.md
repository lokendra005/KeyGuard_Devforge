# Explicit practice configuration

`practice-policy.json` translates expected edges from the organizer's public `practice/README.md` into configuration. It is not a default policy, a secret, a trained classifier or a lookup table of event IDs. Supply your own approved baseline and measured uncertainty for another system. The algorithm accepts arbitrary names.

Source: [official practice context, revision 8901dfb](https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit/tree/8901dfbdbfe048853e0bfa25b60583d1e6617a63/practice). Keep the downloaded toolkit outside the submission. Public labels are development examples, not independent accuracy evidence.

```sh
node track4/cli.cjs detect \
  --events /path/to/toolkit/practice/events.csv \
  --approvals /path/to/toolkit/practice/approvals.json \
  --config track4/examples/practice-policy.json \
  --labels /path/to/toolkit/practice/labels.csv \
  --positive-labels unexpected_role_change,review_after_role_change,lateral_movement_candidate
```
