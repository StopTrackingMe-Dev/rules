# StopTrackingMe rules

This repository is the source of truth for the rules used by StopTrackingMe.
Each file in `rules/` contains one rule bundle so changes can be reviewed independently.

The generated subscription bundle is published as the `rules.json` asset of a GitHub Release.
The stable address for the latest published bundle is:

```text
https://github.com/StopTrackingMe-Dev/rules/releases/latest/download/rules.json
```

The Android application does not bundle these rules. Users add the address above, or another
HTTPS rule subscription, from the Rules screen and manually refresh it when needed.

## Local build

Requires Python 3.10 or newer:

```text
python tools/build_rules.py --output build/rules.json
```

The script validates the JSON structure, parser limits, rule identifiers, regular expressions,
network hosts, and preview configuration before producing the combined bundle. The Android
application's `RuleParser` remains the final compatibility check.

## Publishing

`.github/workflows/publish-rules.yml` runs when rule sources change, can be started manually,
and runs daily on a cron schedule. It skips publishing when the generated bundle is unchanged.
Each published release contains `rules.json` and its SHA-256 checksum.
