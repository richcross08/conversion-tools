# URL Category Enrichment Tool

This tool takes URLs exported from IronPort, looks each URL up against the Palo Alto URL Cloud DB, and creates an Excel workbook that shows the IronPort category/action next to the Palo Alto category/action.

The script does **not** compare IronPort categories to Palo Alto categories. The two sides are handled independently:

- IronPort category comes from the proxy source CSV.
- IronPort action comes from `ironport-category-actions.csv`.
- Palo Alto category comes from the PAN-OS URL test API Cloud DB result.
- Palo Alto action comes from `palo-category-actions.json`.

## Required files

Place these files in the same folder as the script, or provide full paths in the command.

| File | Purpose | Required fields |
|---|---|---|
| `Proxy_top5000_2026_04.csv` | Source list of URLs accessed through IronPort | `dest`, `category` |
| `ironport-category-actions.csv` | IronPort category to action mapping | `Category`, `IronPort Action` |
| `palo-category-actions.json` | Palo Alto category to recommended action mapping | `category`, `recommended_action` |
| `pan_url_category_cache.json` | Local lookup cache to avoid repeating API lookups | Created automatically if it does not exist |

## Output workbook

The script writes an `.xlsx` workbook. The workbook contains these tabs:

| Tab | Description |
|---|---|
| `Enriched URLs` | Final enriched output with URL, IronPort category/action, Palo Alto category/action |
| `Proxy Source` | Copy of the original proxy CSV data |
| `IronPort Actions` | Copy of the IronPort category/action input file |
| `Palo Actions` | Copy of the Palo Alto category/action JSON file |
| `Cache` | Cached Palo Alto lookup results |

Default enriched columns:

```text
URL
Ironport category
Ironport action
palo alto category
palo alto action
```

With `--include-extra`, the tool also adds:

```text
palo alto db url
lookup status
api raw result
```

## Install dependency

```bash
python3 -m pip install requests
```

## Script

Use the keygen-capable XLSX script:

```text
pan_url_category_enrich_xlsx_keygen.py
```

## Option 1: Use an existing PAN-OS API key

This is best when you already have a valid API key.

```bash
export PANOS_API_KEY="YOUR_API_KEY"

python3 pan_url_category_enrich_xlsx_keygen.py \
  --firewall 100.50.81.108:4443 \
  --proxy-csv "Proxy_top5000_2026_04.csv" \
  --ironport-actions-csv "ironport-category-actions.csv" \
  --palo-actions-json "palo-category-actions.json" \
  --output "url_categories_enriched.xlsx" \
  --cache "pan_url_category_cache.json" \
  --include-extra \
  --no-verify
```

To remove the key from the current terminal session after the run:

```bash
unset PANOS_API_KEY
```

## Option 2: Generate an API key using username and prompted password

This is the safest username/password option because the password is not saved in shell history.

```bash
python3 pan_url_category_enrich_xlsx_keygen.py \
  --firewall 100.50.81.108:4443 \
  --username wei-admin \
  --prompt-password \
  --proxy-csv "Proxy_top5000_2026_04.csv" \
  --ironport-actions-csv "ironport-category-actions.csv" \
  --palo-actions-json "palo-category-actions.json" \
  --output "url_categories_enriched.xlsx" \
  --cache "pan_url_category_cache.json" \
  --include-extra \
  --no-verify
```

The script will call the PAN-OS `keygen` API, use the returned API key for the lookup run, and continue normally.

## Option 3: Generate an API key using username and password environment variable

This is useful for repeatable runs without placing the password directly in the command.

```bash
export PANOS_PASSWORD="YOUR_PASSWORD"

python3 pan_url_category_enrich_xlsx_keygen.py \
  --firewall 100.50.81.108:4443 \
  --username wei-admin \
  --password-env PANOS_PASSWORD \
  --proxy-csv "Proxy_top5000_2026_04.csv" \
  --ironport-actions-csv "ironport-category-actions.csv" \
  --palo-actions-json "palo-category-actions.json" \
  --output "url_categories_enriched.xlsx" \
  --cache "pan_url_category_cache.json" \
  --include-extra \
  --no-verify
```

Remove the password variable after the run:

```bash
unset PANOS_PASSWORD
```

## Deduplicated or net-new output

Use this when you want one row per URL that is not already in cache. If the URL is already in cache, the script skips the API lookup and does not write that URL to the `Enriched URLs` tab.

```bash
python3 pan_url_category_enrich_xlsx_keygen.py \
  --firewall 100.50.81.108:4443 \
  --username wei-admin \
  --prompt-password \
  --proxy-csv "Proxy_top5000_2026_04.csv" \
  --ironport-actions-csv "ironport-category-actions.csv" \
  --palo-actions-json "palo-category-actions.json" \
  --output "url_categories_enriched_deduped.xlsx" \
  --cache "new_dedupe_cache.json" \
  --include-extra \
  --skip-cached-output \
  --no-verify
```

Use a fresh cache, such as `new_dedupe_cache.json`, when you want a clean deduped output from the current source file. If you use a cache that already contains every URL, the output will only contain the workbook tabs and no new enriched rows.

## Dry run

Use `--dry-run` to validate inputs and workbook creation without calling the firewall API.

```bash
python3 pan_url_category_enrich_xlsx_keygen.py \
  --dry-run \
  --proxy-csv "Proxy_top5000_2026_04.csv" \
  --ironport-actions-csv "ironport-category-actions.csv" \
  --palo-actions-json "palo-category-actions.json" \
  --output "dry_run_check.xlsx" \
  --include-extra
```

## Common options

| Option | Purpose |
|---|---|
| `--firewall` | PAN-OS firewall IP, hostname, and optional port |
| `--api-key` | API key directly on the command line; environment variable is preferred |
| `--api-key-env` | Environment variable containing the API key; default is `PANOS_API_KEY` |
| `--username` | PAN-OS admin username for keygen |
| `--prompt-password` | Prompt for password securely |
| `--password-env` | Environment variable containing the PAN-OS password |
| `--proxy-csv` | Input proxy URL CSV |
| `--ironport-actions-csv` | IronPort category/action CSV |
| `--palo-actions-json` | Palo Alto category/action JSON |
| `--output` | Output `.xlsx` file |
| `--cache` | Cache JSON file |
| `--include-extra` | Adds DB URL, lookup status, and raw API result columns |
| `--skip-cached-output` | Skips rows already found in cache and avoids writing them to output |
| `--no-verify` | Disables TLS validation for lab or self-signed firewall certificates |
| `--progress-every` | Prints progress every N rows; use `0` to disable |
| `--cache-flush-every` | Saves cache every N rows |

## Notes

- `--no-verify` is useful for lab firewalls with self-signed certificates. For production, use a trusted certificate and remove `--no-verify`.
- The cache prevents duplicate Palo Alto API lookups.
- With `--skip-cached-output`, cached URLs are also skipped from the output workbook.
- If Palo Alto returns a category that is not present in `palo-category-actions.json`, the Palo Alto action is written as `unknown`.
- If the IronPort category is not present in `ironport-category-actions.csv`, the IronPort action is written as `unknown`.
