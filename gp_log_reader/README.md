# GlobalProtect Connection Attempt Report

`gp_connection_attempt_report_v2.py` analyzes Palo Alto Networks GlobalProtect macOS support bundles and reports authentication, certificate-selection, and tunnel results for each connection attempt.

The script accepts either:

- A GlobalProtect `.tgz` or `.tar.gz` support bundle
- A directory containing extracted `PanGPS.log` files

It requires only Python 3 and does not require third-party packages.

## Files

Place the script and GlobalProtect log bundle in the same working directory, or use full paths when running the script.

Example files:

```text
gp_connection_attempt_report_v2.py
GlobalProtectLogs_richardcross_07162026205854.tgz
```

## Requirements

- Python 3.9 or newer is recommended
- Read access to the GlobalProtect support bundle or extracted log directory
- Write access to the selected output directory

Confirm Python is available:

### macOS or Linux

```bash
python3 --version
```

### Windows PowerShell

```powershell
python --version
```

## Basic execution

### macOS or Linux

```bash
python3 gp_connection_attempt_report_v2.py \
  GlobalProtectLogs_richardcross_07162026205854.tgz
```

### Windows PowerShell

```powershell
python .\gp_connection_attempt_report_v2.py `
  .\GlobalProtectLogs_richardcross_07162026205854.tgz
```

By default, the script writes these files to the current directory:

```text
globalprotect_connection_attempts.csv
globalprotect_connection_attempts.json
```

It also prints a summary to the terminal.

## Recommended execution command

Create a separate report directory and analyze the newest ten attempts:

### macOS or Linux

```bash
python3 gp_connection_attempt_report_v2.py \
  GlobalProtectLogs_richardcross_07162026205854.tgz \
  --output-dir ./gp-report \
  --latest 10
```

### Windows PowerShell

```powershell
python .\gp_connection_attempt_report_v2.py `
  .\GlobalProtectLogs_richardcross_07162026205854.tgz `
  --output-dir .\gp-report `
  --latest 10
```

## Detailed timeline

Use `--verbose` to print the chronological event timeline for every included attempt:

### macOS or Linux

```bash
python3 gp_connection_attempt_report_v2.py \
  GlobalProtectLogs_richardcross_07162026205854.tgz \
  --output-dir ./gp-report \
  --latest 5 \
  --verbose
```

### Windows PowerShell

```powershell
python .\gp_connection_attempt_report_v2.py `
  .\GlobalProtectLogs_richardcross_07162026205854.tgz `
  --output-dir .\gp-report `
  --latest 5 `
  --verbose
```

## Analyze an extracted log directory

The directory may contain `PanGPS.log`, `PanGPS.log.old`, or numbered rotated `PanGPS` logs. The script searches subdirectories automatically.

### macOS or Linux

```bash
python3 gp_connection_attempt_report_v2.py \
  /path/to/extracted-globalprotect-logs \
  --output-dir ./gp-report
```

### Windows PowerShell

```powershell
python .\gp_connection_attempt_report_v2.py `
  "C:\Path\To\Extracted-GlobalProtect-Logs" `
  --output-dir .\gp-report
```

## Use a custom output filename

The `--prefix` option changes the base filename for both reports:

```bash
python3 gp_connection_attempt_report_v2.py \
  GlobalProtectLogs_richardcross_07162026205854.tgz \
  --output-dir ./gp-report \
  --prefix richardcross_gp_auth
```

This produces:

```text
gp-report/richardcross_gp_auth.csv
gp-report/richardcross_gp_auth.json
```

## Full command syntax

```text
python3 gp_connection_attempt_report_v2.py INPUT [OPTIONS]
```

| Argument | Description |
|---|---|
| `INPUT` | GlobalProtect `.tgz`, `.tar.gz`, or extracted log directory |
| `-o PATH` | Short form of `--output-dir` |
| `--output-dir PATH` | Directory in which CSV and JSON reports are written |
| `--prefix NAME` | Base filename for the CSV and JSON reports |
| `--latest N` | Include only the newest `N` connection attempts |
| `--verbose` | Print a detailed event timeline to the terminal |
| `-h`, `--help` | Display command help |

Display the built-in help:

```bash
python3 gp_connection_attempt_report_v2.py --help
```

## Running the script from another directory

Use full paths when the script and support bundle are not in the current directory.

```bash
python3 \
  "/Users/richardcross/Documents/Scripts/conversion-tools/gp_log_reader/gp_connection_attempt_report_v2.py" \
  "/Users/richardcross/Documents/Scripts/conversion-tools/gp_log_reader/GlobalProtectLogs_richardcross_07162026205854.tgz" \
  --output-dir "/Users/richardcross/Documents/Scripts/conversion-tools/gp_log_reader/reports" \
  --latest 10
```

## Optional: make the script executable on macOS or Linux

```bash
chmod +x gp_connection_attempt_report_v2.py
```

It can then be run directly:

```bash
./gp_connection_attempt_report_v2.py \
  GlobalProtectLogs_richardcross_07162026205854.tgz \
  --output-dir ./gp-report
```

## Output reports

### CSV report

The CSV file provides one row per connection attempt. It is intended for filtering, sorting, and review in Excel or another spreadsheet application.

Important columns include:

- `status`
- `connected_after_retry`
- `portal`
- `gateway`
- `gateway_ip`
- `username`
- `certificate_store_lookup`
- `selected_identity_transition`
- `final_portal_selected_identity`
- `final_gateway_selected_identity`
- `successful_path_certificate_identity`
- `successful_path_certificate_store`
- `successful_machine_certificate`
- `successful_user_certificate`
- `auth_failures`
- `certificate_selection_failures`

### JSON report

The JSON report contains the same attempt summaries plus:

- Report-level statistics
- Every certificate exchange
- User and System keychain identities found
- Matching identity count
- Certificate-selection status and errors
- Source log file and line number
- A chronological timeline for each attempt

Use the JSON report when detailed troubleshooting or programmatic processing is required.

## Interpreting certificate results

The most useful certificate fields are:

| Field | Meaning |
|---|---|
| `certificate_store_lookup` | GlobalProtect certificate-store setting, such as `machine` or `user-and-machine` |
| `selected_identity_transition` | Certificate identities selected in chronological order, with consecutive duplicates removed |
| `final_portal_selected_identity` | Last usable certificate selected for the portal |
| `final_gateway_selected_identity` | Last usable certificate selected for the gateway |
| `successful_path_certificate_identity` | Certificate associated with the final successful connection path |
| `successful_path_certificate_store` | `machine`, `user`, `unknown`, or empty |
| `certificate_selection_failures` | Locked-keychain or unusable-identity errors detected during selection |
| `certificate_selection_recovered` | A certificate-selection error occurred, but the attempt later connected successfully |

A successful machine-certificate result normally looks like:

```text
status: connected
successful_path_certificate_identity: rich-mac
successful_path_certificate_store: machine
successful_machine_certificate: true
```

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Report completed successfully |
| `1` | Archive, parsing, extraction, or file-system error |
| `2` | Input path does not exist |

On macOS or Linux, display the previous command's exit code with:

```bash
echo $?
```

In PowerShell:

```powershell
$LASTEXITCODE
```

## Troubleshooting

### Input does not exist

Use an absolute path or verify the current directory:

```bash
pwd
ls -l
```

PowerShell equivalents:

```powershell
Get-Location
Get-ChildItem
```

### No PanGPS log was found

Confirm the archive or extracted directory contains one of these files:

```text
PanGPS.log
PanGPS.log.old
PanGPS.log.1
```

The script does not use `PanGPA.log` as the primary source for connection-attempt parsing.

### Output directory cannot be written

Select a directory owned by the current user:

```bash
mkdir -p ./gp-report
python3 gp_connection_attempt_report_v2.py INPUT --output-dir ./gp-report
```

### Only review the newest attempt

```bash
python3 gp_connection_attempt_report_v2.py INPUT --latest 1 --verbose
```

### Preserve a terminal summary in a text file

macOS or Linux:

```bash
python3 gp_connection_attempt_report_v2.py \
  INPUT \
  --output-dir ./gp-report \
  --latest 10 \
  --verbose | tee ./gp-report/console-summary.txt
```

PowerShell:

```powershell
python .\gp_connection_attempt_report_v2.py `
  INPUT `
  --output-dir .\gp-report `
  --latest 10 `
  --verbose | Tee-Object -FilePath .\gp-report\console-summary.txt
```

## Example daily workflow

```bash
cd "/Users/richardcross/Documents/Scripts/conversion-tools/gp_log_reader"

python3 gp_connection_attempt_report_v2.py \
  "GlobalProtectLogs_richardcross_07162026205854.tgz" \
  --output-dir "./reports" \
  --prefix "gp_connection_attempts_2026-07-16" \
  --latest 10 \
  --verbose | tee "./reports/gp_connection_attempts_2026-07-16.txt"
```

Review the resulting files:

```text
reports/gp_connection_attempts_2026-07-16.csv
reports/gp_connection_attempts_2026-07-16.json
reports/gp_connection_attempts_2026-07-16.txt
```
