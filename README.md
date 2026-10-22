# triage-carry-forward

Carry reviewer marks from the last run of a validation tool to the next run by what a finding
says, never by the row number or the ObjectID it happened to get.

A validation tool writes its findings to a table. A reviewer works through the table for a
week. They mark 300 findings FALSE_POSITIVE with a note, three DEFERRED until next quarter, and
a few FIXED. Then someone fixes the data and runs the tool again to confirm. The tool deletes
the output table and builds it again.

Every mark is gone. The reviewer starts over, or does not notice, and the known false
positives come back as open findings. That is the loud version.

The quiet version is worse. Someone copies the marks across by row number or by ObjectID,
because both are columns that exist in both tables. The new run lists the findings in a
different order, with new ObjectIDs, and one finding fewer. The FALSE_POSITIVE note now sits on
a real error in another block. Nothing fails. The table looks triaged.

The count in a message causes the third version. "14,039 addresses disagree with the zone"
becomes "13,900 addresses disagree with the zone" after a partial fix. A match on the full
message text sees a different finding, drops the mark, and reports the old finding as fixed.
The tool printed a clean result and lost the reviewer's work.

This tool reads the old table and the new table, builds a fingerprint of each finding from the
columns you name, and copies the mark to the finding with the same fingerprint. It refuses an
ObjectID in the key. It masks the numbers in the columns you choose. It refuses to guess when
one fingerprint is ambiguous. It tells you when a mark vanished because a count moved.

## What already exists

SARIF, the static analysis exchange format, solves the same problem for code. A tool gives each
result a fingerprint, and a result management system treats two results with the same
fingerprint as the same result (SARIF 2.1.0, sections 3.27.17 and 3.27.24). GitHub code
scanning uses `partialFingerprints` to match alerts across runs, so an alert appears once (see
References). That is a good design, and if your findings are SARIF you should use it.

[SarifHub](https://github.com/sapir0507/sarifhub) is a public project that, by its own
description, tracks findings across SARIF scans with a stable fingerprint and supports triage
with audited decisions. I did not run it.

Those tools take SARIF. A geodatabase validation tool writes a table, not SARIF, and a flat
findings table has no source file and line to compute a fingerprint from. This tool takes two
CSV files and a list of columns you choose. It does not replace SARIF fingerprints. It applies
the same idea to a flat findings table.

A search of GitHub for this repository name and for "triage carry forward" found no repository
that does the same job. That is not proof that none exists.

## What it does

```
$ python triage_carry_forward.py --prior prior.csv --current current.csv --key check_id,feature,message
triage_carry_forward: prior 6 rows (4 marked), current 6 rows
key: check_id, feature, message
carried         0
kept-current    0
unmarked        1
new             5
conflict        0
count-changed   0
unkeyable       0
resolved        1  (prior marks whose finding is gone)
lost marks      3
  LOST  prior row(s) 2: addr-02 | block 7 | 3 duplicate numbers looks like current row(s) 3 but a number differs. Add that field to --mask if the number is a count.
  LOST  prior row(s) 3: geom-01 | tract 4 | 8 gaps over 5 m looks like current row(s) 5 but a number differs. Add that field to --mask if the number is a count.
  LOST  prior row(s) 4: addr-01 | block 9 | 20 addresses disagree with the zone looks like current row(s) 2,4 but a number differs. Add that field to --mask if the number is a count.
dry run: nothing written. Add --out FILE --apply to write the marked copy.
exit 1
```

Without `--mask` three counts changed, so three marks look like fixed findings. The tool
notices that each vanished finding matches a new one once numbers are ignored, reports the
marks as lost, and exits 1. A silent "fixed" would have been the disaster above. With the count
column masked:

```
$ python triage_carry_forward.py --prior prior.csv --current current.csv --key check_id,feature,message --mask message --out marked.csv --apply
triage_carry_forward: prior 6 rows (4 marked), current 6 rows
key: check_id, feature, message (counts masked in: message)
carried         3
kept-current    0
unmarked        2
new             1
conflict        0
count-changed   0
unkeyable       0
resolved        1  (prior marks whose finding is gone)
lost marks      0
wrote 6 rows to marked.csv
exit 0
```

`marked.csv` is the current table with three marks on the right findings, under the new
ObjectIDs. The fourth prior mark belonged to a finding that is really gone, so it is reported
as resolved.

## Self-test

```
$ python triage_carry_forward.py --self-test
triage_carry_forward self-test: no arcpy, no database, no network
--------------------------------------------------------------------
PASS  normalize folds case and whitespace
...
PASS  copying by OBJECTID marks unrelated findings and the fingerprint does not  <-- pinned defect
PASS  the OBJECTID 4 mark belongs to a different finding after the rebuild  <-- pinned defect
PASS  without --mask a changed count drops every mark  <-- pinned defect
PASS  without --mask the drifted marks are reported lost, not quietly resolved  <-- pinned defect
...
PASS  the footer of a failing harness names the failures and exits 1
--------------------------------------------------------------------
146 assertions, 0 failed
```

Every fixture is synthetic. The self-test also runs the script as a separate process, writes
real CSV files in a scratch directory, and reads back the files it wrote. Branch coverage of
the file is 100 percent, measured with `coverage run --branch triage_carry_forward.py --self-test`.
The count is 146 on Windows (Python 3.13) and on Linux (Python 3.12). No assertion depends on
the platform.

## Requirements

Python 3.9 or newer, standard library only. No `arcpy`, no network. Nothing to install. The
file parses with the Python 3.9 grammar. It was run on 3.12 and 3.13, not on 3.9 itself.

```
git clone https://github.com/uhsear/triage-carry-forward.git
python triage_carry_forward.py --self-test
```

Export the findings tables to UTF-8 CSV with your usual tool before you run this one.

## Usage

Check first. Nothing is written without `--apply`.

| Flag | Default | What it does |
|---|---|---|
| `--prior` | none | Previous findings CSV, with the reviewer marks. Required. |
| `--current` | none | New findings CSV. Required. |
| `--key` | none | Comma list of columns that make the fingerprint. Required. |
| `--mask` | none | Key columns whose numbers are ignored. Must be inside `--key`. |
| `--status-field` | `Status` | Column that holds the reviewer status. |
| `--notes-field` | `Notes` | Column that holds the reviewer notes. |
| `--default-status` | `OPEN` | Status of a row nobody reviewed. Compared without case. |
| `--allow-oid-key` | off | Allow an ObjectID-style column in `--key`. |
| `--allow-empty-current` | off | Accept a current file with no rows when the prior file has marks. |
| `--out` | none | New CSV to create. Needs `--apply`. Never overwrites. |
| `--apply` | off | Write `--out`. Without it nothing is written. |
| `--self-test` | off | Run the offline assertions and exit. |

Spell flag names in full. `allow_abbrev` is off, so `--ap` is refused and does not act as
`--apply`.

Exit codes: 0 every mark carried or resolved, 1 some marks could not be carried, 2 usage
error, 3 the output could not be written, 4 the key compared nothing.

A row counts as marked when its status differs from the default status, or its notes are not
empty. The tool carries the status and the notes together.

## How it decides

The fingerprint is the list of the key cells after Unicode NFKC folding, case folding and
whitespace collapse. In a masked column, every run of digits, with its commas, points and
underscores, becomes `#`.

For each fingerprint:

- Only in the new run: `new`. It starts unreviewed.
- No prior mark on any twin: `unmarked`.
- One prior mark, same number of rows on both sides: `carried`.
- The new row already has a mark of its own: `kept-current`. The new file wins.
- The prior twins carry different marks: `conflict`. Nothing is carried, and the lost marks are counted.
- The prior mark has a different number of rows now: `count-changed`. The tool cannot tell which twin the mark belonged to, so nothing is carried.
- Every key cell is blank: `unkeyable`. A marked prior row like this counts as lost.

A prior mark whose fingerprint is gone is `resolved`, unless the same fingerprint appears once
every number is masked. Then the count drifted, and the mark is reported as lost.

The tool exits 4 and writes nothing, even with `--apply`, when it compared nothing: the new
file has no rows while the prior file has marks, no new row has a usable key, or no new row
matches any prior row. A clean exit there would read as "all marks carried".

## Why the obvious version is wrong

Matching on `OBJECTID` is the first thing people try. Esri documents the object ID field as
"maintained by ArcGIS" and as guaranteeing "a unique ID for each row in the table" (see
References). That is a promise of uniqueness within one table. It is not a promise that a
finding keeps its number when the output table is deleted and built again, and a rebuild that
lists findings in a different order will not keep it. This tool refuses an ObjectID-style
column in `--key` (`objectid`, `oid`, `fid`, `rowid`, `source_oid` and similar) unless you
pass `--allow-oid-key`.

Matching on the full message is the second attempt. It breaks on the first count that moves.
Masking fixes that, and masking has a cost: two findings that differ only in a number now
share a fingerprint. The tool covers that case. If their marks differ it reports `conflict`. If
the number of twins changes it reports `count-changed`. It does not guess in either case.

## What it will not do

- It does not read a geodatabase or call `arcpy`. It reads and writes CSV.
- It does not carry a mark across a change in the key text. If a check is renamed, the old
  marks are `resolved` and the new findings are `new`, unless the renamed finding still
  matches once numbers are masked.
- It does not merge marks when twins disagree. A person decides.
- It does not overwrite anything. `--out` is a new file, and an existing file is refused. If
  the disk fails part way through a write, a partial file can remain. Delete it and run again.
- It does not check that the prior file is the run before the current one. Give it the wrong
  file and it carries the wrong marks.
- Fingerprints are exact after folding. It does no fuzzy matching.
- No network and no credentials are involved, so there is no network path to stub.

## How each claim was exercised

| Claim | Where it was run |
|---|---|
| Marks follow the finding after a rebuild with new ObjectIDs, new order and changed counts | Self-test, "the rebuild" assertions, and the demo above |
| Copying by ObjectID marks unrelated findings | Self-test, the two `OBJECTID` pinned defects |
| An ObjectID key is refused, and `--allow-oid-key` allows it | Self-test, `validate_fields` and CLI assertions |
| A moved count without `--mask` is reported lost, exit 1 | Self-test and the first demo run above |
| Conflicts and changed twin counts are refused | Self-test, `conflict` and `count-changed` assertions |
| A key that compares nothing exits 4 and writes nothing under `--apply` | Self-test, exit 4 assertions |
| Nothing is written without `--apply` | Self-test lists the scratch directory before and after a dry run |
| `--out` never overwrites | Self-test, exit 3 assertions, file read back unchanged |
| `--ap` is refused | Self-test, in process and as a separate process |
| UTF-8 data and a byte order mark | Self-test, round trip assertions |
| Linux and Windows agree | 146 assertions on both hosts |

## References

- OASIS SARIF Version 2.1.0, Errata 01, sections 3.27.17 (`partialFingerprints`) and 3.27.24
  (`baselineState`): https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html
- GitHub, SARIF support for code scanning, `partialFingerprints`:
  https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
- Esri, ArcGIS field data types, the Object ID field:
  https://doc.esri.com/en/arcgis-pro/latest/help/data/geodatabases/overview/arcgis-field-data-types.html

## Contributing

Open an issue or pull request on GitHub.

## Author

Built by [Asir Khan](https://www.linkedin.com/in/asir-khan-310317264/).

## License

MIT.

## Related

Other single-file tools in this portfolio that pair with this one:

- [idreuse](https://github.com/uhsear/idreuse) - the same lesson for two layers that share an ID someone recycles
- [safe-republish](https://github.com/uhsear/safe-republish) - refuse the rebuild itself when the replacement is not believable
