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

The count in a message causes the third version. "12,345 addresses disagree with the zone"
becomes "13,900 addresses disagree with the zone" after a partial fix. A match on the full
message text sees a different finding, drops the mark, and reports the old finding as fixed.
The tool printed a clean result and lost the reviewer's work.

This tool reads the old table and the new table, builds a fingerprint of each finding from the
columns you name, and copies the mark to the finding with the same fingerprint. It refuses an
ObjectID in the key. It masks the numbers in the columns you choose. It refuses to guess when
one fingerprint is ambiguous. It tells you when a mark vanished because the count in a
message moved, and when a mark could not be applied because the new row already holds a
different one.

## What already exists

SARIF, the static analysis exchange format, solves the same problem for code. A tool gives each
result a fingerprint, and a result management system treats two results with the same
fingerprint as the same result (SARIF 2.1.0, section 3.27.17, `partialFingerprints`). Section
3.27.24 (`baselineState`) is where a result records whether it is new, unchanged, updated or
absent against a baseline run. GitHub code scanning uses `partialFingerprints` to match alerts
across runs, so an alert appears once (see References). That is a good design, and if your findings are SARIF you should use it.

[SarifHub](https://github.com/sapir0507/sarifhub) is a public project that, by its own
description, tracks findings across SARIF scans with a stable fingerprint and supports triage
with an audit trail. When I read its README on 2026-11-11 its own status
table listed fingerprinting (phase 5) and triage (phase 6) as Planned, not as shipped features.
The page shows no date of the last push, so I give the date I read it. The project can change after that date. I did not run it.

Those tools take SARIF. A geodatabase validation tool writes a table, not SARIF, and a flat
findings table has no source file and line to compute a fingerprint from. This tool takes two
CSV files and a list of columns you choose. It does not replace SARIF fingerprints. It applies
the same idea to a flat findings table.

On 2026-11-11 a search of GitHub for this repository name and for "triage carry forward"
returned no repository that does the same job, other than this one. That is not proof that none
exists.

## What it does

The two demo files below are the whole input of the next two runs. Save them as `prior.csv`
and `current.csv`. `prior.csv` holds four reviewer marks:

```
OBJECTID,check_id,feature,message,Status,Notes
1,ADDR-01,block 7,"12,345 addresses disagree with the zone",OPEN,
2,ADDR-02,block 7,3 duplicate numbers,FALSE_POSITIVE,"known, vendor data"
3,GEOM-01,tract 4,8 gaps over 5 m,DEFERRED,next quarter
4,ADDR-01,block 9,20 addresses disagree with the zone,FIXED,corrected
5,GEOM-02,tract 4,overlap,OPEN,
6,ADDR-03,block 2,6 unnamed streets,FALSE_POSITIVE,private road
```

`current.csv` is the rebuilt table: new order, new ObjectIDs, three counts moved, one finding
fixed and one new:

```
OBJECTID,check_id,feature,message,Status,Notes
1,GEOM-02,tract 4,overlap,OPEN,
2,ADDR-01,block 9,19 addresses disagree with the zone,OPEN,
3,ADDR-02,block 7,4 duplicate numbers,OPEN,
4,ADDR-01,block 7,"13,900 addresses disagree with the zone",OPEN,
5,GEOM-01,tract 4,7 gaps over 5 m,OPEN,
6,NEW-01,block 1,something new,OPEN,
```

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
  NOTE  1 prior mark(s) have no matching finding. A fix looks the same as a truncated export, a renamed check or a drifted key. Check that each finding is really gone. The run exits 1 until you pass --accept-resolved.
  WARNING  1 prior mark(s) have no matching finding while 5 finding(s) are new. A renamed check or a drifted key looks the same as a fix. Compare them before you trust the file.
  LOST  prior row(s) 2: addr-02 | block 7 | 3 duplicate numbers looks like current row(s) 3 but a number differs in message. Add that field to --mask if the number is a count.
  LOST  prior row(s) 3: geom-01 | tract 4 | 8 gaps over 5 m looks like current row(s) 5 but a number differs in message. Add that field to --mask if the number is a count.
  LOST  prior row(s) 4: addr-01 | block 9 | 20 addresses disagree with the zone looks like current row(s) 2 but a number differs in message. Add that field to --mask if the number is a count.
dry run: nothing written. Add --out FILE --apply to write the marked copy.
exit 1
```

Without `--mask` three counts changed, so three marks look like fixed findings. The tool
notices that each vanished finding matches a new one once the numbers in the message are
ignored, reports the marks as lost, and exits 1. A silent "fixed" would have been the disaster
above. The drift check looks at the last `--key` column, so list the message last. A number in
an earlier column, such as a block or a parcel, names another feature and is never read as a
drifted count. With the count column masked, a mark that crosses a changed number is carried but the run
still exits 1, because a mask cannot tell a moved count from a different finding:

```
$ python triage_carry_forward.py --prior prior.csv --current current.csv --key check_id,feature,message --mask message
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
  NOTE  3 carried mark(s) sit on a finding whose masked number changed. --mask treats a number as noise, so check that each is the same finding. The run exits 1 until you pass --accept-shifted.
  NOTE  1 prior mark(s) have no matching finding. A fix looks the same as a truncated export, a renamed check or a drifted key. Check that each finding is really gone. The run exits 1 until you pass --accept-resolved.
dry run: nothing written. Add --out FILE --apply to write the marked copy.
exit 1
```

The three counts are real count changes, so check them. One more prior mark, on `ADDR-03`
in block 2, has no matching finding. The tool calls it resolved, and the run exits 1 until you
pass `--accept-resolved`, because a fixed finding looks the same as a truncated export, a
renamed check or a count that moved in a key column. Check that the finding is really gone,
then run the command again with both flags:

```
$ python triage_carry_forward.py --prior prior.csv --current current.csv --key check_id,feature,message --mask message --accept-shifted --accept-resolved
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
  NOTE  3 carried mark(s) sit on a finding whose masked number changed. --mask treats a number as noise, so check that each is the same finding.
dry run: nothing written. Add --out FILE --apply to write the marked copy.
exit 0
```

Add `--out marked.csv --apply` to write the current table with three marks carried, under the
new ObjectIDs. The self-test pins that written file; the transcript above stops at the dry
run. One carried mark is the `FIXED` mark of block 9 (20 addresses), which lands on the
19-address finding. If that finding is still open, the mark hides it. The NOTE and the exit 1
exist to make you check this, and `--accept-shifted` records that you did.

The exit 1 is the cost of masking. The tool cannot tell a moved count from a different finding
of the same shape. A parcel numbered 1200 and a parcel numbered 1300 share one masked key, so a
mark on the first one would land on the second and hide it. The tool counts every mark that
crossed a changed number and refuses to call the run clean until you accept them. If a number
in the masked column names a feature, move that number into its own `--key` column, which
`--mask` does not touch.

## Self-test

```
$ python triage_carry_forward.py --self-test
triage_carry_forward self-test: no arcpy, no database, no network
--------------------------------------------------------------------
PASS  normalize folds case and whitespace
...
PASS  copying by OBJECTID marks unrelated findings and the fingerprint does not  <-- pinned defect
PASS  the OBJECTID 4 mark belongs to a different finding after the rebuild  <-- pinned defect
...
PASS  the footer of a failing harness names the failures and exits 1
--------------------------------------------------------------------
383 assertions, 0 failed
```

The block above elides the middle of the run with `...`. The first lines, the last PASS line
and the footer are verbatim. Run the command to see all 383 lines.

Every fixture is synthetic. The self-test also runs the script as a separate process, writes
real CSV files in a scratch directory, and reads back the files it wrote. Branch coverage of
the file is 100 percent, measured with `coverage run --branch triage_carry_forward.py --self-test`
(916 statements, 184 branches, none missed). One exclusion applies: the last line,
`if __name__ == "__main__":`, carries `# pragma: no branch`, because its false branch is
unreachable when the file is run. The count is 383 on Windows (Python 3.9, 3.10, 3.12 and 3.13) and on
Linux (Python 3.9, 3.10, 3.11, 3.12 and 3.13). No assertion depends on the platform.

## Requirements

Python 3.9 or newer, standard library only. No `arcpy`, no network. Nothing to install. The
self-test was run, with warnings as errors, on Python 3.9, 3.10, 3.12 and 3.13 on Windows and on 3.9, 3.10, 3.11, 3.12 and 3.13 on Linux.

```
git clone https://github.com/uhsear/triage-carry-forward.git
python triage_carry_forward.py --self-test
```

Export the findings tables to comma-delimited UTF-8 CSV with your usual tool before you run
this one.

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
| `--accept-shifted` | off | Exit 0 although a mark crossed a changed masked number. Pass it after you checked them. |
| `--accept-resolved` | off | Exit 0 although marked findings are gone from the current file. Pass it after you checked that each is really fixed. `--allow-empty-current` and `--allow-no-carry` imply it. |
| `--allow-oid-key` | off | Allow an ObjectID-style column in `--key`. |
| `--allow-empty-current` | off | Accept a current file with no rows when the prior file has marks. |
| `--allow-no-carry` | off | Accept a run that carries no mark: the prior file holds no marks, or every marked prior finding is gone from the current file. |
| `--out` | none | New CSV to create. Needs `--apply`. Never overwrites. |
| `--apply` | off | Write `--out`. Without it nothing is written. |
| `--self-test` | off | Run the offline assertions and exit. |

Spell flag names in full. `allow_abbrev` is off, so `--ap` is refused and does not act as
`--apply`.

Exit codes: 0 every mark carried, or resolved and accepted, 1 some marks could not be carried,
a carried mark crossed a changed masked number, or a marked finding is gone and
`--accept-resolved` was not passed, 2 usage error, 3 the output could not be written, 4 the
run could not tell a fix from a failure (see "How it decides"), 5 an unexpected internal error (one line on stderr, no traceback). `--self-test` also exits 1 when an
assertion fails.

A marked finding that is gone is `resolved`. The tool cannot tell a fix from a truncated
export, a renamed check or a count that moved in a key column, so the run exits 1 and prints a
NOTE until you pass `--accept-resolved`. Compare the `resolved` count and the row counts before
you do.

Exit 0 can still print a `WARNING` line. It appears when resolved prior marks outnumber the
carried plus kept-current rows and new findings appeared, which is also what a renamed check
looks like. Read it before you trust the file.

A row counts as marked when its status differs from the default status, or its notes are not
empty. The tool carries the status and the notes together. If your validation tool writes its
own status into every new row (for example `NEW`), pass it as `--default-status`. Otherwise
every new row looks reviewed and the prior marks are reported lost.

Blank lines in a CSV are skipped. A character the console cannot encode prints as
`?` instead of stopping the report.

## How it decides

The fingerprint is the list of the key cells after Unicode NFKC folding, case folding and
whitespace collapse. In a masked column, every run of digits, with its commas, points and
underscores, becomes `#`.

For each fingerprint:

- Only in the new run: `new`. It starts unreviewed.
- No prior mark on any twin: `unmarked`.
- One prior mark, same number of rows on both sides: `carried`.
- The new row already has a mark of its own: `kept-current`. The new file wins. If its mark
  differs from the prior mark, the prior mark is counted as lost and the run exits 1.
- The prior twins carry different marks: `conflict`. Nothing is carried, and the lost marks are counted.
- The prior mark has a different number of rows now: `count-changed`. The tool cannot tell which twin the mark belonged to, so nothing is carried.
- Every key cell is blank: `unkeyable`. A marked prior row like this counts as lost.

A prior mark whose fingerprint is gone is `resolved` (the run exits 1 until `--accept-resolved`), unless the same fingerprint appears
after the numbers in the last `--key` column (and in the `--mask` columns) are masked. Then the
count drifted, and the mark is reported as lost.

A key cell is compared with every apostrophe in front of a formula character dropped, so a
cell the tool wrote with its guard and the same cell in a raw export have one fingerprint.

The tool exits 4 and writes nothing, even with `--apply`, when a clean exit would read as "all
marks carried" and the tool cannot tell that from a failure. Five cases:

- The prior file holds no marked row in the status and notes columns. The reviewer's marks may
  sit in another column, so the message names `--status-field` and `--notes-field`. If nobody
  reviewed the prior run, pass `--allow-no-carry`.
- The current file has no rows (`--allow-empty-current` accepts it).
- No current row has a usable key.
- No current row matches any prior row.
- No current row matches a marked prior row and no mark was reported lost. With new findings
  this looks like a renamed check or a drifted key, and `--allow-no-carry` does not accept it.
  With no new findings, every marked finding is gone, which is what a fix and a truncated
  export both look like. `--allow-no-carry` accepts that one after you compare the row counts.
  An unmarked survivor row does not stop either refusal, so a rename with one survivor looks
  no cleaner than a rename with none.

## Why the obvious version is wrong

Matching on `OBJECTID` is the first thing people try. Esri documents the object ID field as
"maintained by ArcGIS" and as guaranteeing "a unique ID for each row in the table" (see
References). That is a promise of uniqueness within one table. It is not a promise that a
finding keeps its number when the output table is deleted and built again, and a rebuild that
lists findings in a different order will not keep it. This tool refuses an ObjectID-style
column in `--key` (`objectid`, `oid`, `fid`, `rowid`, `source_oid`, and the spellings a join
or an export adds, such as `OBJECTID_1`, `FID_1`, `FID_parcels`, `OBJECT_ID`, `OBJ_ID`)
unless you pass `--allow-oid-key`.

Matching on the full message is the second attempt. It breaks on the first count that moves.
Masking fixes that, and masking has a cost: two findings that differ only in a number now
share a fingerprint. The tool covers that case. If their marks differ it reports `conflict`. If
the number of twins changes it reports `count-changed`. It does not guess in either case.
When one prior finding and one new finding share a masked key, the mark is carried, because
the tool cannot tell a moved count from a different finding. The NOTE line counts those
carries, and the run exits 1 until you pass `--accept-shifted`.

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

## Limits

- The 100 percent branch coverage figure relies on one `# pragma: no branch` on the
  `if __name__` line, described under Self-test. Every other line and branch is measured.
- Formula guard. The input files are untrusted, so every text cell of the output, the header
  included, is checked before it is written. A cell whose first character is `=`, `+`, `-`,
  `@`, tab, CR or LF, or the full-width form of `=`, `+`, `-` or `@`, gets one leading
  apostrophe (OWASP, CSV Injection, in References, which lists all of these characters). A plain number such as `-3` or `+4.5` is left alone, so a
  numeric column stays numeric. When the tool reads a file, it strips one apostrophe that sits
  in front of such a character. A round trip of the tool's own output therefore changes
  nothing, and a Notes cell that really starts with `'` survives: `'=quoted` is written as
  `''=quoted` and read back as `'=quoted`. The self-test pins each guarded field, tab and CR
  included.
- The strip on read is exact. It removes one leading apostrophe only where the writer would
  add one: in front of a formula character, when the rest of the cell is not a plain number. A
  raw cell `'=x` reads as `=x` and is written back as `'=x`, so the file is unchanged. A raw
  cell `'-12` (apostrophe, then a plain number) is not a guard, so it is read as `'-12` and
  written as `''-12`. The same holds for a Notes cell: `'-3` carries through as `'-3`. The tool
  cannot tell a guard from a real apostrophe in a raw export, so a raw `'=x` that really starts
  with an apostrophe loses it, and a prior file written by an older, unguarded version of this
  tool loses it the same way on the next carry. Key cells are compared with those apostrophes
  dropped on both sides, so a guarded prior cell and a raw current cell with the same text
  still carry the mark. The strip applies to every column, not only the key and the marks.
- The key fold drops every leading apostrophe in front of a formula character. Two findings
  whose key cells differ only by leading apostrophes before a formula character are treated as
  the same finding, and fall under the `conflict` or `count-changed` rules.
- The guard tests only the first character, so a cell that starts with a space, a
  non-breaking space, a zero-width character or another control character before `=`, `+`, `-`
  or `@` is written unchanged; this tool did not test how spreadsheets treat it. The guard
  covers the characters OWASP lists (LF among them), plus the full-width forms of `=`, `+`, `-`
  and `@`, and nothing else. A cell
  that starts with `|` or `%` is not guarded.
- A signed number with a thousands separator, such as `-1,234` or `+1,000`, is not a plain
  number to the guard, so the tool writes that number as text with a leading apostrophe, and a
  column that holds such values does not stay numeric. A signed number without a separator,
  such as `-3` or `+4.5`, is written unchanged.
- The apostrophe is visible text when the CSV is opened in some spreadsheets. A guarded cell
  shows a leading `'` there, and the strip on read undoes it only for this tool. OWASP says the
  mitigations it lists, the apostrophe among them, are not reliable in Excel after the file is
  saved and opened again. OWASP recommends a leading tab for Excel-resistant output; this tool
  uses the apostrophe the spec asked for and reads it back, so open the output in Excel only
  after reading it. Excel was not run for this tool.
- With exit 1 and `--apply`, the tool still writes the output file, with the lost marks left as
  they are in the current file (usually OPEN). Read the LOST lines before you use the file.
  Exit 4 never writes.
- Column names for `--key`, `--status-field` and `--notes-field` match exactly. A header that
  differs in case or has trailing spaces is refused as a usage error.
- Input must be comma-delimited UTF-8. A cp1252 file that holds a non-ASCII byte, a UTF-16
  export and a semicolon-delimited file are refused with exit 2. An ASCII-only cp1252 file is accepted,
  because its bytes are valid UTF-8. The semicolon case reports a missing key column and hides the real cause,
  so check the delimiter first.
- The output is UTF-8 without a byte order mark, with LF line ends. Excel may show non-ASCII
  text wrongly when you double-click the file. This was not tested, and the Microsoft page on
  importing CSV files (in References) says nothing about encodings or the byte order mark, so
  treat that advice as unverified. The page does document Data > From Text/CSV as the route
  that lets you inspect how a CSV file is read.
- Carried notes lose leading and trailing whitespace. A Notes cell that starts with a tab is
  carried without it, so the guard never sees that tab. Marks are compared exactly:
  `false_positive` and `FALSE_POSITIVE` on two prior twins count as different marks and give a
  `conflict`.
- Version-like or decimal text in a masked column (for example `v2.1`) is masked as a count.
  Two findings that differ only in such a number share one fingerprint and fall under the
  `conflict` or `count-changed` rules.
- Fingerprints fold with NFKC and case folding only. Zero-width characters and soft hyphens are
  kept, so two findings that look identical can differ.
- A `conflict` or `count-changed` verdict counts the prior marks as lost even when the new
  rows already hold a mark of their own.
- A current file that is a truncated export and still matches at least one marked prior finding
  reports the missing marked findings as resolved, because the tool cannot tell a fix from a
  missing row. The run exits 1 until you pass `--accept-resolved`, and the pass is your word that
  you compared the row counts. A current file that lost every marked finding exits 4.
- Giving the same file as `--prior` and `--current` is accepted. A marked row counts as
  kept-current, an unmarked row as unmarked, and the run exits 0. The tool does not check that
  the two files are different runs.
- The report prints key cells as they appear in the data, control and escape characters
  included. A key cell that holds a control or escape character is printed unchanged in the
  LOST and conflict lines, up to 60 characters of each cell. A key column that holds a secret,
  such as a connection string in a message, sends that text to the terminal and any log;
  redirect or scrub the report when key columns may hold secrets. This is not covered by the
  self-test.
- `--out` is opened for exclusive creation, but the tool does not test that the target is a
  regular file. On Windows, `--out nul` can report success and keep nothing; NUL is a reserved
  device name there (see References). This is not covered by the self-test.
- A single CSV cell over Python's csv limit of 131072 characters is refused as exit 2
  `cannot read`, not skipped. The self-test pins both sides of the limit.
- Python's csv module always quotes a field that holds the delimiter or the quote character.
  On Python 3.9 and 3.10 it quotes a line break only when the break is part of the line
  terminator, so a bare CR was left unquoted and split the record. The version difference in
  csv quoting was found by running the self-test on each Python version, not taken from the
  documentation. The writer therefore emits each row with a CR LF terminator, which
  quotes CR and LF on every version, and then ends the line with LF. A cell with a bare CR is
  quoted in the file (Python csv documentation, `QUOTE_MINIMAL`, in References).
- `--out` is compared with the inputs by real path, with case ignored on Windows (Microsoft's
  file naming rules say not to assume case sensitivity; see References). An `--out` path that
  reaches an input through a hard link or an 8.3 short name is not detected; creation is still
  exclusive, so no file is overwritten. Subst drives are not detected either.
- The CSV reader is strict. An unterminated opening quote in a cell, for example a hand-typed
  Notes cell that starts with `"`, is refused as exit 2 `cannot read ... unexpected end of
  data`. Without strict mode Python merged every following row into that cell, and the missing
  findings were reported as resolved. A quote inside an unquoted cell, such as `5" pipe`, is
  still read.
- `--status-field` and `--notes-field` name the only columns that hold marks. A mark in any
  other column is not seen; the run exits 4 when no row holds a mark in the named columns.
- `--key` refuses names like `OBJECTID`, `OBJECTID_1` and `FID_parcels`. It does not refuse
  `OBJECTID1` or a bare `id`, which can also be a row number that a rebuild changes.
- A blank line is skipped, so in a one-column file a row whose only cell is empty is skipped
  too.
- An unexpected error exits 5 with one line on stderr. Exit 1 from a run means lost marks or
  an unaccepted shifted carry or an unaccepted resolved mark. Exit 1 from `--self-test` means failed assertions.
- A header with two or more blank cells is refused as exit 2 `repeats a column name`. A header
  with exactly one blank cell, such as a trailing comma, is accepted, and the blank column is
  carried through to the output. A data row with a trailing comma under a header that has no
  blank cell is refused as exit 2 `has 7 cells but the header has 6`. Common spreadsheet
  exports can trigger either refusal.
- Only the last `--key` column is tested for a drifted count. With the message listed before
  another column and no `--mask`, a changed count is not recognised as drift, so the mark is
  reported resolved and the run exits 1 until `--accept-resolved`. List the message last.
- NFKC folding makes compatibility characters, such as ligatures, equal to their plain forms,
  so two findings that differ only by such a character share a fingerprint and fall under the
  `conflict` or `count-changed` rules. This was not run.
- A cell that holds a NUL byte is read on Python 3.13 and refused as exit 2 `cannot read ... line
  contains NUL` on Python 3.9, so the exit code for such a file depends on the Python version.
  Both were run on a one-cell file.
- A partial write leaves a partial `--out` file with exit 3, and the next run refuses it as
  already existing. Delete the partial file before you run again.

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
| A mark the new row cannot take is lost, not dropped silently | Self-test, `kept-current` assertions and the NEW-status CLI run |
| A fixed finding next to a new one on another block is not a lost mark | Self-test, the feature-number assertions and the block 7 and block 9 CLI run |
| Joined and exported ObjectID names are refused | Self-test, the OID-style name list |
| A console that cannot encode a character still gets the report | Self-test, a separate process with `PYTHONIOENCODING=ascii` |
| An unexpected error exits 5 | Self-test, a forced error in `run` |
| A text cell that starts with `=`, `+`, `-`, `@`, tab, CR or LF is written with one apostrophe, in every output field and the header | Self-test, one assertion per field and per leading character, then read back from the file |
| A plain number stays a number | Self-test, `-3`, `+3`, `-1.5`, `-.5` and the other numeric cells, written and read back |
| The tool reads its own output back and strips exactly one apostrophe, so marks and fingerprints survive a second cycle | Self-test, the two-cycle assertions and the `'=quoted` Notes round trip |
| A bare CR inside a cell is quoted in the file | Self-test, a byte comparison of the written file, run on Python 3.9, 3.10, 3.12 and 3.13 |
| Marks in an unnamed column, and a current file that lost every marked finding, exit 4 and write nothing; `--allow-no-carry` accepts them | Self-test, the CLI runs and the `dead_run` assertions |
| A stray opening quote is refused, not merged into one cell | Self-test, `read_rows` and CLI assertions |
| A cell over the csv field limit is refused | Self-test, 131073 and 131072 characters |
| The two demo reports | Run by hand on the two files shown above, Windows, Python 3.13. The write step is pinned by the self-test |
| A mark carried across a changed masked number exits 1 until `--accept-shifted` | Self-test, `exit_code` and CLI assertions |
| A rename with one unmarked survivor exits 4, like a rename with none | Self-test, `dead_run` and CLI assertions |
| A guarded prior key and a raw current key with the same text carry the mark | Self-test, `normalize` and CLI assertions |
| A marked finding that is gone exits 1 until `--accept-resolved`, for a truncated export, a partial rename and a count that moved in a key column | Self-test, `exit_code` and CLI assertions, the three pinned runs |
| A Notes cell that is an apostrophe and a number, and a raw `'=x` or `'-12`, round-trip as described in Limits | Self-test, the per-field round trip and the raw apostrophe assertions |
| A cell with a NUL byte is read on 3.13 and refused on 3.9 | Run by hand on one file, not in the self-test |
| Linux and Windows agree | 383 assertions on Python 3.9, 3.10, 3.12 and 3.13 on Windows and 3.9, 3.10, 3.11, 3.12 and 3.13 on Linux |

## References

- OASIS SARIF Version 2.1.0, Errata 01, sections 3.27.17 (`partialFingerprints`) and 3.27.24
  (`baselineState`): https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html
- GitHub, SARIF support for code scanning, `partialFingerprints`:
  https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
- OWASP, CSV Injection (the list of leading characters, the single quote prefix and its limits):
  https://owasp.org/www-community/attacks/CSV_Injection
- Python documentation, `csv` module, `QUOTE_MINIMAL` and the `newline=''` rule for files:
  https://docs.python.org/3/library/csv.html
- Microsoft, Naming Files, Paths, and Namespaces (case sensitivity, reserved device names such as
  NUL, 8.3 names, hard links):
  https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
- Microsoft, Import or export text (.txt or .csv) files (the Data > From Text/CSV route):
  https://support.microsoft.com/en-us/office/import-or-export-text-txt-or-csv-files-5250ac4c-663c-47ce-937b-339e391393ba
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
