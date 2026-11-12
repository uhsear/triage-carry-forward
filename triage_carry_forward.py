#!/usr/bin/env python
"""Carry reviewer marks forward to a new run by a content fingerprint, never by an OID.

A validation tool writes its findings to a table. A reviewer opens the table and marks
findings: Status FALSE_POSITIVE, Notes "known, vendor data". The reviewer fixes some data
and the tool runs again. The new table is a rebuild, so the marks are gone, or worse, they
were copied by row number or by ObjectID and now sit on the wrong finding.

This tool reads the previous table (with the marks) and the new table (without them), and
matches each finding by a fingerprint of the fields YOU name: the check id, the feature
reference, the message. The row number and the ObjectID are not part of it. A field that
holds a count ("12,345 addresses disagree") can be masked, so the count may change between
runs without losing the mark.

A match is only trusted when it is unambiguous. If one fingerprint carries two different
marks, or appears a different number of times in the two runs, the mark is NOT carried and
the tool says so and exits 1. A prior mark that the current row cannot take, because the
current row already holds a different mark, is also lost and also exits 1. A key that
compares nothing at all exits 4. So does a prior file with no mark in the status and notes
columns, a run in which no marked prior finding matches while no mark was reported lost, and a
run in which every marked prior finding is gone (--allow-no-carry accepts the last two).
A mark carried across a changed number in a --mask field exits 1 until --accept-shifted is passed.
A marked prior finding that is gone exits 1 until --accept-resolved is passed, because a fix looks the
same as a truncated export, a renamed check or a count that moved in a key field.

    python triage_carry_forward.py --self-test
    python triage_carry_forward.py --prior old.csv --current new.csv --key check_id,feature,message --mask message
    python triage_carry_forward.py --prior old.csv --current new.csv --key check_id,feature,message --mask message --out new_marked.csv --apply

Without --apply nothing is written. Exit codes: 0 every mark carried, or resolved and
accepted, 1 some marks could not be carried, a carried mark crossed a changed masked number, or a
marked finding is gone and --accept-resolved was not passed, 2 usage error,
3 the output could not be written, 4 the key compared nothing, 5 an unexpected internal error.
"""
from __future__ import print_function

import argparse
import contextlib
import csv
import io
import os
import re
import subprocess
import sys
import tempfile
import unicodedata

EXIT_OK = 0
EXIT_LOST = 1
EXIT_USAGE = 2
EXIT_WRITE = 3
EXIT_NOTHING = 4
EXIT_CRASH = 5

DEFAULT_STATUS = "OPEN"
MAX_LINES = 20

# A run of digits with the separators people print inside a count: 12,345 or 1.5 or 2_000.
_COUNT = re.compile(r"\d+(?:[,._]\d+)*")
# Field names that hold a row identity the next rebuild will not reproduce. Includes the
# names a join or an export gives them: OBJECTID_1, FID_1, FID_<layer>, OBJECT_ID, OBJ_ID.
_OID_NAME = re.compile(
    r"^(?:[a-z0-9]*_)?(?:object_?id|obj_id|oid|fid|rowid)(?:_\d+)?$"
    r"|^(?:fid|oid)_[a-z0-9_]+$|^(?:source|src)oid$")

# A spreadsheet runs a text cell as a formula when it starts with one of these (OWASP, CSV
# Injection): = + - @ tab CR LF, and the full-width forms of the first four.
_LEAD = r"=+\-@\t\r\n\uff1d\uff0b\uff0d\uff20"
_GUARDED = re.compile(u"^'*[" + _LEAD + u"]")
# Apostrophes in front of a formula character, dropped from a key cell before it is compared.
_GUARD_FOLD = re.compile(u"^'+(?=[" + _LEAD + u"])")
# A plain number is never a formula, so a numeric column stays numeric. \Z, not $: $ also
# matches before a final newline.
_PLAIN_NUMBER = re.compile(r"^[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z")

OUTCOMES = ("carried", "kept-current", "unmarked", "new", "conflict",
            "count-changed", "unkeyable")


class UsageError(ValueError):
    """The request cannot be run as written. Never raised for a data finding."""


# ----------------------------------------------------------------------------
# Pure decision core. No file, no network, no clock.
# ----------------------------------------------------------------------------

def normalize(value, mask):
    """Fold a cell to the form two runs agree on; mask=True also hides every number.
    Apostrophes in front of a formula character are dropped, because a raw export and a copy this
    tool wrote cannot be told apart by the cell alone (see the README Limits)."""
    text = unicodedata.normalize("NFKC", _GUARD_FOLD.sub("", value)).casefold()
    if mask:
        text = _COUNT.sub("#", text)
    return " ".join(text.split())


def fingerprint(row, key_fields, mask_fields):
    """Tuple of normalized key cells, or None when every key cell is blank."""
    key = tuple(normalize(row.get(f, ""), f in mask_fields) for f in key_fields)
    return key if any(key) else None


def guard_cell(value):
    """The cell as written to CSV: a text cell that a spreadsheet would run as a formula gets one
    leading apostrophe. The test also catches apostrophes in front of a formula character, so
    unguard_cell can strip exactly one apostrophe and a cell that really starts with "'" survives."""
    if _GUARDED.match(value) and not _PLAIN_NUMBER.match(value):
        return "'" + value
    return value


def unguard_cell(value):
    """Exact inverse of guard_cell: strip the leading apostrophe only when guard_cell would have
    added it. A raw cell such as "'-3" (apostrophe, plain number) is no guard, so it stays."""
    rest = value[1:]
    return rest if value[:1] == "'" and _GUARDED.match(rest) and not _PLAIN_NUMBER.match(rest) else value


def is_oid_name(name):
    """True for a field name that carries an OID-style identity (objectid, fid, source_oid)."""
    return bool(_OID_NAME.match(name.strip().casefold()))


def mark_of(row, status_field, notes_field, default_status):
    """(status, notes) when a reviewer touched the row, else None."""
    status = row.get(status_field, "").strip()
    notes = row.get(notes_field, "").strip()
    if status.casefold() == default_status.casefold():
        status = ""
    if not status and not notes:
        return None
    return (status or default_status, notes)


def split_list(text):
    """Comma list to a list of stripped, non-empty names."""
    return [part.strip() for part in text.split(",") if part.strip()]


def validate_fields(key_fields, mask_fields, status_field, notes_field,
                    header_prior, header_current, allow_oid_key):
    """Refuse a request whose key cannot work. Raises UsageError."""
    if not key_fields:
        raise UsageError("--key names no field")
    if len(set(key_fields)) != len(key_fields):
        raise UsageError("--key names a field twice")
    if status_field == notes_field:
        raise UsageError("--status-field and --notes-field are the same field")
    for name in key_fields:
        if name in (status_field, notes_field):
            raise UsageError(
                "--key includes %s, which holds the marks. The fingerprint would "
                "change the moment a reviewer marked the row." % name)
        if is_oid_name(name) and not allow_oid_key:
            raise UsageError(
                "--key includes %s, an identity the next rebuild will not reproduce. "
                "That is the failure this tool exists to avoid. Pass --allow-oid-key "
                "only when the field is stable across your runs." % name)
        for label, header in (("prior", header_prior), ("current", header_current)):
            if name not in header:
                raise UsageError("key field %s is not a column of the %s file" % (name, label))
    for name in mask_fields:
        if name not in key_fields:
            raise UsageError("--mask names %s, which is not in --key" % name)
    if status_field not in header_prior:
        raise UsageError("status field %s is not a column of the prior file" % status_field)
    if notes_field not in header_prior:
        raise UsageError("notes field %s is not a column of the prior file" % notes_field)


def _mark_text(mark):
    status, notes = mark
    return "%s (%s)" % (status, notes) if notes else status


def _short(key):
    text = " | ".join(key)
    return text if len(text) <= 60 else text[:57] + "..."


def decide(prior, current, key_fields, mask_fields, status_field, notes_field, default_status):
    """Decide, for every current row, whether a prior mark is carried to it.

    Returns a dict: outcomes (one (name, mark-or-None) per current row, in order), counts,
    lost (human lines for each mark that did not carry), lost_marks, resolved (prior marks
    whose finding is gone), prior_marked, keyable (current rows with a usable key), matched
    (fingerprints present on both sides), marked_matched (those that hold a prior mark), shifted (carried marks whose masked number changed).
    """
    pgroups = {}
    prior_marked = 0
    lost = []
    lost_marks = 0
    for number, row in enumerate(prior, 1):
        mark = mark_of(row, status_field, notes_field, default_status)
        if mark is not None:
            prior_marked += 1
        key = fingerprint(row, key_fields, mask_fields)
        if key is None:
            if mark is not None:
                lost_marks += 1
                lost.append("prior row %d carries a mark but every key field is blank" % number)
            continue
        pgroups.setdefault(key, []).append((number, mark))

    cgroups = {}
    outcomes = [("unkeyable", None)] * len(current)
    keyable = 0
    for number, row in enumerate(current, 1):
        key = fingerprint(row, key_fields, mask_fields)
        if key is not None:
            keyable += 1
            cgroups.setdefault(key, []).append(number)

    matched = 0
    marked_matched = 0
    shifted = 0
    for key, numbers in cgroups.items():
        group = pgroups.get(key)
        if group is None:
            for number in numbers:
                outcomes[number - 1] = ("new", None)
            continue
        matched += 1
        marks = set(item[1] for item in group)
        marked = [item for item in group if item[1] is not None]
        marked_matched += 1 if marked else 0
        if len(marks) > 1:
            verdict = "conflict"
            lost.append("current row(s) %s: prior row(s) %s carry different marks for %s"
                        % (_numbers(numbers), _numbers([i[0] for i in group]), _short(key)))
        elif not marked:
            verdict = "unmarked"
        elif len(group) != len(numbers):
            verdict = "count-changed"
            lost.append("current row(s) %s: %s appears %d time(s) in the prior run and %d now"
                        % (_numbers(numbers), _short(key), len(group), len(numbers)))
        else:
            verdict = "carried"
        if verdict in ("conflict", "count-changed"):
            lost_marks += len(marked)
        # --mask treats a number as noise. Say when a carried mark crossed a changed number.
        moved = (sorted(fingerprint(prior[i[0] - 1], key_fields, []) for i in group)
                 != sorted(fingerprint(current[n - 1], key_fields, []) for n in numbers))
        for number in numbers:
            if verdict == "carried":
                own = mark_of(current[number - 1], status_field, notes_field, default_status)
                if own is None:
                    outcomes[number - 1] = ("carried", group[0][1])
                    shifted += 1 if moved else 0
                else:
                    outcomes[number - 1] = ("kept-current", None)
                    if own != group[0][1]:
                        lost_marks += 1
                        lost.append("current row %d already holds mark %s, so prior mark %s "
                                    "was not applied. If your validation tool writes its own "
                                    "status, pass --default-status."
                                    % (number, _mark_text(own), _mark_text(group[0][1])))
            else:
                outcomes[number - 1] = (verdict, None)

    # A prior mark whose finding vanished is either fixed or its count drifted. The count
    # lives in the LAST --key field (the message). If that field with its numbers masked
    # still equals a new finding, the count drifted: say so. A number in an earlier field
    # (a block, a parcel) names a different feature, so it is never read as a drift.
    drift = list(mask_fields) + [key_fields[-1]]
    loose_new = {}
    for key, numbers in cgroups.items():
        if key not in pgroups:
            loose = fingerprint(current[numbers[0] - 1], key_fields, drift)
            loose_new.setdefault(loose, []).extend(numbers)
    resolved = 0
    for key, group in pgroups.items():
        marked = [item for item in group if item[1] is not None]
        if key in cgroups or not marked:
            continue
        near = loose_new.get(fingerprint(prior[group[0][0] - 1], key_fields, drift))
        if near:
            lost_marks += len(marked)
            lost.append("prior row(s) %s: %s looks like current row(s) %s but a number differs "
                        "in %s. Add that field to --mask if the number is a count."
                        % (_numbers([i[0] for i in marked]), _short(key), _numbers(near),
                           key_fields[-1]))
        else:
            resolved += len(marked)
    counts = dict((name, 0) for name in OUTCOMES)
    for name, _ in outcomes:
        counts[name] += 1
    return {"outcomes": outcomes, "counts": counts, "lost": lost, "lost_marks": lost_marks,
            "resolved": resolved, "prior_marked": prior_marked, "keyable": keyable,
            "matched": matched, "marked_matched": marked_matched, "shifted": shifted}


def _numbers(values):
    return ",".join(str(v) for v in values)


def dead_run(result, n_current, allow_empty_current, allow_no_carry=False):
    """Why this run compared nothing, or None. A clean exit here would read as 'all carried'."""
    if result["prior_marked"] == 0:
        return None if allow_no_carry else (
            "the prior file holds no marked row in the status and notes columns, so there is "
            "nothing to carry. If the reviewer's marks sit in other columns, pass "
            "--status-field and --notes-field. Pass --allow-no-carry if nobody reviewed it.")
    if n_current == 0:
        return None if allow_empty_current else (
            "the current file has no rows but the prior file has %d marked row(s). "
            "A failed export looks the same. Pass --allow-empty-current if every "
            "finding was really fixed." % result["prior_marked"])
    if result["keyable"] == 0:
        return "no current row has a non-blank key, so nothing was compared"
    if result["matched"] == 0:
        return ("no current finding matches any prior finding on this key, so nothing was "
                "compared. The key fields or the --mask list probably drifted.")
    if result["marked_matched"] == 0 and not result["lost_marks"]:
        if result["counts"]["new"]:
            return ("no prior mark matches a current finding, no mark was reported lost, and %d "
                    "finding(s) are new, so a fix cannot be told from a renamed check or a "
                    "drifted key. Compare the two files by hand." % result["counts"]["new"])
        if not allow_no_carry:
            return ("every marked prior finding is gone from the current file, so a fix cannot "
                    "be told from a truncated export. Compare the row counts. Pass "
                    "--allow-no-carry if every marked finding was really fixed.")
    return None


def exit_code(result, accept_shifted, accept_resolved=False):
    """EXIT_LOST when a mark was lost, when a carried mark crossed a masked number that the
    caller has not accepted, or when a mark is called resolved and the caller has not accepted
    it. A mask cannot tell a moved count from a different finding, and a fixed finding looks
    the same as a truncated export, a renamed check or a drifted key."""
    if (result["lost_marks"] or (result["shifted"] and not accept_shifted)
            or (result["resolved"] and not accept_resolved)):
        return EXIT_LOST
    return EXIT_OK


def apply_marks(current, outcomes, status_field, notes_field, default_status):
    """Copies of the current rows with carried marks written and Status never blank."""
    rows = []
    for row, (name, mark) in zip(current, outcomes):
        new = dict(row)
        if name == "carried":
            new[status_field], new[notes_field] = mark
        elif not new.get(status_field, "").strip():
            new[status_field] = default_status
        new.setdefault(notes_field, "")
        rows.append(new)
    return rows


def build_report(result, n_prior, n_current, key_fields, mask_fields, max_lines=MAX_LINES,
                 accept_shifted=False, accept_resolved=False):
    """Report lines for a decide() result."""
    counts = result["counts"]
    lines = ["triage_carry_forward: prior %d rows (%d marked), current %d rows"
             % (n_prior, result["prior_marked"], n_current),
             "key: %s%s" % (", ".join(key_fields),
                            " (counts masked in: %s)" % ", ".join(mask_fields)
                            if mask_fields else "")]
    for name in OUTCOMES:
        lines.append("%-15s %d" % (name, counts[name]))
    lines.append("%-15s %d  (prior marks whose finding is gone)" % ("resolved", result["resolved"]))
    lines.append("%-15s %d" % ("lost marks", result["lost_marks"]))
    if result["shifted"]:
        lines.append("  NOTE  %d carried mark(s) sit on a finding whose masked number changed. "
                     "--mask treats a number as noise, so check that each is the same finding.%s"
                     % (result["shifted"], "" if accept_shifted
                        else " The run exits 1 until you pass --accept-shifted."))
    if result["resolved"] and not accept_resolved:
        lines.append("  NOTE  %d prior mark(s) have no matching finding. A fix looks the same as "
                     "a truncated export, a renamed check or a drifted key. Check that each "
                     "finding is really gone. The run exits 1 until you pass --accept-resolved."
                     % result["resolved"])
    if result["resolved"] > counts["carried"] + counts["kept-current"] and counts["new"]:
        lines.append("  WARNING  %d prior mark(s) have no matching finding while %d finding(s) "
                     "are new. A renamed check or a drifted key looks the same as a fix. "
                     "Compare them before you trust the file."
                     % (result["resolved"], counts["new"]))
    for text in result["lost"][:max_lines]:
        lines.append("  LOST  " + text)
    extra = len(result["lost"]) - max_lines
    if extra > 0:
        lines.append("  ... and %d more" % extra)
    return lines


# ----------------------------------------------------------------------------
# I/O
# ----------------------------------------------------------------------------

def read_rows(path):
    """(header, rows) of a UTF-8 CSV. Raises UsageError for a file that cannot be trusted."""
    try:
        with io.open(path, "r", newline="", encoding="utf-8-sig") as handle:
            reader = csv.reader(handle, strict=True)  # strict: a stray quote is an error, not a merged cell
            header = next(reader, None)
            if not header:
                raise UsageError("%s has no header row" % path)
            header = [unguard_cell(name) for name in header]
            if len(set(header)) != len(header):
                raise UsageError("%s repeats a column name, so a cell cannot be told apart" % path)
            rows = []
            for number, cells in enumerate(reader, 1):
                if not cells:
                    continue  # csv.reader yields [] for a blank line
                if len(cells) > len(header):
                    raise UsageError(
                        "%s data row %d has %d cells but the header has %d"
                        % (path, number, len(cells), len(header)))
                cells = [unguard_cell(cell) for cell in cells]
                cells = cells + [""] * (len(header) - len(cells))
                rows.append(dict(zip(header, cells)))
    except UsageError:
        raise
    except (OSError, ValueError, csv.Error) as exc:  # ValueError: not UTF-8, or a NUL in the path
        raise UsageError("cannot read %s: %s" % (path, exc))
    return header, rows


def write_rows(path, header, rows):
    """Create path (never overwrite) and write the rows. Raises OSError.
    Every text cell, the header included, goes through guard_cell."""
    # shortcut: a disk error part way leaves a partial file, remove it by hand and re-run; write to a temp name and rename if an unattended job ever consumes the file.
    with io.open(path, "x", newline="", encoding="utf-8") as handle:
        # Python 3.9 and 3.10 quote a field only for a character of the line terminator, so
        # "\n" alone leaves a bare CR unquoted and splits the record. Write each row with
        # "\r\n", which quotes CR and LF on every version, then end the line with "\n".
        line = io.StringIO()
        writer = csv.writer(line, lineterminator="\r\n")
        for cells in [header] + [[row.get(name, "") for name in header] for row in rows]:
            line.seek(0)
            line.truncate()
            writer.writerow([guard_cell(cell) for cell in cells])
            handle.write(line.getvalue()[:-2] + "\n")


def _same_file(a, b):
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def build_parser():
    ap = argparse.ArgumentParser(
        prog="triage_carry_forward.py", allow_abbrev=False,
        description="Carry reviewer marks forward by a content fingerprint. "
                    "Nothing is written without --apply.")
    ap.add_argument("--prior", help="previous findings CSV, with the reviewer marks")
    ap.add_argument("--current", help="new findings CSV, without marks")
    ap.add_argument("--key", help="comma list of columns that make up the fingerprint")
    ap.add_argument("--mask", default="",
                    help="comma list of --key columns whose numbers are ignored")
    ap.add_argument("--status-field", default="Status", help="default Status")
    ap.add_argument("--notes-field", default="Notes", help="default Notes")
    ap.add_argument("--default-status", default=DEFAULT_STATUS,
                    help="status of an unreviewed row, default %s" % DEFAULT_STATUS)
    ap.add_argument("--allow-oid-key", action="store_true",
                    help="permit an ObjectID-style column in --key")
    ap.add_argument("--accept-shifted", action="store_true",
                    help="exit 0 although a mark crossed a changed masked number (checked by hand)")
    ap.add_argument("--accept-resolved", action="store_true",
                    help="exit 0 although marked findings are gone (checked by hand). "
                         "--allow-empty-current and --allow-no-carry imply it")
    ap.add_argument("--allow-empty-current", action="store_true",
                    help="accept a current file with no rows when the prior file has marks")
    ap.add_argument("--allow-no-carry", action="store_true",
                    help="accept a run that carries no mark: the prior file holds no marks, or "
                         "every marked prior finding is gone")
    ap.add_argument("--out", help="new CSV to create; needs --apply, never overwrites")
    ap.add_argument("--apply", action="store_true",
                    help="write --out. Without it nothing is written.")
    ap.add_argument("--self-test", dest="self_test", action="store_true",
                    help="run the offline assertions and exit")
    return ap


def run(args):
    """Execute one parsed request. Returns an exit code; prints the report."""
    for flag in ("prior", "current", "key"):
        if not getattr(args, flag):
            raise UsageError("--%s is required" % flag)
    if args.apply and not args.out:
        raise UsageError("--apply needs --out")
    if args.out and not args.apply:
        raise UsageError("--out needs --apply, because nothing is written without it")
    if args.out and (_same_file(args.out, args.prior) or _same_file(args.out, args.current)):
        raise UsageError("--out must be a new file, not the prior or the current file")
    key_fields = split_list(args.key)
    mask_fields = split_list(args.mask)
    header_prior, prior = read_rows(args.prior)
    header_current, current = read_rows(args.current)
    validate_fields(key_fields, mask_fields, args.status_field, args.notes_field,
                    header_prior, header_current, args.allow_oid_key)
    result = decide(prior, current, key_fields, mask_fields,
                    args.status_field, args.notes_field, args.default_status)
    accept_resolved = args.accept_resolved or args.allow_empty_current or args.allow_no_carry
    for line in build_report(result, len(prior), len(current), key_fields, mask_fields,
                             accept_shifted=args.accept_shifted, accept_resolved=accept_resolved):
        print(line)
    reason = dead_run(result, len(current), args.allow_empty_current, args.allow_no_carry)
    if reason:
        print("NOTHING COMPARED: " + reason)
        return EXIT_NOTHING
    if args.apply:
        header = list(header_current)
        for name in (args.status_field, args.notes_field):
            if name not in header:
                header.append(name)
        rows = apply_marks(current, result["outcomes"], args.status_field,
                           args.notes_field, args.default_status)
        try:
            write_rows(args.out, header, rows)
        except FileExistsError:
            print("REFUSED: %s already exists. Choose a new name." % args.out)
            return EXIT_WRITE
        except OSError as exc:
            print("REFUSED: cannot write %s: %s" % (args.out, exc))
            return EXIT_WRITE
        print("wrote %d rows to %s" % (len(rows), args.out))
    else:
        print("dry run: nothing written. Add --out FILE --apply to write the marked copy.")
    return exit_code(result, args.accept_shifted, accept_resolved)


def main(argv=None):
    # A character the console code page cannot encode must not turn a report into a crash.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    ap = build_parser()
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        return run(args)
    except UsageError as exc:
        print("usage error: %s" % exc, file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:  # last resort: a crash must not share exit 1 with "marks lost"
        print("internal error: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return EXIT_CRASH


# ----------------------------------------------------------------------------
# Self-test. Synthetic fixtures only: no real data, no arcpy, no network.
# ----------------------------------------------------------------------------

HEADER = ["OBJECTID", "check_id", "feature", "message", "Status", "Notes"]


def _row(oid, check, feature, message, status="OPEN", notes=""):
    return {"OBJECTID": str(oid), "check_id": check, "feature": feature,
            "message": message, "Status": status, "Notes": notes}


def _csv_text(rows, header=HEADER):
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=header, lineterminator="\r\n")
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


class Harness(object):
    """check()/raises() counters and the footer, kept apart so the harness can be tested."""

    def __init__(self):
        self.passed = 0
        self.failed = []

    def check(self, cond, label):
        if cond:
            self.passed += 1
            print("PASS  %s" % label)
        else:
            self.failed.append(label)
            print("FAIL  %s" % label)

    def raises(self, fn, label):
        try:
            fn()
        except ValueError:
            self.check(True, label)
        except Exception as exc:
            self.check(False, "%s (wrong exception %r)" % (label, exc))
        else:
            self.check(False, "%s (no error raised)" % label)

    def footer(self):
        total = self.passed + len(self.failed)
        print("-" * 68)
        print("%d assertions, %d failed" % (total, len(self.failed)))
        for label in self.failed:
            print("  FAILED: %s" % label)
        return 1 if self.failed else 0


def self_test():
    """Assertions over the decision core and the CLI. Returns an exit code."""
    h = Harness()
    check, raises = h.check, h.raises

    def cli(argv):
        """Run main() in process. Returns (code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = main(argv)
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    print("triage_carry_forward self-test: no arcpy, no database, no network")
    print("-" * 68)

    key = ["check_id", "feature", "message"]
    mask = ["message"]

    # ---- normalize and fingerprint
    check(normalize("  Two   Words ", False) == "two words", "normalize folds case and whitespace")
    check(normalize("'=x", False) == normalize("''=x", False) == normalize("=x", False) == "=x",
          "apostrophes in front of a formula character do not change a key cell  <-- pinned defect")
    check(normalize(u"'\uff1dx", False) == "=x" and normalize("'-5", False) == "-5",
          "the fold also covers a full-width formula character and a signed number")
    check(normalize("'abc", False) == "'abc" and normalize("x'=y", False) == "x'=y" and normalize("'", False) == "'",
          "an apostrophe that is not in front of a formula character is kept")
    check(normalize("12,345 addresses", True) == "# addresses", "mask hides a count with a thousands separator")
    check(normalize("12,345 addresses", False) == "12,345 addresses", "no mask keeps the count")
    check(normalize("1.5 and 2_000", True) == "# and #", "mask hides a decimal and an underscore count")
    check(normalize("\uff11\uff14 items", True) == "# items", "NFKC folds full-width digits before masking")
    check(normalize("Stra\u00dfe", False) == "strasse", "casefold, not lower: sharp s folds to ss")
    check(normalize("\uff21\uff24\uff24\uff32-01", False) == "addr-01", "NFKC folds full-width letters, which casefold alone keeps")
    check(fingerprint({"a": "X", "b": " y "}, ["a", "b"], []) == ("x", "y"), "fingerprint is the tuple of normalized cells")
    check(fingerprint({"a": " ", "b": ""}, ["a", "b"], []) is None, "all-blank key is None")
    check(fingerprint({"a": "x"}, ["a", "b"], []) == ("x", ""), "a missing column reads as blank")
    check(fingerprint({"m": "5 of 9"}, ["m"], ["m"]) == ("# of #",), "fingerprint masks only the named fields")
    check(fingerprint({"m": "5", "n": "6"}, ["m", "n"], ["m"]) == ("#", "6"), "an unmasked field keeps its number")

    # ---- OID-style names
    for name in ("OBJECTID", "oid", "FID", "source_oid", "SourceOID", "rowid", "OGC_FID", "src_objectid",
                 "src_rowid", "srcoid"):
        check(is_oid_name(name), "%s is an OID-style name" % name)
    for name in ("OBJECTID_1", "OBJECTID_12", "FID_1", "FID_parcels", "OBJECT_ID", "OBJ_ID", "OID_1",
                 "parcels_fid_3"):
        check(is_oid_name(name), "%s, a join or export spelling, is an OID-style name  <-- pinned defect" % name)
    for name in ("segment_id", "check_id", "avoid", "GlobalID", "feature", "void", "avoid_1", "fiduciary"):
        check(not is_oid_name(name), "%s is not an OID-style name" % name)

    # ---- marks
    check(mark_of(_row(1, "c", "f", "m"), "Status", "Notes", "OPEN") is None, "an OPEN row with no notes is unmarked")
    check(mark_of(_row(1, "c", "f", "m", "open"), "Status", "Notes", "OPEN") is None, "OPEN matches case-blind")
    check(mark_of(_row(1, "c", "f", "m", "", ""), "Status", "Notes", "OPEN") is None, "a blank status with no notes is unmarked")
    check(mark_of(_row(1, "c", "f", "m", "FALSE_POSITIVE"), "Status", "Notes", "OPEN") == ("FALSE_POSITIVE", ""), "a status change is a mark")
    check(mark_of(_row(1, "c", "f", "m", "OPEN", " see ticket "), "Status", "Notes", "OPEN") == ("OPEN", "see ticket"), "notes alone are a mark and are stripped")
    check(mark_of(_row(1, "c", "f", "m", "OPEN", "\tnote"), "Status", "Notes", "OPEN") == ("OPEN", "note"),
          "a Notes cell that starts with a tab is carried without the tab")
    check(mark_of({}, "Status", "Notes", "OPEN") is None, "a row without the columns is unmarked")
    check(mark_of(_row(1, "c", "f", "m", "   ", "  "), "Status", "Notes", "OPEN") is None, "a whitespace-only status is not a mark")

    check(split_list(" a, b ,,c ") == ["a", "b", "c"], "split_list strips and drops blanks")

    # ---- the story: a rebuild renumbers every row and changes every count
    prior = [
        _row(1, "ADDR-01", "block 7", "12,345 addresses disagree with the zone"),
        _row(2, "ADDR-02", "block 7", "3 duplicate numbers", "FALSE_POSITIVE", "known, vendor data"),
        _row(3, "GEOM-01", "tract 4", "8 gaps over 5 m", "DEFERRED", "next quarter"),
        _row(4, "ADDR-01", "block 9", "20 addresses disagree with the zone", "FIXED", "corrected"),
        _row(5, "GEOM-02", "tract 4", "overlap", "OPEN"),
        _row(6, "ADDR-03", "block 2", "6 unnamed streets", "FALSE_POSITIVE", "private road"),
    ]
    current = [   # new order, new OIDs, changed counts, one finding fixed, one new
        _row(1, "GEOM-02", "tract 4", "overlap"),
        _row(2, "ADDR-01", "block 9", "19 addresses disagree with the zone"),
        _row(3, "ADDR-02", "block 7", "4 duplicate numbers"),
        _row(4, "ADDR-01", "block 7", "13,900 addresses disagree with the zone"),
        _row(5, "GEOM-01", "tract 4", "7 gaps over 5 m"),
        _row(6, "NEW-01", "block 1", "something new"),
    ]
    r = decide(prior, current, key, mask, "Status", "Notes", "OPEN")
    names = [o[0] for o in r["outcomes"]]
    check(names == ["unmarked", "carried", "carried", "unmarked", "carried", "new"], "the rebuild: each mark follows its finding")
    check(r["outcomes"][1][1] == ("FIXED", "corrected"), "the FIXED mark reached the right finding after the count changed")
    check(r["outcomes"][2][1] == ("FALSE_POSITIVE", "known, vendor data"), "the FALSE_POSITIVE note survived a count change")
    check(r["outcomes"][4][1] == ("DEFERRED", "next quarter"), "the DEFERRED note survived a count change")
    check(r["resolved"] == 1 and r["lost_marks"] == 0, "the mark on the fixed finding is resolved, not lost")
    check(r["counts"]["carried"] == 3 and r["counts"]["new"] == 1 and r["counts"]["unmarked"] == 2, "story counts add up")
    check(sum(r["counts"].values()) == len(current), "every current row gets exactly one outcome")
    # the naive way: copy the mark to the row with the same OBJECTID
    naive = dict((p["OBJECTID"], p["Status"]) for p in prior)
    wrong = [c["feature"] for c in current if naive.get(c["OBJECTID"], "OPEN") != "OPEN"]
    check(len(wrong) >= 3 and r["outcomes"][3][0] != "carried",
          "copying by OBJECTID marks unrelated findings and the fingerprint does not  <-- pinned defect")
    check(naive["4"] == "FIXED" and current[3]["OBJECTID"] == "4" and r["outcomes"][3][1] is None,
          "the OBJECTID 4 mark belongs to a different finding after the rebuild  <-- pinned defect")

    # ---- counts: without the mask the mark is dropped, with it the mark carries
    r2 = decide(prior, current, key, [], "Status", "Notes", "OPEN")
    check(r2["counts"]["carried"] == 0, "without --mask a changed count drops every mark  <-- pinned defect")
    check(r2["lost_marks"] == 3 and r2["resolved"] == 1 and len(r2["lost"]) == 3,
          "without --mask the drifted marks are reported lost, not quietly resolved  <-- pinned defect")
    check("looks like current row(s) 3 but a number differs" in r2["lost"][0], "the drift line names the current row and the fix")
    r3 = decide([_row(1, "C", "f", "m 5"), _row(2, "C", "f", "m 6", "FIXED", "x")], [_row(1, "C", "f", "m 7"), _row(2, "C", "f", "m 8")],
                key, [], "Status", "Notes", "OPEN")
    check(r3["lost_marks"] == 1 and "current row(s) 1,2" in r3["lost"][0], "one drifted mark can match several new rows")
    check(r3["resolved"] == 0, "an unmarked vanished finding is not counted as a resolved mark")
    check(r2["counts"]["new"] == 5, "without --mask the changed findings read as new")
    check("a number differs in message." in r2["lost"][0], "the drift line names the field to mask")

    # ---- a number in an earlier key field names another feature, never a drifted count
    pf = [_row(1, "ADDR-01", "block 7", "5 addresses disagree", "FIXED", "done")]
    cf = [_row(1, "ADDR-01", "block 9", "5 addresses disagree")]
    for use_mask in (mask, []):
        r = decide(pf, cf, key, use_mask, "Status", "Notes", "OPEN")
        check(r["resolved"] == 1 and r["lost_marks"] == 0 and r["lost"] == [],
              "a fixed finding is resolved when a new one differs only in a feature number (mask %s)  <-- pinned defect" % bool(use_mask))
    pi = [_row(1, "ADDR-01", "1001", "dup", "FALSE_POSITIVE", "known"), _row(2, "ADDR-02", "1002", "gap")]
    ci = [_row(1, "ADDR-01", "2002", "dup"), _row(2, "ADDR-02", "1002", "gap")]
    r = decide(pi, ci, key, [], "Status", "Notes", "OPEN")
    check(r["resolved"] == 1 and r["lost_marks"] == 0 and r["counts"]["new"] == 1,
          "a changed numeric feature id is one fixed finding and one new finding  <-- pinned defect")
    pe = [_row(1, "C", "f", "5 gaps", "FIXED", "x"), _row(2, "C", "f", "6 gaps")]
    r = decide(pe, [_row(1, "C", "f", "6 gaps")], key, [], "Status", "Notes", "OPEN")
    check(r["resolved"] == 1 and r["lost_marks"] == 0, "a drift look-alike that already matches its own prior twin is not a drift")
    pt = [_row(1, "C", "f", "m", "FIXED", "x"), _row(2, "C", "f", "m", "FIXED", "x")]
    r = decide(pt, [_row(1, "Z", "g", "n")], key, [], "Status", "Notes", "OPEN")
    check(r["resolved"] == 2 and r["lost_marks"] == 0, "two marked twins whose finding is gone are two resolved marks")
    ptd = [_row(1, "C", "f", "m 5", "FIXED", "x"), _row(2, "C", "f", "m 5", "FIXED", "x")]
    r = decide(ptd, [_row(1, "C", "f", "m 6"), _row(2, "C", "f", "m 6")], key, [], "Status", "Notes", "OPEN")
    check(r["lost_marks"] == 2 and len(r["lost"]) == 1, "two marked twins whose count drifted are two lost marks")

    # ---- a mask is a choice: say when a carried mark crossed a changed number
    pc = [_row(1, "PARCEL-01", "block 7", "Parcel 1200 has no owner", "FALSE_POSITIVE", "known")]
    cc = [_row(1, "PARCEL-01", "block 7", "Parcel 1300 has no owner")]
    r = decide(pc, cc, key, mask, "Status", "Notes", "OPEN")
    check(r["outcomes"][0][0] == "carried" and r["shifted"] == 1, "a mask carries a mark across a changed number and counts it")
    check(any(l.startswith("  NOTE") and "1 carried mark(s)" in l for l in build_report(r, 1, 1, key, mask)),
          "the report names the carried marks whose number changed  <-- pinned defect")
    r = decide(pc, [_row(1, "PARCEL-01", "block 7", "Parcel 1200 has no owner")], key, mask, "Status", "Notes", "OPEN")
    check(r["shifted"] == 0 and not any("NOTE" in l for l in build_report(r, 1, 1, key, mask)), "an unchanged number raises no note")
    r = decide(prior, current, key, mask, "Status", "Notes", "OPEN")
    check(r["shifted"] == 3, "the story run crosses three changed counts")
    ra = dict(r, resolved=0)
    check(exit_code(ra, False) == EXIT_LOST and exit_code(ra, True) == EXIT_OK,
          "a shifted carry exits 1, and exits 0 once --accept-shifted is passed  <-- pinned defect")
    check(exit_code(dict(ra, shifted=0), False) == EXIT_OK and exit_code(dict(ra, lost_marks=2, shifted=0), True) == EXIT_LOST,
          "no shifted carry exits 0, and a lost mark exits 1 even with --accept-shifted")
    check(not any("exits 1 until" in l for l in build_report(ra, 6, 6, key, mask, accept_shifted=True)),
          "the NOTE drops the exit 1 sentence once --accept-shifted is passed")
    r1 = decide(pc, cc, key, mask, "Status", "Notes", "OPEN")
    check(r1["marked_matched"] == 1 and dead_run(r1, 1, False) is None,
          "a single prior mark that matches is not a dead run, so the shifted carry stays an exit 1 decision")

    # ---- the drift check reads the last --key field only
    order = ["check_id", "message", "feature"]
    r = decide([_row(1, "A-1", "block 7", "5 gaps", "FIXED", "x")], [_row(1, "A-1", "block 7", "6 gaps")],
               order, [], "Status", "Notes", "OPEN")
    check(r["lost_marks"] == 0 and r["resolved"] == 1,
          "a changed count in a key field that is not last is not seen as drift, so the mark resolves")

    # ---- a partial key drift looks like a fix, so the report warns
    pw = [_row(i, "CHK-%d" % i, "f", "m", "FIXED", "x") for i in range(1, 6)]
    cw = [_row(1, "CHK-1", "f", "m")] + [_row(i, "CHK_%d" % i, "f", "m") for i in range(2, 6)]
    r = decide(pw, cw, key, [], "Status", "Notes", "OPEN")
    check(r["resolved"] == 4 and r["counts"]["carried"] == 1 and r["lost_marks"] == 0, "a partial rename resolves four marks and carries one")
    warn = [l for l in build_report(r, 5, 5, key, []) if "WARNING" in l]
    check(len(warn) == 1 and "4 prior mark(s)" in warn[0] and "4 finding(s) are new" in warn[0],
          "the report warns when more marks resolve than carry while findings are new  <-- pinned defect")
    pk = [_row(1, "A", "f", "m", "FIXED", "x"), _row(2, "B", "f", "m", "FIXED", "x")]
    ck = [_row(1, "A", "f", "m", "FIXED", "x"), _row(2, "C", "f", "m")]
    r = decide(pk, ck, key, [], "Status", "Notes", "OPEN")
    check(r["counts"]["kept-current"] == 1 and r["resolved"] == 1 and r["counts"]["new"] == 1 and r["lost_marks"] == 0,
          "one kept mark, one resolved mark and one new finding")
    check(not any("WARNING" in l for l in build_report(r, 2, 2, key, [])), "a kept mark counts as matched, so one resolved mark raises no warning")
    r = decide(prior, current, key, mask, "Status", "Notes", "OPEN")
    check(not any("WARNING" in l for l in build_report(r, 6, 6, key, mask)), "the story run raises no warning")

    # ---- the drift check covers the last key field and every masked field
    order = ["check_id", "message", "feature"]
    r = decide([_row(1, "A-1", "5 gaps", "block 7", "FIXED", "x")], [_row(1, "A-1", "6 gaps", "block 8")],
               order, ["message"], "Status", "Notes", "OPEN")
    check(r["lost_marks"] == 1 and "differs in feature" in r["lost"][0], "the drift check masks the last key field and the --mask fields together")
    r = decide(prior, [], key, mask, "Status", "Notes", "OPEN")
    check(not any("WARNING" in l for l in build_report(r, 6, 0, key, mask)), "an empty current file raises no warning, because nothing is new")

    # ---- ambiguity is refused, not guessed
    p = [_row(1, "C", "f", "m", "FALSE_POSITIVE", "a"), _row(2, "C", "f", "m", "FIXED", "b")]
    c = [_row(9, "C", "f", "m")]
    r = decide(p, c, key, [], "Status", "Notes", "OPEN")
    check(r["outcomes"][0] == ("conflict", None) and r["lost_marks"] == 2, "two different marks on one fingerprint are refused and both counted lost")
    check("carry different marks" in r["lost"][0], "the conflict line says why")
    p = [_row(1, "C", "f", "m", "FALSE_POSITIVE", "a"), _row(2, "C", "f", "m")]
    r = decide(p, c, key, [], "Status", "Notes", "OPEN")
    check(r["outcomes"][0][0] == "conflict" and r["lost_marks"] == 1, "a marked and an unmarked twin conflict")
    p = [_row(1, "C", "f", "m", "FALSE_POSITIVE", "a"), _row(2, "C", "f", "m", "FALSE_POSITIVE", "a")]
    c2 = [_row(8, "C", "f", "m"), _row(9, "C", "f", "m")]
    r = decide(p, c2, key, [], "Status", "Notes", "OPEN")
    check([o[0] for o in r["outcomes"]] == ["carried", "carried"], "identical twins with the same mark both carry")
    r = decide(p, c, key, [], "Status", "Notes", "OPEN")
    check(r["outcomes"][0][0] == "count-changed" and r["lost_marks"] == 2, "two prior twins and one now is refused")
    check("2 time(s) in the prior run and 1 now" in r["lost"][0], "the count-changed line gives both counts")
    p1 = [_row(1, "C", "f", "m", "FALSE_POSITIVE", "a")]
    r = decide(p1, c2, key, [], "Status", "Notes", "OPEN")
    check(r["outcomes"][0][0] == "count-changed" and r["outcomes"][1][0] == "count-changed" and r["lost_marks"] == 1,
          "one marked prior and two now is refused, because the mark cannot pick a twin")
    pu = [_row(1, "C", "f", "m"), _row(2, "C", "f", "m")]
    r = decide(pu, c, key, [], "Status", "Notes", "OPEN")
    check(r["outcomes"][0][0] == "unmarked" and r["lost_marks"] == 0, "an unmarked group that changes size loses nothing")

    # ---- a reviewer who already marked the new file is not overwritten
    cm = [_row(9, "C", "f", "m", "FIXED", "fresh")]
    r = decide(p1, cm, key, [], "Status", "Notes", "OPEN")
    check(r["outcomes"][0] == ("kept-current", None), "a mark already on the new row wins")
    check(r["lost_marks"] == 1 and "already holds mark FIXED (fresh)" in r["lost"][0] and "prior mark FALSE_POSITIVE (a)" in r["lost"][0],
          "a different mark on the new row counts the prior mark as lost, not silently dropped  <-- pinned defect")
    check("--default-status" in r["lost"][0], "the kept-current line points at --default-status")
    out_rows = apply_marks(cm, r["outcomes"], "Status", "Notes", "OPEN")
    check(out_rows[0]["Status"] == "FIXED" and out_rows[0]["Notes"] == "fresh", "apply_marks leaves a kept-current row alone")
    same = decide(p1, [_row(9, "C", "f", "m", "FALSE_POSITIVE", "a")], key, [], "Status", "Notes", "OPEN")
    check(same["outcomes"][0][0] == "kept-current" and same["lost_marks"] == 0, "the same mark already on the new row loses nothing")
    own_status = decide(p1, [_row(9, "C", "f", "m", "NEW")], key, [], "Status", "Notes", "OPEN")
    check(own_status["lost_marks"] == 1 and own_status["counts"]["kept-current"] == 1,
          "a tool that writes its own Status NEW hides the reviewer mark, so it is lost, not clean  <-- pinned defect")
    check(decide(p1, [_row(9, "C", "f", "m", "NEW")], key, [], "Status", "Notes", "NEW")["outcomes"][0][0] == "carried",
          "with --default-status NEW the same file carries the mark")
    notes_pre = decide(p1, [_row(9, "C", "f", "m", "OPEN", "auto: see layer")], key, [], "Status", "Notes", "OPEN")
    check(notes_pre["lost_marks"] == 1, "notes a tool pre-fills also hide the reviewer mark, so it is lost  <-- pinned defect")

    # ---- blank keys
    pb = [_row(1, "", "", "", "FALSE_POSITIVE", "x")]
    cb = [_row(1, "", "", "")]
    r = decide(pb, cb, key, [], "Status", "Notes", "OPEN")
    check(r["outcomes"][0] == ("unkeyable", None) and r["lost_marks"] == 1 and r["keyable"] == 0, "a marked prior row with a blank key is lost and said so")
    check("every key field is blank" in r["lost"][0], "the blank-key line says why")
    r = decide([_row(1, "", "", "")], cb, key, [], "Status", "Notes", "OPEN")
    check(r["lost_marks"] == 0 and r["lost"] == [], "an unmarked prior row with a blank key loses nothing")

    # ---- a key that compares nothing is not a clean run
    r = decide(prior, [], key, mask, "Status", "Notes", "OPEN")
    check(dead_run(r, 0, False) is not None, "an empty current file with prior marks is refused  <-- pinned defect")
    check(dead_run(r, 0, True) is None, "--allow-empty-current accepts it")
    r = decide([_row(1, "C", "f", "m")], [], key, [], "Status", "Notes", "OPEN")
    check("no marked row" in dead_run(r, 0, False) and "--status-field" in dead_run(r, 0, True)
          and dead_run(r, 0, False, True) is None,
          "a prior file with no marks is refused unless --allow-no-carry is passed, whatever the current file holds  <-- pinned defect")
    r = decide(pb, cb, key, [], "Status", "Notes", "OPEN")
    check("non-blank key" in dead_run(r, 1, False), "a current file with only blank keys is refused")
    drift = [_row(1, "OTHER", "x", "y")]
    r = decide(prior, drift, key, mask, "Status", "Notes", "OPEN")
    check("nothing was compared" in dead_run(r, 1, False), "marks present and zero matches is refused  <-- pinned defect")
    r = decide(prior, current, key, mask, "Status", "Notes", "OPEN")
    check(dead_run(r, len(current), False) is None, "the story run is not a dead run")
    ps = [_row(1, "ADDR-01", "f", "m", "FALSE_POSITIVE", "x"), _row(2, "GEOM-01", "f", "m", "FALSE_POSITIVE", "y"),
          _row(3, "GEOM-02", "f", "m")]
    cs = [_row(1, "ADDR-1", "f", "m"), _row(2, "GEOM-1", "f", "m"), _row(3, "GEOM-02", "f", "m")]
    r = decide(ps, cs, key, [], "Status", "Notes", "OPEN")
    check(r["matched"] == 1 and r["marked_matched"] == 0 and r["resolved"] == 2 and r["lost_marks"] == 0,
          "an unmarked survivor matches, but no mark does: both marks resolve")
    check("renamed check" in dead_run(r, 3, False),
          "marks resolved, findings new and one unmarked survivor is refused like the all-renamed run  <-- pinned defect")
    r = decide(ps, [_row(3, "GEOM-02", "f", "m")], key, [], "Status", "Notes", "OPEN")
    check("truncated export" in dead_run(r, 1, False) and dead_run(r, 1, False, True) is None,
          "every mark resolved, no new finding, is refused like a truncated export unless --allow-no-carry is passed  <-- pinned defect")
    r = decide(ps, [_row(1, "ADDR-01", "f", "m"), _row(3, "GEOM-02", "f", "m")], key, [], "Status", "Notes", "OPEN")
    check(r["marked_matched"] == 1 and dead_run(r, 2, False) is None,
          "one marked finding still matching keeps a partial fix a clean run")
    r = decide(prior, current, key, [], "Status", "Notes", "OPEN")
    check(r["marked_matched"] == 0 and r["lost_marks"] == 3 and dead_run(r, len(current), False) is None,
          "a run that reports lost marks keeps exit 1 instead of the refusal")

    # ---- apply_marks
    cur_no_status = [{"check_id": "C", "feature": "f", "message": "m"}]
    r = decide(p1, cur_no_status, key, [], "Status", "Notes", "OPEN")
    out_rows = apply_marks(cur_no_status, r["outcomes"], "Status", "Notes", "OPEN")
    check(out_rows[0]["Status"] == "FALSE_POSITIVE" and out_rows[0]["Notes"] == "a", "apply_marks adds the columns a current file lacks")
    r = decide(prior, current, key, mask, "Status", "Notes", "OPEN")
    out_rows = apply_marks(current, r["outcomes"], "Status", "Notes", "OPEN")
    check(out_rows[5]["Status"] == "OPEN" and out_rows[5]["Notes"] == "", "a new finding is written OPEN with empty notes")
    check(current[1]["Status"] == "OPEN", "apply_marks does not mutate its input")
    blank_status = [_row(1, "NEW", "f", "m", "")]
    out_rows = apply_marks(blank_status, [("new", None)], "Status", "Notes", "OPEN")
    check(out_rows[0]["Status"] == "OPEN", "a blank status is written as the default status")
    out_rows = apply_marks([_row(1, "NEW", "f", "m", "   ")], [("new", None)], "Status", "Notes", "OPEN")
    check(out_rows[0]["Status"] == "OPEN", "a whitespace-only status is written as the default status")

    # ---- the report
    lines = build_report(r, 6, 6, key, mask)
    check(lines[0] == "triage_carry_forward: prior 6 rows (4 marked), current 6 rows", "report header counts rows and marks")
    check(lines[1] == "key: check_id, feature, message (counts masked in: message)", "report names the key and the mask")
    check("key: check_id" in build_report(r, 6, 6, key, [])[1] and "masked" not in build_report(r, 6, 6, key, [])[1], "report omits the mask clause when there is none")
    check(any(l.startswith("carried") and l.endswith(" 3") for l in lines), "report counts carried marks")
    many = {"outcomes": [], "counts": dict((n, 0) for n in OUTCOMES), "lost": ["l%d" % i for i in range(25)],
            "lost_marks": 25, "resolved": 0, "prior_marked": 25, "keyable": 0, "matched": 0, "shifted": 0}
    lines = build_report(many, 25, 0, key, [])
    check(sum(1 for l in lines if l.startswith("  LOST")) == 20 and lines[-1] == "  ... and 5 more", "report caps the lost list at 20 and counts the rest")
    check(len(_short(("x" * 100,))) == 60, "long keys are shortened for the report")
    check(_short(("x" * 60,)) == "x" * 60, "a key of exactly 60 characters is not shortened")
    many["lost"] = ["l%d" % i for i in range(20)]
    check(not any("more" in l for l in build_report(many, 25, 0, key, [])), "exactly 20 lost lines print no 'and 0 more' line")

    # ---- field validation
    hp = ["OBJECTID", "check_id", "Status", "Notes"]
    ok = (["check_id"], [], "Status", "Notes", hp, hp, False)
    validate_fields(*ok)
    check(True, "a valid request passes validation")
    raises(lambda: validate_fields([], [], "Status", "Notes", hp, hp, False), "an empty --key is refused")
    raises(lambda: validate_fields(["check_id", "check_id"], [], "Status", "Notes", hp, hp, False), "a repeated key field is refused")
    raises(lambda: validate_fields(["check_id"], [], "Status", "Status", hp, hp, False), "one field for status and notes is refused")
    raises(lambda: validate_fields(["Status"], [], "Status", "Notes", hp, hp, False), "a key that includes the Status column is refused")
    raises(lambda: validate_fields(["Notes"], [], "Status", "Notes", hp, hp, False), "a key that includes the Notes column is refused")
    raises(lambda: validate_fields(["OBJECTID"], [], "Status", "Notes", hp, hp, False), "an OBJECTID key is refused  <-- pinned defect")
    validate_fields(["OBJECTID"], [], "Status", "Notes", hp, hp, True)
    check(True, "--allow-oid-key permits an OBJECTID key")
    raises(lambda: validate_fields(["nope"], [], "Status", "Notes", hp, hp, False), "a key field missing from both files is refused")
    raises(lambda: validate_fields(["check_id"], [], "Status", "Notes", hp, ["Status"], False), "a key field missing from the current file is refused")
    raises(lambda: validate_fields(["check_id"], [], "Status", "Notes", ["Status", "Notes"], hp, False), "a key field missing from the prior file is refused")
    raises(lambda: validate_fields(["check_id"], ["other"], "Status", "Notes", hp, hp, False), "a mask field outside the key is refused")
    raises(lambda: validate_fields(["check_id"], [], "State", "Notes", hp, hp, False), "a status column missing from the prior file is refused")
    raises(lambda: validate_fields(["check_id"], [], "Status", "Memo", hp, hp, False), "a notes column missing from the prior file is refused")

    # ---- file reading and the CLI, in a scratch directory
    with tempfile.TemporaryDirectory() as tmp:
        def path(name):
            return os.path.join(tmp, name)

        def put(name, text, mode="w", encoding="utf-8"):
            with io.open(path(name), mode, newline=None if "b" in mode else "", encoding=encoding) as handle:
                handle.write(text)
            return path(name)

        header, rows = read_rows(put("bom.csv", u"\ufeffa,b\n1,2\n3\n"))
        check(header == ["a", "b"], "a UTF-8 BOM is not part of the first column name")
        check(rows == [{"a": "1", "b": "2"}, {"a": "3", "b": ""}], "a short row reads its missing cells as blank")
        raises(lambda: read_rows(put("long.csv", "a,b\n1,2,3\n")), "a row with extra cells is refused")
        raises(lambda: read_rows(put("trail.csv", "a,b\n1,2,\n")), "a data row with a trailing comma is refused")
        raises(lambda: read_rows(put("blankhdr.csv", "a,,\n1,2,3\n")), "two blank header cells are refused as a repeated column name")
        put("ascii1252.csv", b"a,b\nx,y\n", mode="wb", encoding=None)
        check(read_rows(path("ascii1252.csv"))[1] == [{"a": "x", "b": "y"}],
              "an ASCII-only file is read whatever code page wrote it")
        raises(lambda: read_rows(put("dup.csv", "a,a\n1,2\n")), "a repeated column name is refused")
        raises(lambda: read_rows(put("empty.csv", "")), "an empty file is refused")
        raises(lambda: read_rows(path("missing.csv")), "a missing file is refused")
        put("bad.csv", b"a,b\n\xff\xfe,2\n", mode="wb", encoding=None)
        check(os.path.exists(path("bad.csv")), "the non-UTF-8 fixture file exists  <-- pinned defect")
        bad_message = ""
        try:
            read_rows(path("bad.csv"))
        except UsageError as exc:
            bad_message = str(exc)
        check("cannot read" in bad_message, "a file that is not UTF-8 is refused as cannot read")
        put("wide.csv", "a,b\n" + "x" * 131073 + ",1\n")
        raises(lambda: read_rows(path("wide.csv")), "a cell over the csv field limit of 131072 characters is refused, not skipped")
        check(len(read_rows(put("edge.csv", "a,b\n" + "x" * 131072 + ",1\n"))[1][0]["a"]) == 131072,
              "a cell of exactly 131072 characters is read")

        pri = put("prior.csv", _csv_text(prior))
        cur = put("current.csv", _csv_text(current))
        base = ["--prior", pri, "--current", cur, "--key", "check_id,feature,message", "--mask", "message",
                "--accept-resolved", "--accept-shifted"]

        before = sorted(os.listdir(tmp))
        code, out, err = cli(base[:-1])
        check(code == 1 and "carried         3" in out and "exits 1 until you pass --accept-shifted" in out,
              "a mark carried across a changed masked number exits 1 until --accept-shifted is passed  <-- pinned defect")
        code, out, err = cli(base[:-2] + ["--accept-shifted"])
        check(code == 1 and "resolved        1" in out and "exits 1 until you pass --accept-resolved" in out,
              "a marked finding that is gone exits 1 until --accept-resolved is passed  <-- pinned defect")
        code, out, err = cli(base)
        check(code == 0 and "exits 1 until" not in out, "a clean dry run exits 0")
        check(sorted(os.listdir(tmp)) == before, "a dry run writes no file at all")
        check("dry run: nothing written" in out, "the dry run says nothing was written")
        check("carried         3" in out and "resolved" in out, "the dry run prints the counts")

        code, out, err = cli(["--prior", pri, "--current", cur, "--key", "check_id,feature,message"])
        check(code == 1 and "a number differs" in out and "Add that field to --mask" in out,
              "the same run without --mask exits 1 and tells the user to mask the count  <-- pinned defect")

        target = path("marked.csv")
        code, out, err = cli(base + ["--out", target])
        check(code == 2 and not os.path.exists(target), "--out without --apply is refused and writes nothing")
        code, out, err = cli(base + ["--apply"])
        check(code == 2 and "--apply needs --out" in err, "--apply without --out is refused")
        code, out, err = cli(base + ["--out", target, "--apply"])
        check(code == 0 and os.path.exists(target), "--apply --out writes the marked copy")
        header, written = read_rows(target)
        check(header == HEADER and len(written) == 6, "the output keeps the current columns and rows")
        check([w["Status"] for w in written] == ["OPEN", "FIXED", "FALSE_POSITIVE", "OPEN", "DEFERRED", "OPEN"],
              "the output Status column follows the fingerprint, not the row number")
        check(written[2]["Notes"] == "known, vendor data", "the output Notes column follows the fingerprint")
        check([w["OBJECTID"] for w in written] == [str(i) for i in range(1, 7)], "the output keeps the NEW OBJECTIDs")
        code, out, err = cli(base + ["--out", target, "--apply"])
        check(code == 3 and "already exists" in out, "an existing --out is never overwritten  <-- pinned defect")
        check(read_rows(target)[1] == written, "the refused overwrite left the file unchanged")
        code, out, err = cli(base + ["--out", os.path.join(tmp, "no_such_dir", "x.csv"), "--apply"])
        check(code == 3 and "cannot write" in out, "an unwritable --out exits 3")
        code, out, err = cli(base + ["--out", os.path.join(tmp, ".", "current.csv"), "--apply"])
        check(code == 2 and "new file" in err, "--out spelled differently but equal to --current is refused")
        code, out, err = cli(base + ["--out", pri, "--apply"])
        check(code == 2 and "new file" in err, "--out equal to --prior is refused")

        # a current file with no Status or Notes column gets them
        slim = put("slim.csv", "check_id,feature,message\nADDR-02,block 7,9 duplicate numbers\n")
        slim_out = path("slim_out.csv")
        code, out, err = cli(["--prior", pri, "--current", slim, "--key", "check_id,feature,message",
                              "--mask", "message", "--accept-resolved", "--accept-shifted", "--out", slim_out,
                              "--apply"])
        header, written = read_rows(slim_out)
        check(code == 0 and header == ["check_id", "feature", "message", "Status", "Notes"], "a current file without Status and Notes gains both")
        check(written[0]["Status"] == "FALSE_POSITIVE" and written[0]["Notes"] == "known, vendor data", "the added columns hold the carried mark")

        # exit 1: a mark that cannot be carried
        amb_p = put("amb_p.csv", _csv_text([_row(1, "C", "f", "m", "FALSE_POSITIVE", "a"), _row(2, "C", "f", "m", "FIXED", "b")]))
        amb_c = put("amb_c.csv", _csv_text([_row(1, "C", "f", "m"), _row(2, "D", "g", "n")]))
        amb_out = path("amb_out.csv")
        code, out, err = cli(["--prior", amb_p, "--current", amb_c, "--key", "check_id,feature,message",
                              "--out", amb_out, "--apply"])
        check(code == 1 and "LOST" in out and "lost marks      2" in out, "an ambiguous fingerprint exits 1 and names the lost marks")
        check(os.path.exists(amb_out) and read_rows(amb_out)[1][0]["Status"] == "OPEN", "exit 1 still writes the copy, with the ambiguous row left OPEN")

        # exit 4: nothing compared
        drift = put("drift.csv", _csv_text([_row(1, "OTHER", "x", "y")]))
        code, out, err = cli(["--prior", pri, "--current", drift, "--key", "check_id,feature,message", "--mask", "message"])
        check(code == 4 and "NOTHING COMPARED" in out, "a key that matches nothing exits 4")
        drift_out = path("drift_out.csv")
        code, out, err = cli(["--prior", pri, "--current", drift, "--key", "check_id,feature,message",
                              "--out", drift_out, "--apply"])
        check(code == 4 and not os.path.exists(drift_out), "exit 4 writes nothing even with --apply  <-- pinned defect")
        hdr_only = put("hdr_only.csv", _csv_text([]))
        code, out, err = cli(["--prior", pri, "--current", hdr_only, "--key", "check_id,feature,message"])
        check(code == 4, "a header-only current file exits 4")
        code, out, err = cli(["--prior", pri, "--current", hdr_only, "--key", "check_id,feature,message", "--allow-empty-current"])
        check(code == 0 and "resolved        4" in out, "--allow-empty-current exits 0 and resolves the marks")

        # the repro files of the audit, through the CLI
        kp = put("kc_p.csv", "k,Status,Notes\na,FALSE_POSITIVE,known\nb,NEW,\n")
        kc = put("kc_c.csv", "k,Status,Notes\na,NEW,\nb,NEW,\n")
        kc_out = path("kc_out.csv")
        code, out, err = cli(["--prior", kp, "--current", kc, "--key", "k", "--out", kc_out, "--apply"])
        check(code == 1 and "lost marks      1" in out and "--default-status" in out,
              "a current file full of NEW exits 1 and says why instead of exiting 0 with the marks gone  <-- pinned defect")
        code, out, err = cli(["--prior", kp, "--current", kc, "--key", "k", "--default-status", "NEW"])
        check(code == 0 and "carried         1" in out, "--default-status NEW carries the same mark and exits 0")

        bp = put("blk_p.csv", "check_id,feature,message,Status,Notes\nADDR-01,block 7,5 addresses disagree,FIXED,done\n")
        bc = put("blk_c.csv", "check_id,feature,message,Status,Notes\nADDR-01,block 9,5 addresses disagree,,\n")
        code, out, err = cli(["--prior", bp, "--current", bc, "--key", "check_id,feature,message", "--mask", "message"])
        check(code == 4 and "resolved        1" in out, "a different block with the same message is not carried, and nothing compared exits 4")
        bc2 = put("blk_c2.csv", "check_id,feature,message,Status,Notes\nADDR-01,block 9,5 addresses disagree,,\nZ,y,x,,\n")
        bp2 = put("blk_p2.csv", "check_id,feature,message,Status,Notes\nADDR-01,block 7,5 addresses disagree,FIXED,done\nZ,y,x,,\n")
        code, out, err = cli(["--prior", bp2, "--current", bc2, "--key", "check_id,feature,message", "--mask", "message"])
        check(code == 4 and "lost marks      0" in out and "cannot be told from a renamed check" in out,
              "a fixed finding next to a new one on another block matches no mark, so it exits 4, not 0  <-- pinned defect")

        partial_p = put("part_p.csv", _csv_text(pw))
        partial_c = put("part_c.csv", _csv_text(cw))
        partial_args = ["--prior", partial_p, "--current", partial_c, "--key", "check_id,feature,message"]
        code, out, err = cli(partial_args)
        check(code == 1 and "WARNING" in out and "--accept-resolved" in out,
              "a partial rename exits 1 with a WARNING line until --accept-resolved is passed  <-- pinned defect")
        code, out, err = cli(partial_args + ["--accept-resolved"])
        check(code == 0 and "WARNING" in out, "a partial rename accepted by hand exits 0 and still prints the WARNING")

        # a marked finding that is gone cannot be told from a truncated export or a missed key drift
        trunc_p = put("trunc_p.csv", "check_id,feature,message,Status,Notes\nA,f,one,FALSE_POSITIVE,known\n"
                      "B,f,two,FALSE_POSITIVE,known\nC,f,three,FALSE_POSITIVE,known\n")
        trunc_c = put("trunc_c.csv", "check_id,feature,message,Status,Notes\nA,f,one,,\n")
        trunc_args = ["--prior", trunc_p, "--current", trunc_c, "--key", "check_id,feature,message"]
        code, out, err = cli(trunc_args)
        check(code == 1 and "resolved        2" in out and "--accept-resolved" in out,
              "a current file that keeps one of three marked findings exits 1, not 0  <-- pinned defect")
        code, out, err = cli(trunc_args + ["--accept-resolved"])
        check(code == 0 and "resolved        2" in out, "the same run exits 0 once --accept-resolved is passed")
        drift_p = put("drift_p.csv", "check_id,feature,message,Status,Notes\nA,f,12 addresses,FIXED,x\n"
                      "B,f,one,FALSE_POSITIVE,k\nC,f,two,FALSE_POSITIVE,k\n")
        drift_c = put("drift_c.csv", "check_id,feature,message,Status,Notes\nA,f,13 addresses,,\nB,f,one,,\nC,f,two,,\n")
        code, out, err = cli(["--prior", drift_p, "--current", drift_c, "--key", "check_id,message,feature"])
        check(code == 1 and "carried         2" in out and "resolved        1" in out,
              "a count that moves in a key field that is not last exits 1 instead of reporting the mark resolved  <-- pinned defect")
        apos_p = put("apos_p.csv", "check_id,feature,message,Status,Notes\nA,f,m,FIXED,'-3\n")
        apos_c = put("apos_c.csv", "check_id,feature,message,Status,Notes\nA,f,m,,\n")
        apos_out = path("apos_out.csv")
        code, out, err = cli(["--prior", apos_p, "--current", apos_c, "--key", "check_id,feature,message",
                              "--out", apos_out, "--apply"])
        check(code == 0 and read_rows(apos_out)[1][0]["Notes"] == "'-3",
              "a Notes cell that really starts with an apostrophe and a number survives the carry  <-- pinned defect")

        # a rename with one unmarked survivor must not look cleaner than a rename with none
        sv_p = put("sv_p.csv", "check_id,feature,message,Status,Notes\nADDR-01,f,m,FALSE_POSITIVE,x\nGEOM-01,f,m,FALSE_POSITIVE,y\nGEOM-02,f,m,OPEN,\n")
        sv_c = put("sv_c.csv", "check_id,feature,message,Status,Notes\nADDR-1,f,m,,\nGEOM-1,f,m,,\nGEOM-02,f,m,,\n")
        sv_out = path("sv_out.csv")
        code, out, err = cli(["--prior", sv_p, "--current", sv_c, "--key", "check_id,feature,message", "--out", sv_out, "--apply"])
        check(code == 4 and "NOTHING COMPARED" in out and not os.path.exists(sv_out),
              "two renamed checks and an unmarked survivor exit 4 and write nothing  <-- pinned defect")

        # the prior file was written by this tool, the current file is a raw export
        gp_p = put("gp_p.csv", "check_id,feature,message,Status,Notes\nC,''=x,m,FALSE_POSITIVE,known\nD,f,ok,OPEN,\n")
        gp_c = put("gp_c.csv", "check_id,feature,message,Status,Notes\nC,'=x,m,,\nD,f,ok,,\n")
        code, out, err = cli(["--prior", gp_p, "--current", gp_c, "--key", "check_id,feature,message"])
        check(code == 0 and "carried         1" in out and "new             0" in out and "WARNING" not in out,
              "a guarded prior key and a raw current key with the same text carry the mark  <-- pinned defect")

        # blank lines are not rows
        blank_p = put("blank_p.csv", "check_id,feature,message,Status,Notes\nC,f,m,FIXED,x\n\n")
        blank_c = put("blank_c.csv", "check_id,feature,message,Status,Notes\n\nC,f,m,,\n\n")
        blank_out = path("blank_out.csv")
        code, out, err = cli(["--prior", blank_p, "--current", blank_c, "--key", "check_id,feature,message", "--out", blank_out, "--apply"])
        check(code == 0 and "unkeyable       0" in out and "wrote 1 rows" in out, "blank lines are skipped, not counted as unkeyable rows  <-- pinned defect")
        check(len(read_rows(blank_out)[1]) == 1, "the output has no phantom empty row")
        code, out, err = cli(["--prior", "a\x00b", "--current", cur, "--key", "check_id"])
        check(code == 2 and "cannot read" in err, "a path with a NUL character is a usage error, not a traceback")

        # the audit repros: a mark in a column the tool was not told about, a truncated export,
        # a stray quote and a blank header cell
        nm_p = put("nm_p.csv", "check_id,feature,message,Status,Notes,Review\nA,f,m,OPEN,,FALSE_POSITIVE x\nB,f,m,OPEN,,\n")
        nm_c = put("nm_c.csv", "check_id,feature,message,Status,Notes\nA,f,m,,\nB,f,m,,\n")
        nm_out = path("nm_out.csv")
        nm_argv = ["--prior", nm_p, "--current", nm_c, "--key", "check_id,feature,message", "--out", nm_out, "--apply"]
        code, out, err = cli(nm_argv)
        check(code == 4 and "(0 marked)" in out and "--status-field" in out and not os.path.exists(nm_out),
              "marks in a column the tool was not told about exit 4, name the flags and write nothing  <-- pinned defect")
        code, out, err = cli(nm_argv + ["--notes-field", "Review"])
        check(code == 0 and "carried         1" in out and read_rows(nm_out)[1][0]["Review"] == "FALSE_POSITIVE x",
              "naming that column as --notes-field carries the mark")
        nm_out2 = path("nm_out2.csv")
        code, out, err = cli(nm_argv[:-3] + ["--allow-no-carry", "--out", nm_out2, "--apply"])
        check(code == 0 and "(0 marked)" in out and os.path.exists(nm_out2),
              "--allow-no-carry runs a prior file with no marks, exits 0 and writes the output")

        tr_p = put("tr_p.csv", _csv_text(prior))
        tr_c = put("tr_c.csv", _csv_text([_row(5, "GEOM-02", "tract 4", "overlap")]))
        tr_out = path("tr_out.csv")
        tr_argv = ["--prior", tr_p, "--current", tr_c, "--key", "check_id,feature,message", "--out", tr_out, "--apply"]
        code, out, err = cli(tr_argv)
        check(code == 4 and "truncated export" in out and "resolved        4" in out and not os.path.exists(tr_out),
              "a current file that lost every marked finding exits 4 and writes nothing  <-- pinned defect")
        code, out, err = cli(tr_argv + ["--allow-no-carry"])
        check(code == 0 and os.path.exists(tr_out), "--allow-no-carry accepts the same run, exits 0 and writes the output")

        sq_p = put("sq_p.csv", 'check_id,feature,message,Status,Notes\nA,f,m,FIXED,"oops\nB,f,m,OPEN,\nC,f,m,OPEN,\n')
        sq_c = put("sq_c.csv", "check_id,feature,message,Status,Notes\nA,f,m,,\nB,f,m,,\nC,f,m,,\n")
        raises(lambda: read_rows(sq_p), "an unterminated opening quote is refused, not merged into one cell  <-- pinned defect")
        code, out, err = cli(["--prior", sq_p, "--current", sq_c, "--key", "check_id,feature,message"])
        check(code == 2 and "cannot read" in err, "the stray quote is a usage error through the CLI")
        check(read_rows(put("q_ok.csv", 'k,m\na,"x ""y"" z"\nb,5" pipe\n'))[1] == [{"k": "a", "m": 'x "y" z'}, {"k": "b", "m": '5" pipe'}],
              "a doubled quote and a quote inside an unquoted cell are still read")

        bh_p = put("bh_p.csv", "check_id,feature,message,Status,Notes,\nC,f,m,FIXED,x,\n")
        bh_c = put("bh_c.csv", "check_id,feature,message,Status,Notes,\nC,f,m,,,\n")
        bh_out = path("bh_out.csv")
        code, out, err = cli(["--prior", bh_p, "--current", bh_c, "--key", "check_id,feature,message", "--out", bh_out, "--apply"])
        check(code == 0 and read_rows(bh_out)[0][-1] == "" and read_rows(bh_out)[1][0]["Status"] == "FIXED",
              "a single blank header cell is accepted and carried through; only a repeated name is refused  <-- pinned defect")

        # a character the console cannot encode must not crash the report
        enc_p = put("enc_p.csv", u"k,Status,Notes\ngap \u2265 5 m,DONE,n\nsteady,OPEN,\n")
        enc_c = put("enc_c.csv", u"k,Status,Notes\ngap \u2265 6 m,,\nsteady,,\n")
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "ascii"
        proc = subprocess.run([sys.executable, os.path.abspath(__file__), "--prior", enc_p, "--current", enc_c, "--key", "k"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=env)
        check(proc.returncode == 1 and "LOST" in proc.stdout and "gap ? 5 m" in proc.stdout and "Traceback" not in proc.stderr,
              "an ASCII-only console prints '?' for an unencodable character and still reports the lost mark  <-- pinned defect")

        # an unexpected error exits 5, never the 'marks lost' code 1
        real_run = globals()["run"]

        def boom(args):
            raise RuntimeError("boom")
        globals()["run"] = boom
        try:
            code, out, err = cli(base)
        finally:
            globals()["run"] = real_run
        check(code == 5 and "internal error: RuntimeError: boom" in err and "Traceback" not in err,
              "an unexpected error exits 5 with a one-line message, not 1  <-- pinned defect")

        # usage errors
        code, out, err = cli(["--prior", pri, "--current", cur])
        check(code == 2 and "--key is required" in err, "a missing --key is a usage error")
        code, out, err = cli(["--current", cur, "--key", "check_id"])
        check(code == 2 and "--prior is required" in err, "a missing --prior is a usage error")
        code, out, err = cli(["--prior", pri, "--current", cur, "--key", "OBJECTID"])
        check(code == 2 and "--allow-oid-key" in err, "an OBJECTID --key is a usage error through the CLI")
        code, out, err = cli(["--prior", pri, "--current", cur, "--key", "OBJECTID,check_id", "--allow-oid-key"])
        check(code == 1 and "carried         1" in out and "lost marks      1" in out,
              "--allow-oid-key lets the run proceed: the rebuilt ObjectID 4 carries a mark onto an unrelated finding")
        code, out, err = cli(["--prior", path("missing.csv"), "--current", cur, "--key", "check_id"])
        check(code == 2 and "cannot read" in err, "a missing --prior file is a usage error")

        # status/notes names and default status are honoured
        alt_p = put("alt_p.csv", "k,State,Memo\nalpha 5,DONE,seen\nbeta,todo,\n")
        alt_c = put("alt_c.csv", "k,State,Memo\nbeta,,\nalpha 9,,\n")
        alt_out = path("alt_out.csv")
        code, out, err = cli(["--prior", alt_p, "--current", alt_c, "--key", "k", "--mask", "k", "--status-field", "State",
                              "--notes-field", "Memo", "--default-status", "todo", "--accept-shifted", "--out", alt_out,
                              "--apply"])
        written = read_rows(alt_out)[1]
        check(code == 0 and [w["State"] for w in written] == ["todo", "DONE"], "custom field names and default status are honoured")
        check(written[1]["Memo"] == "seen", "the custom notes column is carried")

        # non-ASCII data survives the round trip
        uni_p = put("uni_p.csv", u"k,Status,Notes\ncaf\u00e9,DONE,n\u00f3te\n")
        uni_c = put("uni_c.csv", u"k,Status,Notes\ncaf\u00e9,OPEN,\n")
        uni_out = path("uni_out.csv")
        code, out, err = cli(["--prior", uni_p, "--current", uni_c, "--key", "k", "--out", uni_out, "--apply"])
        check(read_rows(uni_out)[1][0]["Notes"] == u"n\u00f3te", "non-ASCII notes survive the round trip")

        # a real second process: the script run as a command
        script = os.path.abspath(__file__)
        proc = subprocess.run([sys.executable, script] + base, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, universal_newlines=True)
        check(proc.returncode == 0 and "carried         3" in proc.stdout, "the script runs as a command and exits 0")
        subprocess_out = path("sub_out.csv")
        proc = subprocess.run([sys.executable, script] + base + ["--out", subprocess_out, "--apply"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        check(proc.returncode == 0 and read_rows(subprocess_out)[1][2]["Status"] == "FALSE_POSITIVE",
              "the script run as a command writes the carried marks")
        proc = subprocess.run([sys.executable, script] + base + ["--out", path("ab.csv"), "--ap"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        check(proc.returncode == 2 and not os.path.exists(path("ab.csv")),
              "a unique prefix --ap of --apply is REFUSED by the parser  <-- pinned defect")

        # ---- formula guard: a text cell a spreadsheet would run as a formula is written as text
        leads = [("equals", "=1+1"), ("plus", "+1+1"), ("minus", "-1+1"), ("at", "@SUM(1)"),
                 ("tab", "\tx"), ("carriage return", "\rx"), ("line feed", "\nx"),
                 ("full-width equals", u"\uff1d1+1"), ("full-width plus", u"\uff0b1"),
                 ("full-width minus", u"\uff0d1"), ("full-width at", u"\uff20x")]
        for name, text in leads:
            check(guard_cell(text) == "'" + text, "guard_cell puts one apostrophe in front of a cell that starts with %s" % name)
            check(unguard_cell("'" + text) == text, "unguard_cell strips that apostrophe from a cell that starts with %s" % name)
        for text in ("-3", "+3", "-1.5", "-.5", "+7.", "-1e-3", "42", "0", "abc", "", "O'Brien", "x=1", "a-b", " =x"):
            check(guard_cell(text) == text, "guard_cell leaves %r alone: a plain number or text that is not a formula" % text)
        for text in ("-3x", "-", "+", "-3\n", "-3\r", "- 3", "-1+2", "--3", "-3-"):
            check(guard_cell(text) == "'" + text, "guard_cell treats %r as text, not as a number  <-- pinned defect" % text)
        for text in ("-1,234", "+1,000"):
            check(guard_cell(text) == "'" + text, "guard_cell writes %r as text: a thousands separator is not a plain number" % text)
        for text in ("|x", "%x", chr(1) + "=x"):
            check(guard_cell(text) == text, "guard_cell does not guard %r: it is not in the OWASP list" % text)
        for text in (chr(160) + "=x", "  +x", chr(0x200b) + "=x"):
            check(guard_cell(text) == text, "guard_cell does not guard %r: only the first character is tested" % text)
        check(unguard_cell("'abc") == "'abc" and unguard_cell("'") == "'" and unguard_cell("") == "",
              "unguard_cell leaves an apostrophe that is not in front of a formula character")
        check(unguard_cell("''=x") == "'=x" and unguard_cell("'=x") == "=x", "unguard_cell strips exactly one apostrophe")
        check(unguard_cell("'-5") == "'-5" and unguard_cell("'+4.5") == "'+4.5",
              "unguard_cell keeps an apostrophe in front of a plain number, because guard_cell never adds one  <-- pinned defect")
        check(unguard_cell("'-1,234") == "-1,234", "unguard_cell strips the apostrophe guard_cell adds to a comma-separated number")
        sample = ["=1+1", "'=x", "''=x", "'hello", "'", "''", "'\t", "-5", "'-5", "@a", "\tz", "\rz", "+", "", "plain", u"\uff1dx",
                  "-3\n", "'-3\n"]
        check(all(unguard_cell(guard_cell(t)) == t for t in sample),
              "guard_cell then unguard_cell returns every sample cell unchanged, apostrophes included  <-- pinned defect")
        check(all(guard_cell(unguard_cell(guard_cell(t))) == guard_cell(t) for t in sample),
              "the guard is stable: guarding a cell that was read back gives the cell that was written")

        def raw_cells(name):
            with io.open(path(name), "r", newline="", encoding="utf-8") as handle:
                return list(csv.reader(handle))

        # each text field of the output, for each leading character, written and read back
        for field in ("check_id", "feature", "message", "Status", "Notes"):
            col = HEADER.index(field)
            out_name = "guard_%s.csv" % field
            for name, text in leads:
                row = _row(1, "c", "f", "m")
                row[field] = text
                if os.path.exists(path(out_name)):
                    os.remove(path(out_name))
                write_rows(path(out_name), HEADER, [row])
                check(raw_cells(out_name)[1][col] == "'" + text,
                      "write_rows guards the %s field when it starts with %s" % (field, name))
            row = _row(1, "c", "f", "m")
            row[field] = "'=keep"
            os.remove(path(out_name))
            write_rows(path(out_name), HEADER, [row])
            check(read_rows(path(out_name))[1][0][field] == "'=keep",
                  "a %s cell that really starts with an apostrophe and a formula character survives the round trip  <-- pinned defect" % field)
            row[field] = "'plain apostrophe"
            os.remove(path(out_name))
            write_rows(path(out_name), HEADER, [row])
            check(raw_cells(out_name)[1][col] == "'plain apostrophe" and read_rows(path(out_name))[1][0][field] == "'plain apostrophe",
                  "a %s cell with a leading apostrophe and no formula character is neither changed nor stripped" % field)
            row[field] = "'-3"
            os.remove(path(out_name))
            write_rows(path(out_name), HEADER, [row])
            check(raw_cells(out_name)[1][col] == "''-3" and read_rows(path(out_name))[1][0][field] == "'-3",
                  "a %s cell that is an apostrophe and a plain number survives the round trip  <-- pinned defect" % field)
        raw_apos = read_rows(put("rawapos.csv", "k,Memo\na,'=x\nb,'-12\n"))[1]
        check(raw_apos == [{"k": "a", "Memo": "=x"}, {"k": "b", "Memo": "'-12"}],
              "a raw '=x is read as the guarded =x, and a raw '-12 keeps its apostrophe because no guard was written there  <-- pinned defect")
        write_rows(path("rawapos_out.csv"), ["k", "Memo"], raw_apos)
        check(raw_cells("rawapos_out.csv")[1:] == [["a", "'=x"], ["b", "''-12"]],
              "a raw '=x is written back as '=x, and a raw '-12 is written as ''-12  <-- pinned defect")
        write_rows(path("num.csv"), HEADER, [_row(-3, "-7", "f", "-12", "+4", "-0.5")])
        check(raw_cells("num.csv")[1] == ["-3", "-7", "f", "-12", "+4", "-0.5"],
              "numeric cells, negative or signed, are written as numbers  <-- pinned defect")
        write_rows(path("hdr.csv"), ["=a", "b"], [{"=a": "1", "b": "2"}])
        check(raw_cells("hdr.csv")[0] == ["'=a", "b"] and read_rows(path("hdr.csv"))[0] == ["=a", "b"],
              "a header cell that starts with a formula character is guarded and read back")
        ex_header = HEADER + ["Reviewer"]
        write_rows(path("extra.csv"), ex_header, [dict(_row(1, "c", "f", "m"), Reviewer="=SUM(A1)")])
        check(raw_cells("extra.csv")[1][-1] == "'=SUM(A1)" and read_rows(path("extra.csv"))[1][0]["Reviewer"] == "=SUM(A1)",
              "a free-text column that is neither key nor mark is guarded and read back")
        write_rows(path("cr.csv"), ["k", "m"], [{"k": "a", "m": "x\ry"}, {"k": "b", "m": "\rz"}])
        with io.open(path("cr.csv"), "rb") as handle:
            check(handle.read() == b'k,m\na,"x\ry"\nb,"\'\rz"\n',
                  "a bare CR inside a cell is quoted in the file on every Python version  <-- pinned defect")
        check(read_rows(path("cr.csv"))[1] == [{"k": "a", "m": "x\ry"}, {"k": "b", "m": "\rz"}],
              "a cell with a bare CR reads back as one cell")
        raises(lambda: read_rows(put("hdupe.csv", "=a,'=a\n1,2\n")), "a header that repeats a name once the guard is stripped is refused")
        check(read_rows(put("rawf.csv", "k,m\n=1+1,@x\n"))[1] == [{"k": "=1+1", "m": "@x"}],
              "a cell with no apostrophe is read as it is")

        # the tool reads its own output back: marks and fingerprints must survive a second cycle
        fp = [_row(1, "f-1", "=cmd|' /c calc'!A1", "+2 gaps", "FALSE_POSITIVE", "=HYPERLINK(\"http://x\")"),
              _row(2, "f-2", "@home", "-4 over", "DEFERRED", "'=quoted"),
              _row(3, "f-3", "\tpad", "\rret", "FIXED", "'only an apostrophe"),
              _row(4, "f-4", "-12", "m", "OPEN", ""),
              _row(5, "f-5", "ok", "m", "-", "")]
        blank = [dict(r, Status="OPEN", Notes="") for r in fp]
        cyc_cur = put("cyc_cur.csv", _csv_text(blank))
        seed = path("cyc_seed.csv")
        write_rows(seed, HEADER, fp)
        cyc_key = ["--key", "check_id,feature,message", "--mask", "message"]
        out1 = path("cyc1.csv")
        code, out, err = cli(["--prior", seed, "--current", cyc_cur] + cyc_key + ["--out", out1, "--apply"])
        check(code == 0 and "carried         4" in out and "lost marks      0" in out,
              "a prior file the tool wrote itself, with guarded fingerprints, carries every mark on the next run  <-- pinned defect")
        check([(r["Status"], r["Notes"]) for r in read_rows(out1)[1]] == [(r["Status"], r["Notes"]) for r in fp],
              "the carried Status and Notes read back exactly, formulas and apostrophes included")
        raw1 = raw_cells("cyc1.csv")
        check(raw1[1][2] == "'=cmd|' /c calc'!A1" and raw1[1][5] == "'=HYPERLINK(\"http://x\")",
              "the output file holds the formula cells as text")
        check(raw1[2][5] == "''=quoted" and raw1[3][5] == "'only an apostrophe",
              "a Notes cell that really starts with an apostrophe is not confused with a guard  <-- pinned defect")
        check(raw1[4][2] == "-12" and raw1[3][2] == "'\tpad" and raw1[3][3] == "'\rret" and raw1[5][4] == "'-",
              "a numeric text cell stays as it is while tab, carriage return and a lone minus are guarded")
        out2 = path("cyc2.csv")
        code, out, err = cli(["--prior", out1, "--current", cyc_cur] + cyc_key + ["--out", out2, "--apply"])
        check(code == 0 and "carried         4" in out and read_rows(out2)[1] == read_rows(out1)[1],
              "a second cycle through the tool's own output changes nothing  <-- pinned defect")
        check(raw_cells("cyc2.csv") == raw_cells("cyc1.csv"), "the second output holds the same cells as the first")
        out3 = path("cyc3.csv")
        code, out, err = cli(["--prior", cyc_cur, "--current", cyc_cur] + cyc_key + ["--allow-no-carry", "--out", out3, "--apply"])
        check(raw_cells("cyc3.csv")[1][2] == "'=cmd|' /c calc'!A1" and raw_cells("cyc3.csv")[1][3] == "'+2 gaps",
              "formula cells that come from the current input are guarded in the output too")
        bare = put("cyc_bare.csv", _csv_text([dict(r, Status="", Notes="") for r in fp]))
        out4 = path("cyc4.csv")
        code, out, err = cli(["--prior", bare, "--current", bare] + cyc_key + ["--allow-no-carry", "--default-status", "-", "--out", out4, "--apply"])
        check(code == 0 and raw_cells("cyc4.csv")[1][4] == "'-" and read_rows(out4)[1][0]["Status"] == "-",
              "a --default-status that starts with a formula character is guarded in the output")

    # ---- the parser
    ap = build_parser()
    check(ap.parse_args(["--apply"]).apply is True, "--apply parses")
    check(ap.parse_args([]).apply is False, "--apply defaults to OFF")
    for prefix in ("--app", "--appl", "--ap", "--ma", "--prio", "--out-", "--self"):
        code, out, err = cli([prefix, "x"])
        check(code == 2, "the prefix %s is refused by the parser" % prefix)
    code, out, err = cli(["--mask", "x", "--bogus"])
    check(code == 2 and "unrecognized" in err, "an unknown flag is refused")

    # ---- every claim in the README's table of exit codes is distinct
    check(len(set([EXIT_OK, EXIT_LOST, EXIT_USAGE, EXIT_WRITE, EXIT_NOTHING, EXIT_CRASH])) == 6, "the six exit codes are distinct")

    # ---- the harness itself: a failing check must be reported, not swallowed
    probe, out = Harness(), io.StringIO()
    with contextlib.redirect_stdout(out):
        probe.check(False, "deliberate")
        probe.raises(lambda: 1, "no error")
        probe.raises(lambda: 1 / 0, "wrong error")
        probe.raises(lambda: int("x"), "right error")
        probe_code = probe.footer()
    text = out.getvalue()
    check(probe.passed == 1 and len(probe.failed) == 3, "the harness counts one pass and three failures")
    check("FAIL  deliberate" in text and "(no error raised)" in text and "(wrong exception" in text, "the harness prints each failure and why")
    check("4 assertions, 3 failed" in text and "FAILED: deliberate" in text and probe_code == 1, "the footer of a failing harness names the failures and exits 1")

    return h.footer()


if __name__ == "__main__":  # pragma: no branch (always true when the file is run)
    sys.exit(main())
