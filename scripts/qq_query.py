"""Query and export QQ NT chat messages.

usage:
    python qq_query.py --db <nt_msg.db> --key <16-byte key> --out out.jsonl --peer 123456789
    python qq_query.py --db <nt_msg.db> --key <key> --out out.jsonl --group 123456 --day 2026-10-04
    python qq_query.py --db <nt_msg.db> --key <key> --out out.jsonl --sender 100200300

The source database is never modified: the 1024-byte NTQQ header is stripped into a
temporary copy (with its -wal/-shm when present) that is deleted on exit. A live QQ
database can yield torn pages, so the snapshot+query is retried on a malformed-database
error.
"""
import argparse
import datetime as dt
import json
import os
import shutil
import sqlite3
import sys
import tempfile

HEADER = 1024
TEXT_TYPES = {1, 6, 8, 14}          # plain, face, gray tip, markdown
MEDIA_TYPES = {2: "image", 3: "file", 4: "voice", 5: "video", 9: "redbag", 10: "ark", 11: "marketface", 21: "call"}


def read_varint(buf, i):
    shift = 0
    val = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i
        shift += 7


def iter_fields(buf):
    i = 0
    n = len(buf)
    while i < n:
        key, i = read_varint(buf, i)
        field, wire = key >> 3, key & 7
        if wire == 0:
            val, i = read_varint(buf, i)
            yield field, wire, val
        elif wire == 2:
            ln, i = read_varint(buf, i)
            yield field, wire, buf[i:i + ln]
            i += ln
        elif wire == 5:
            yield field, wire, buf[i:i + 4]
            i += 4
        elif wire == 1:
            yield field, wire, buf[i:i + 8]
            i += 8
        else:
            return


def parse_body(blob):
    """MsgBody{repeated MsgContent content=40800} -> list of segments."""
    segs = []
    for field, wire, val in iter_fields(blob or b""):
        if field != 40800 or wire != 2:
            continue
        seg = {"type": None, "text": "", "extra": {}}
        for f2, w2, v2 in iter_fields(val):
            if f2 == 45002 and w2 == 0:
                seg["type"] = v2
            elif f2 == 45101 and w2 == 2:
                seg["text"] = v2.decode("utf-8", "replace")
            elif f2 == 47602 and w2 == 2:
                seg["text"] = seg["text"] or v2.decode("utf-8", "replace")
            elif f2 == 80900 and w2 == 2:
                seg["text"] = seg["text"] or v2.decode("utf-8", "replace")
            elif f2 == 45402 and w2 == 2:
                seg["extra"]["file"] = v2.decode("utf-8", "replace")
        seg["kind"] = "text" if seg["type"] in TEXT_TYPES else MEDIA_TYPES.get(seg["type"], "other")
        segs.append(seg)
    return segs


def snapshot(src, dst):
    """Strip the NTQQ 1024-byte header into dst; returns True when a header was removed."""
    with open(src, "rb") as fin:
        head = fin.read(HEADER)
        stripped = not head[:16].startswith(b"SQLite format 3")
        if not stripped:
            fin.seek(0)
            with open(dst, "wb") as fout:
                shutil.copyfileobj(fin, fout, 8 << 20)
            return False
        with open(dst, "wb") as fout:
            shutil.copyfileobj(fin, fout, 8 << 20)
    for suffix in ("-wal", "-shm"):
        side = src + suffix
        if os.path.exists(side):
            try:
                shutil.copyfile(side, dst + suffix)
            except OSError:
                pass
    return True


def connect(path, key):
    from sqlcipher3 import dbapi2 as sqlcipher
    con = sqlcipher.connect(path)
    cur = con.cursor()
    # order matters: page size before key
    cur.execute("PRAGMA cipher_page_size = 4096")
    cur.execute("PRAGMA key = '%s'" % key.replace("'", "''"))
    cur.execute("PRAGMA kdf_iter = 4000")
    cur.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA1")
    cur.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512")
    cur.execute("SELECT count(*) FROM sqlite_master")
    return con


def day_bounds(day):
    start = dt.datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=dt.timezone(dt.timedelta(hours=8)))
    return int(start.timestamp()), int((start + dt.timedelta(days=1)).timestamp())


def build_jobs(args):
    jobs = []
    if args.peer is not None or args.group is None:
        jobs.append(("c2c_msg_table", args.peer))
    if args.group is not None or args.peer is None:
        jobs.append(("group_msg_table", args.group))
    return jobs


def query_all(cur, args, fout):
    since, until = args.since, args.until
    if args.day:
        since, until = day_bounds(args.day)

    written = 0
    for table, peer_val in build_jobs(args):
        if args.limit and written >= args.limit:
            break
        where, params = [], []
        if peer_val is not None:
            where.append('"40030" = ?')
            params.append(peer_val)
        if args.sender is not None:
            where.append('"40033" = ?')
            params.append(args.sender)
        if args.sent_only:
            where.append('"40013" IN (1, 2)')
        if since is not None:
            where.append('"40050" >= ?')
            params.append(since)
        if until is not None:
            where.append('"40050" < ?')
            params.append(until)
        sql = ('SELECT "40001","40013","40020","40033","40030","40027","40050",'
               '"40090","40093","40800" FROM "%s"' % table)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += ' ORDER BY "40050" ASC'
        if args.limit:
            sql += " LIMIT %d" % (args.limit - written)

        for row in cur.execute(sql, params):
            mid, direction, uid, sender, peer, session, ts, card, nick, body = row
            segs = parse_body(body)
            text = "".join(s["text"] for s in segs if s["kind"] == "text")
            fout.write(json.dumps({
                "ts": dt.datetime.fromtimestamp(ts, dt.timezone(dt.timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S"),
                "unix": ts,
                "table": table,
                "msg_id": mid,
                "direction": direction,
                "sender": sender,
                "uid": uid,
                "peer": peer,
                "session": session,
                "card": card,
                "nick": nick,
                "text": text,
                "segments": [{"kind": s["kind"], "type": s["type"], "text": s["text"]} for s in segs],
            }, ensure_ascii=False) + "\n")
            written += 1
    return written


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--peer", type=int, help="c2c peer QQ")
    ap.add_argument("--group", type=int, help="group number")
    ap.add_argument("--sender", type=int, help="filter by sender QQ")
    ap.add_argument("--day", help="YYYY-MM-DD (UTC+8)")
    ap.add_argument("--since", type=int, help="unix seconds")
    ap.add_argument("--until", type=int, help="unix seconds")
    ap.add_argument("--sent-only", action="store_true")
    ap.add_argument("--limit", type=int, default=0, help="max messages overall (0 = unlimited)")
    ap.add_argument("--retries", type=int, default=3, help="snapshot retries on a malformed live db")
    args = ap.parse_args()

    tmpdir = tempfile.mkdtemp(prefix="qqdump_")
    try:
        last_error = None
        for attempt in range(1, args.retries + 1):
            stripped = os.path.join(tmpdir, "nt_msg_%d.db" % attempt)
            try:
                had_header = snapshot(args.db, stripped)
                print("attempt %d: header stripped=%s" % (attempt, had_header), file=sys.stderr)
                con = connect(stripped, args.key)
                cur = con.cursor()
                with open(args.out, "w", encoding="utf-8") as fout:
                    written = query_all(cur, args, fout)
                print("wrote %d messages -> %s" % (written, args.out), file=sys.stderr)
                return
            except sqlite3.DatabaseError as exc:
                last_error = exc
                print("attempt %d failed: %s" % (attempt, exc), file=sys.stderr)
            finally:
                for suffix in ("", "-wal", "-shm"):
                    try:
                        os.remove(stripped + suffix)
                    except OSError:
                        pass
        raise SystemExit("all %d snapshots failed (%s); QQ is writing the db - retry later"
                         % (args.retries, last_error))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
