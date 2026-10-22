#!/usr/bin/env python3
"""Schlanke Web-Oberfläche für OpenLDAP (Verzeichnisbaum mit Anlegen, Bearbeiten, Löschen, Verschieben).

Start:  pip install flask ldap3
        LDAP_URI=ldaps://ldap.example.org LDAP_BASE=dc=example,dc=org python app.py
"""
import base64, os, re, secrets
from html import escape as html_escape
from flask import Flask, request, jsonify, session, Response
from ldap3 import Server, Connection, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, HASHED_SALTED_SHA, LEVEL, SUBTREE, NO_ATTRIBUTES, BASE as SCOPE_BASE
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn, safe_rdn, parse_dn
from ldap3.utils.hashed import hashed

URI = os.environ.get("LDAP_URI", "ldap://localhost:389")
BASE = os.environ.get("LDAP_BASE", "dc=example,dc=org")
UOU = os.environ.get("LDAP_USERS", "ou=people") + "," + BASE

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))
app.config.update(SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=20 * 1024 * 1024)
SESS = {}  # Zugangsdaten bleiben serverseitig, im Cookie liegt nur eine Zufalls-ID
CFG = {}   # optionale Zugangsdaten für cn=config (Zugriffsrechte), ebenfalls nur im Speicher
CFG_DN = os.environ.get("LDAP_CONFIG_DN", "cn=admin,cn=config")
APP_TITLE = os.environ.get("APP_TITLE") or None  # ohne Angabe: "Directory" bzw. "Verzeichnis" je nach Sprache

# ---- Sprache: Englisch ist Standard, Deutsch bei deutscher Browsersprache (Accept-Language) ----
DE = {
    "Please log in.": "Bitte anmelden.",
    "Please enter a password.": "Bitte ein Passwort eingeben.",
    "Login as {dn} failed: {err}": "Anmeldung als {dn} fehlgeschlagen: {err}",
    "The DN is outside the base.": "Der DN liegt außerhalb der Basis.",
    "Entry not found.": "Eintrag nicht gefunden.",
    "RDN attribute and RDN value are required.": "RDN-Attribut und RDN-Wert sind erforderlich.",
    "At least one object class is required.": "Mindestens eine Objektklasse ist erforderlich.",
    "Invalid attribute name: {name}": "Ungültiger Attributname: {name}",
    "The base cannot be deleted.": "Die Basis kann nicht gelöscht werden.",
    "The base cannot be moved.": "Die Basis kann nicht verschoben werden.",
    "The target must not be the entry itself or below it.": "Das Ziel darf nicht der Eintrag selbst oder darunter sein.",
    "Invalid line: {line}": "Ungültige Zeile: {line}",
    "Invalid Base64 in {name}": "Ungültiges Base64 bei {name}",
    "URL values (attr:< …) are not supported.": "URL-Werte (attr:< …) werden nicht unterstützt.",
    "The entry does not start with “dn:”.": "Der Eintrag beginnt nicht mit „dn:“.",
    "Unexpected line in modification: {name}": "Unerwartete Zeile in der Änderung: {name}",
    "changetype “{ct}” is not supported (please move entries in the tree).":
        "changetype „{ct}“ wird nicht unterstützt (Verschieben bitte im Baum).",
    "Entry {n}: {err}": "Eintrag {n}: {err}",
    "objectClass is missing.": "objectClass fehlt.",
    "No entries found.": "Keine Einträge gefunden.",
    "No database with the suffix {base} was found in cn=config (or the account may not read it).":
        "In cn=config wurde keine Datenbank mit dem Suffix {base} gefunden (oder das Konto darf sie nicht lesen).",
    "Invalid level.": "Ungültige Stufe.",
    "Please choose a valid DN.": "Bitte einen gültigen DN auswählen.",
    "This entry does not exist.": "Dieser Eintrag existiert nicht.",
    "posixGroup is not supported (its members are not DNs).":
        "posixGroup wird nicht unterstützt (die Mitglieder sind keine DNs).",
    "Please log in with a cn=config account first.": "Bitte zuerst mit einem cn=config-Konto anmelden.",
    "This permission already exists.": "Dieses Recht gibt es schon.",
    "Rule not found or not managed by this app.": "Regel nicht gefunden oder nicht von dieser App verwaltet.",
    "The schema could not be read.": "Das Schema konnte nicht gelesen werden.",
    "‹binary, {n} bytes›": "‹binär, {n} Bytes›",
}


def lang():
    for code, _q in request.accept_languages:  # nach Wunsch des Browsers sortiert
        c = code.lower()
        if c.startswith("de"):
            return "de"
        if c.startswith("en"):
            return "en"
    return "en"


def tr(msg, **kw):
    if lang() == "de":
        msg = DE.get(msg, msg)
    return msg.format(**kw) if kw else msg



def conn():
    cred = SESS.get(session.get("sid"))
    if not cred:
        raise PermissionError(tr("Please log in."))
    return Connection(Server(URI), user=cred[0], password=cred[1], auto_bind=True)


def chk(c):
    if c.result["result"] != 0:
        raise ValueError(f'{c.result["description"]} {c.result.get("message", "")}'.strip())


@app.errorhandler(PermissionError)
def _401(e):
    return jsonify(error=str(e)), 401


@app.errorhandler(ValueError)
@app.errorhandler(LDAPException)
def _400(e):
    return jsonify(error=str(e)), 400


def one(v):
    return v[0] if isinstance(v, list) and v else (v if not isinstance(v, list) else "")


@app.post("/api/login")
def login():
    d = request.json
    u = d["user"].strip()
    dn = u if "=" in u else f"uid={escape_rdn(u)},{UOU}"
    if not d["password"]:
        raise ValueError(tr("Please enter a password."))
    try:
        Connection(Server(URI), user=dn, password=d["password"], auto_bind=True).unbind()
    except LDAPException as e:
        app.logger.warning("Login failed (URI=%s, DN=%s): %s", URI, dn, e)
        raise ValueError(tr("Login as {dn} failed: {err}", dn=dn, err=e))
    sid = secrets.token_hex(16)
    SESS[sid] = (dn, d["password"])
    session["sid"] = sid
    return jsonify(dn=dn)


@app.post("/api/logout")
def logout():
    sid = session.pop("sid", None)
    SESS.pop(sid, None)
    CFG.pop(sid, None)
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    cred = SESS.get(session.get("sid"))
    if not cred:
        raise PermissionError(tr("Please log in."))
    return jsonify(dn=cred[0], base=BASE)


def in_base(dn):
    if not dn.lower().endswith(BASE.lower()):
        raise ValueError(tr("The DN is outside the base."))
    return dn


def kind_of(oc):
    oc = {x.lower() for x in oc}
    if oc & {"organizationalunit", "organization", "dcobject", "domain"}:
        return "ou"
    if "inetorgperson" in oc:
        return "user"
    if oc & {"groupofnames", "groupofuniquenames"}:
        return "group"
    return "other"


def show(v):
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return tr("‹binary, {n} bytes›", n=len(v))
    return str(v)


@app.get("/api/tree")
def tree():
    dn = in_base(request.args.get("dn") or BASE)
    c = conn()
    c.search(dn, "(objectClass=*)", search_scope=LEVEL, attributes=["objectClass", "hasSubordinates"])
    if c.result["result"] not in (0, 4):
        chk(c)
    out = []
    for e in c.response:
        if not e.get("dn"):
            continue
        a = e["attributes"]
        hs = a.get("hasSubordinates")
        out.append({"dn": e["dn"], "rdn": safe_rdn(e["dn"], decompose=False)[0],
                    "kind": kind_of(a.get("objectClass") or []),
                    "kids": hs is None or hs == [] or str(one(hs)).upper() == "TRUE"})
    return jsonify(sorted(out, key=lambda n: (n["kind"] != "ou", n["rdn"].lower())))


@app.get("/api/entry")
def entry():
    dn = in_base(request.args["dn"])
    c = conn()
    c.search(dn, "(objectClass=*)", search_scope=SCOPE_BASE, attributes=["*"])
    chk(c)
    e = next((x for x in c.response if x.get("dn")), None)
    if not e:
        raise ValueError(tr("Entry not found."))
    attrs = {}
    for k, vals in e["attributes"].items():
        vals = vals if isinstance(vals, list) else [vals]
        attrs[k] = [pw_label(v) if k.lower() == "userpassword" else show(v) for v in vals]
    order = sorted(attrs.items(), key=lambda kv: (kv[0].lower() != "objectclass", kv[0].lower()))
    parent = dn[len(safe_rdn(dn, decompose=False)[0]) + 1:]
    return jsonify(dn=dn, parent=parent, attrs=dict(order))


NAME = re.compile(r"^[A-Za-z][A-Za-z0-9;-]*$")


def set_password(c, dn, pw):
    """Passwort setzen. Bevorzugt per Password-Modify-Operation: Der Server hasht selbst mit dem Verfahren aus
    olcPasswordHash. Fallback: {SSHA}, das jeder OpenLDAP ohne Zusatzmodul kennt ({SSHA512} braucht pw-sha2)."""
    try:
        c.extend.standard.modify_password(dn, None, pw)
        if c.result["result"] == 0:
            return
    except Exception:
        pass
    c.modify(dn, {"userPassword": [(MODIFY_REPLACE, [hashed(HASHED_SALTED_SHA, pw)])]})
    chk(c)


def pw_label(v):
    m = re.match(rb"^\{([^}]+)\}", v if isinstance(v, bytes) else str(v).encode("utf-8", "replace"))
    return "{" + m.group(1).decode("ascii", "replace") + "} •••••" if m else "•••••"


@app.post("/api/entry")
def entry_create():
    d = request.json
    parent = in_base(d["parent"])
    ra, rv = d.get("ra", "").strip(), d.get("rv", "").strip()
    if not NAME.match(ra) or not rv:
        raise ValueError(tr("RDN attribute and RDN value are required."))
    oc = d.get("oc") or []
    if not oc:
        raise ValueError(tr("At least one object class is required."))
    attrs = {}
    for k, v in (d.get("attrs") or {}).items():
        if not NAME.match(k):
            raise ValueError(tr("Invalid attribute name: {name}", name=k))
        if v and k.lower() != "objectclass":
            attrs[k] = v
    if not any(k.lower() == ra.lower() for k in attrs):
        attrs[ra] = [rv]
    dn = f"{ra}={escape_rdn(rv)},{parent}"
    c = conn()
    c.add(dn, oc, attrs)
    chk(c)
    if d.get("password"):
        set_password(c, dn, d["password"])
    return jsonify(dn=dn)


@app.put("/api/entry")
def entry_update():
    d = request.json
    dn = in_base(d["dn"])
    ch = {}
    for k, v in (d.get("attrs") or {}).items():
        if not NAME.match(k):
            raise ValueError(tr("Invalid attribute name: {name}", name=k))
        ch[k] = [(MODIFY_REPLACE, v)]  # leere Liste entfernt das Attribut
    c = conn()
    if ch:
        c.modify(dn, ch)
        chk(c)
    if d.get("password"):
        set_password(c, dn, d["password"])
    return jsonify(ok=True)


@app.delete("/api/entry")
def entry_delete():
    dn = in_base(request.args["dn"])
    if dn.lower() == BASE.lower():
        raise ValueError(tr("The base cannot be deleted."))
    c = conn()
    dns = [dn]
    if request.args.get("recursive"):
        c.search(dn, "(objectClass=*)", search_scope=SUBTREE, attributes=[NO_ATTRIBUTES])
        dns = sorted((e["dn"] for e in c.response if e.get("dn")), key=lambda x: len(parse_dn(x)), reverse=True)
    for x in dns:  # tiefste Einträge zuerst
        c.delete(x)
        chk(c)
    return jsonify(deleted=len(dns))


@app.post("/api/move")
def entry_move():
    d = request.json
    dn, target = in_base(d["dn"]), in_base(d["target"])
    if dn.lower() == BASE.lower():
        raise ValueError(tr("The base cannot be moved."))
    if target.lower() == dn.lower() or target.lower().endswith("," + dn.lower()):
        raise ValueError(tr("The target must not be the entry itself or below it."))
    rdn = safe_rdn(dn, decompose=False)[0]
    c = conn()
    c.modify_dn(dn, rdn, new_superior=target)
    chk(c)
    return jsonify(dn=f"{rdn},{target}")


@app.get("/api/containers")
def containers():
    c = conn()
    c.search(BASE, "(|(objectClass=organizationalUnit)(objectClass=organization)(objectClass=dcObject)(objectClass=domain))",
             search_scope=SUBTREE, attributes=[NO_ATTRIBUTES])
    return jsonify(sorted((e["dn"] for e in c.response if e.get("dn")), key=str.lower))


def ldif_text(name, raw):
    """Eine LDIF-Zeile (RFC 2849): Base64 bei unsicheren Werten, Zeilenumbruch nach 76 Zeichen."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    try:
        s = raw.decode("ascii")
    except UnicodeDecodeError:
        s = None
    if raw == b"":
        line = f"{name}: "
    elif s is not None and s[0] not in " :<" and not s.endswith(" ") and not any(ch in s for ch in "\0\n\r"):
        line = f"{name}: {s}"
    else:
        line = f"{name}:: {base64.b64encode(raw).decode()}"
    parts, rest = [line[:76]], line[76:]
    while rest:
        parts.append(" " + rest[:75])
        rest = rest[75:]
    return "\n".join(parts)


@app.get("/api/export")
def ldif_export():
    dn = in_base(request.args["dn"])
    subtree = request.args.get("scope") == "subtree"
    with_pw = request.args.get("pw") == "1"
    c = conn()
    if subtree:
        ents = c.extend.standard.paged_search(dn, "(objectClass=*)", search_scope=SUBTREE,
                                              attributes=["*"], paged_size=500, generator=False)
    else:
        c.search(dn, "(objectClass=*)", search_scope=SCOPE_BASE, attributes=["*"])
        chk(c)
        ents = c.response
    ents = sorted((e for e in ents if e.get("dn")), key=lambda e: (len(parse_dn(e["dn"])), e["dn"].lower()))
    out = ["version: 1", ""]
    for e in ents:  # Eltern vor Kindern, damit sich die Datei wieder importieren lässt
        out.append(ldif_text("dn", e["dn"]))
        raw = e["raw_attributes"]
        for k in sorted(raw, key=lambda k: (k.lower() != "objectclass", k.lower())):
            if k.lower() == "userpassword" and not with_pw:
                continue
            out.extend(ldif_text(k, v) for v in raw[k])
        out.append("")
    fname = re.sub(r"[^A-Za-z0-9._-]", "_", safe_rdn(dn, decompose=False)[0]) + ".ldif"
    return Response("\n".join(out), mimetype="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


def _decode(b):
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b


def _parse_line(line):
    if line == "-":
        return "-", b""
    i = line.find(":")
    if i < 1:
        raise ValueError(tr("Invalid line: {line}", line=line[:60]))
    name, rest = line[:i].strip(), line[i + 1:]
    if rest.startswith(":"):
        try:
            return name, base64.b64decode(rest[1:].strip(), validate=True)
        except Exception:
            raise ValueError(tr("Invalid Base64 in {name}", name=name))
    if rest.startswith("<"):
        raise ValueError(tr("URL values (attr:< …) are not supported."))
    return name, (rest[1:] if rest.startswith(" ") else rest).encode("utf-8")


def parse_ldif(text):
    """Liest LDIF-Inhalte (add) und Änderungen (changetype add/modify/delete)."""
    lines = []
    for raw in text.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if raw.startswith(" ") and lines and lines[-1] != "":
            lines[-1] += raw[1:]  # Fortsetzungszeile
        else:
            lines.append(raw)
    recs, cur = [], []
    for ln in lines + [""]:
        if ln.startswith("#"):
            continue
        if ln.strip() == "":
            if cur:
                recs.append(cur)
                cur = []
        else:
            cur.append(ln)
    out = []
    for n, rec in enumerate(recs, 1):
        try:
            pairs = [_parse_line(ln) for ln in rec]
            if pairs[0][0].lower() == "version":
                pairs = pairs[1:]
            if not pairs:
                continue
            if pairs[0][0].lower() != "dn":
                raise ValueError(tr("The entry does not start with “dn:”."))
            dn, rest, ct = pairs[0][1].decode("utf-8").strip(), pairs[1:], "add"
            if rest and rest[0][0].lower() == "changetype":
                ct, rest = rest[0][1].decode("utf-8").strip().lower(), rest[1:]
            if ct == "add":
                attrs = {}
                for k, v in rest:
                    if v:
                        attrs.setdefault(k, []).append(_decode(v))
                out.append({"dn": dn, "op": "add", "attrs": attrs})
            elif ct == "delete":
                out.append({"dn": dn, "op": "delete"})
            elif ct == "modify":
                ops, op = [], None
                for k, v in rest:
                    kl = k.lower()
                    if k == "-":
                        if op:
                            ops.append(op)
                        op = None
                    elif kl in ("add", "delete", "replace") and (op is None or kl != op[1].lower()):
                        if op:
                            ops.append(op)
                        op = (kl, v.decode("utf-8").strip(), [])
                    elif op and kl == op[1].lower():
                        op[2].append(_decode(v))
                    else:
                        raise ValueError(tr("Unexpected line in modification: {name}", name=k))
                if op:
                    ops.append(op)
                out.append({"dn": dn, "op": "modify", "ops": ops})
            else:
                raise ValueError(tr("changetype “{ct}” is not supported (please move entries in the tree).", ct=ct))
        except ValueError as e:
            raise ValueError(tr("Entry {n}: {err}", n=n, err=e))
    return out


def apply_rec(c, r, skip_existing):
    dn = in_base(r["dn"])
    if r["op"] == "add":
        attrs = dict(r["attrs"])
        ocs = next((attrs.pop(k) for k in list(attrs) if k.lower() == "objectclass"), [])
        if not ocs:
            raise ValueError(tr("objectClass is missing."))
        c.add(dn, ocs, attrs)
        if skip_existing and c.result["result"] == 68:  # entryAlreadyExists
            return "skipped"
        chk(c)
    elif r["op"] == "modify":
        ch = {}
        for op, attr, vals in r["ops"]:
            m = {"add": MODIFY_ADD, "delete": MODIFY_DELETE, "replace": MODIFY_REPLACE}[op]
            ch.setdefault(attr, []).append((m, vals))
        c.modify(dn, ch)
        chk(c)
    else:
        if dn.lower() == BASE.lower():
            raise ValueError(tr("The base cannot be deleted."))
        c.delete(dn)
        chk(c)
    return "ok"


@app.post("/api/import")
def ldif_import():
    d = request.json or {}
    recs = parse_ldif(d.get("ldif", ""))
    if not recs:
        raise ValueError(tr("No entries found."))
    for r in recs:
        in_base(r["dn"])
    if not d.get("apply"):  # nur prüfen
        ops = {}
        for r in recs:
            ops[r["op"]] = ops.get(r["op"], 0) + 1
        return jsonify(count=len(recs), ops=ops)
    c = conn()
    res = {"total": len(recs), "ok": 0, "skipped": 0, "errors": []}
    for r in recs:
        try:
            st = apply_rec(c, r, bool(d.get("skip")))
            res["ok" if st == "ok" else "skipped"] += 1
        except (ValueError, LDAPException) as e:
            res["errors"].append(f'{r["dn"]}: {e}')
            if not d.get("cont"):
                break
    return jsonify(res)


# ---- Zugriffsrechte (olcAccess in cn=config) ----
# Verwaltet werden ausschließlich Regeln dieser Form. Sie stehen ganz oben und enden mit "by * break",
# geben also nur zusätzliche Rechte und lassen alle anderen Regeln unverändert weiterlaufen.
#   to dn.subtree="<Bereich>" by <dn.exact|group...exact>="<DN>" <write|manage> by * break
RULE = re.compile(r'^to\s+dn\.subtree="(?P<scope>[^"]+)"\s+by\s+(?P<who>dn\.exact|group(?:/\w+/\w+)?\.exact)'
                  r'="(?P<dn>[^"]+)"\s+(?P<lvl>write|manage)\s+by\s+\*\s+break\s*$')


def acl_strip(v):
    return re.sub(r"^\{\d+\}", "", v).strip()


def acl_rules(e):
    vals = e["attributes"].get("olcAccess") or []
    return [acl_strip(v) for v in ([vals] if isinstance(vals, str) else vals)]


def acl_open():
    """Verbindung zu cn=config: erst mit den gespeicherten Konfig-Zugangsdaten, sonst mit dem normalen Login."""
    sid = session.get("sid")
    main = SESS.get(sid)
    if not main:
        raise PermissionError(tr("Please log in."))
    cred = CFG.get(sid) or main
    try:
        c = Connection(Server(URI), user=cred[0], password=cred[1], auto_bind=True)
    except LDAPException:
        return None
    c.search("cn=config", f"(&(objectClass=olcDatabaseConfig)(olcSuffix={escape_filter_chars(BASE)}))",
             attributes=["olcAccess", "olcRootDN"])
    ents = [e for e in c.response if e.get("dn")]
    if not ents:
        if sid in CFG:
            raise ValueError(tr("No database with the suffix {base} was found in cn=config "
                                "(or the account may not read it).", base=BASE))
        return None
    return c, cred[0], ents[0]


def acl_write(c, e, rules):
    c.modify(e["dn"], {"olcAccess": [(MODIFY_REPLACE, rules)]})
    chk(c)


@app.post("/api/acl/login")
def acl_login():
    sid = session.get("sid")
    if not SESS.get(sid):
        raise PermissionError(tr("Please log in."))
    d = request.json
    dn = d["dn"].strip()
    if not d["password"]:
        raise ValueError(tr("Please enter a password."))
    try:
        Connection(Server(URI), user=dn, password=d["password"], auto_bind=True).unbind()
    except LDAPException as ex:
        raise ValueError(tr("Login as {dn} failed: {err}", dn=dn, err=ex))
    CFG[sid] = (dn, d["password"])
    return jsonify(ok=True)


@app.get("/api/acl")
def acl_get():
    o = acl_open()
    if not o:
        return jsonify(needLogin=True, dn=CFG_DN)
    _, who, e = o
    grants, others = [], []
    for r in acl_rules(e):
        m = RULE.match(r)
        if m:
            grants.append({"rule": r, "kind": "group" if m["who"].startswith("group") else "user",
                           "who": m["dn"], "scope": m["scope"], "level": m["lvl"]})
        else:
            others.append(r)
    return jsonify(needLogin=False, db=e["dn"], user=who, root=one(e["attributes"].get("olcRootDN")),
                   grants=grants, others=others)


@app.post("/api/acl/grant")
def acl_grant():
    d = request.json
    who, scope, lvl = d.get("who", "").strip(), (d.get("scope") or BASE).strip(), d.get("level")
    if lvl not in ("write", "manage"):
        raise ValueError(tr("Invalid level."))
    if "=" not in who or '"' in who or '"' in scope:
        raise ValueError(tr("Please choose a valid DN."))
    in_base(who)
    in_base(scope)
    m = conn()
    m.search(who, "(objectClass=*)", search_scope=SCOPE_BASE, attributes=["objectClass"])
    ents = [x for x in m.response if x.get("dn")]
    if not ents:
        raise ValueError(tr("This entry does not exist."))
    oc = {x.lower() for x in ents[0]["attributes"].get("objectClass") or []}
    if "groupofuniquenames" in oc:
        w = "group/groupOfUniqueNames/uniqueMember.exact"
    elif "groupofnames" in oc:
        w = "group/groupOfNames/member.exact"
    elif "posixgroup" in oc:
        raise ValueError(tr("posixGroup is not supported (its members are not DNs)."))
    else:
        w = "dn.exact"
    rule = f'to dn.subtree="{scope}" by {w}="{who}" {lvl} by * break'
    o = acl_open()
    if not o:
        raise ValueError(tr("Please log in with a cn=config account first."))
    c, _, e = o
    rules = acl_rules(e)
    if rule in rules:
        raise ValueError(tr("This permission already exists."))
    mine = [r for r in rules if RULE.match(r)]
    rest = [r for r in rules if not RULE.match(r)]
    acl_write(c, e, mine + [rule] + rest)
    return jsonify(ok=True)


@app.post("/api/acl/revoke")
def acl_revoke():
    rule = request.json["rule"]
    o = acl_open()
    if not o:
        raise ValueError(tr("Please log in with a cn=config account first."))
    c, _, e = o
    rules = acl_rules(e)
    if rule not in rules or not RULE.match(rule):
        raise ValueError(tr("Rule not found or not managed by this app."))
    rules.remove(rule)
    acl_write(c, e, rules)
    return jsonify(ok=True)


@app.get("/api/lookup")
def lookup():
    q = escape_filter_chars(request.args.get("q", "").strip())
    if len(q) < 2:
        return jsonify([])
    c = conn()
    c.search(BASE, "(&(|(objectClass=inetOrgPerson)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))"
                   f"(|(uid=*{q}*)(cn=*{q}*)(mail=*{q}*)))",
             search_scope=SUBTREE, attributes=["cn", "objectClass"], size_limit=20)
    out = []
    for e in c.response:
        if e.get("dn"):
            oc = {x.lower() for x in e["attributes"].get("objectClass") or []}
            out.append({"dn": e["dn"], "cn": one(e["attributes"].get("cn")),
                        "kind": "group" if oc & {"groupofnames", "groupofuniquenames"} else "user"})
    return jsonify(out)


@app.get("/api/search")
def search():
    terms = [escape_filter_chars(t) for t in request.args.get("q", "").split()][:5]
    if not terms or sum(len(t) for t in terms) < 2:
        return jsonify(items=[], more=False)
    users = "(objectClass=inetOrgPerson)"
    groups = "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))"
    kind = request.args.get("type", "all")
    cls = users if kind == "user" else groups if kind == "group" else f"(|{users}{groups})"
    # jeder Suchbegriff muss in irgendeinem der Felder vorkommen
    match = "".join(f"(|(uid=*{t}*)(cn=*{t}*)(sn=*{t}*)(givenName=*{t}*)(mail=*{t}*)(description=*{t}*))" for t in terms)
    c = conn()
    c.search(BASE, f"(&{cls}{match})", search_scope=SUBTREE,
             attributes=["cn", "uid", "mail", "objectClass"], size_limit=101)
    items = []
    for e in c.response:
        if not e.get("dn"):
            continue
        a = e["attributes"]
        oc = {x.lower() for x in a.get("objectClass") or []}
        items.append({"dn": e["dn"], "cn": one(a.get("cn")) or one(a.get("uid")), "mail": one(a.get("mail")),
                      "kind": "group" if oc & {"groupofnames", "groupofuniquenames", "posixgroup"} else "user"})
    items.sort(key=lambda i: (i["kind"] != "user", i["cn"].lower()))
    return jsonify(items=items[:100], more=len(items) > 100)


@app.get("/api/schema")
def schema():
    names = [x.strip() for x in request.args.get("oc", "").split(",") if x.strip()]
    c = conn()
    sc = c.server.schema
    if not sc:
        raise ValueError(tr("The schema could not be read."))
    found, seen = {}, set()

    def walk(n):  # Objektklasse samt allen Oberklassen auswerten
        if n.lower() in seen:
            return
        seen.add(n.lower())
        o = sc.object_classes.get(n)
        if not o:
            return
        for must, attrs in ((True, o.must_contain or []), (False, o.may_contain or [])):
            for a in attrs:
                t = sc.attribute_types.get(a)
                name = t.name[0] if t and t.name else a
                if name.lower() == "objectclass":
                    continue
                cur = found.get(name.lower())
                found[name.lower()] = {"name": name, "must": must or bool(cur and cur["must"]),
                                       "single": bool(t and t.single_value),
                                       "desc": (t.description or "") if t else ""}
        for sup in o.superior or []:
            walk(sup)

    for n in names:
        walk(n)
    return jsonify(sorted(found.values(), key=lambda a: (not a["must"], a["name"].lower())))


@app.get("/")
def index():
    title = APP_TITLE or ("Verzeichnis" if lang() == "de" else "Directory")
    return Response(PAGE.replace("{{TITLE}}", html_escape(title)), mimetype="text/html")


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}}</title>
<link rel="stylesheet" href="/static/style.css"></head><body>

<div id="login" class="hidden"><form id="lf">
  <h1 style="font:600 1.6rem var(--serif);margin:0">{{TITLE}}</h1>
  <label data-i18n>Username or full DN<input id="lu" required autocomplete="username" placeholder="cn=admin,dc=example,dc=org"></label>
  <label data-i18n>Password<input id="lp" type="password" required autocomplete="current-password"></label>
  <p class="err" id="le"></p>
  <button class="btn" data-i18n>Log in</button>
</form></div>

<div id="app" class="hidden">
<header><h1>{{TITLE}}</h1><span class="base" id="base"></span><button class="btn ghost" id="acl" data-i18n>Permissions</button><button class="btn ghost" id="imp" data-i18n>Import LDIF</button><button class="btn ghost" id="out" data-i18n>Log out</button></header>
<main>
  <div class="split" id="tree"><div id="left">
    <div class="sbar"><input id="sq" type="search" placeholder="Search users and groups" autocomplete="off" aria-label="Search" data-i18n-attr="placeholder,aria-label">
    <div class="seg" id="sf"><button type="button" data-t="all" aria-pressed="true" data-i18n>All</button><button type="button" data-t="user" aria-pressed="false" data-i18n>Users</button><button type="button" data-t="group" aria-pressed="false" data-i18n>Groups</button></div></div>
    <div class="list" id="tt"></div><div class="list hidden" id="sr"></div></div><div class="grip" id="gp" role="separator" aria-orientation="vertical" tabindex="0" title="Resize (double-click: automatic)" data-i18n-attr="title"></div><div class="detail" id="td"><div class="empty" data-i18n>Select an entry on the left.</div></div></div>
</main></div>

<dialog id="dlg"><form method="dialog" id="df"></form></dialog>
<div id="toast" role="status"></div>

<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const DE={
'Username or full DN':'Benutzername oder vollständiger DN','Password':'Passwort','Log in':'Anmelden','Permissions':'Zugriffsrechte',
'Import LDIF':'LDIF importieren','Log out':'Abmelden','Search users and groups':'Benutzer und Gruppen suchen','Search':'Suchen',
'All':'Alle','Users':'Benutzer','Groups':'Gruppen','Resize (double-click: automatic)':'Breite ändern (Doppelklick: automatisch)',
'Select an entry on the left.':'Wähle links einen Eintrag.','Request failed':'Anfrage fehlgeschlagen',
'Create below':'Darunter anlegen','Edit':'Bearbeiten','Export':'Exportieren','Move':'Verschieben','Delete':'Löschen',
'{0} values, sorted alphabetically':'{0} Werte, alphabetisch sortiert','Organizational unit':'Organisationseinheit',
'User':'Benutzer','Group':'Gruppe','Custom entry':'Eigener Eintrag',
'Available attributes – click to insert a line (* = required, dimmed = already present)':'Verfügbare Attribute – Klick fügt eine Zeile ein (* = Pflicht, abgeblendet = schon vorhanden)',
' (single value only)':' (nur ein Wert)','Create entry':'Eintrag anlegen','below {0}':'unter {0}','Type':'Typ',
'RDN attribute':'RDN-Attribut','RDN value':'RDN-Wert','Object classes (comma-separated)':'Objektklassen (mit Komma getrennt)',
'More attributes (one line per value: name: value)':'Weitere Attribute (eine Zeile pro Wert: name: wert)',
'Password (optional)':'Passwort (optional)','Edit entry':'Eintrag bearbeiten',
'Attributes (one line per value; missing lines are removed)':'Attribute (eine Zeile pro Wert; fehlende Zeilen werden entfernt)',
'Sorts the values within each attribute alphabetically':'Sortiert die Werte innerhalb jedes Attributs alphabetisch',
'Sort values':'Werte sortieren','New password':'Neues Passwort','Leave empty to keep it':'Leer lassen, um es zu behalten',
'Move entry':'Eintrag verschieben','New parent entry':'Neuer übergeordneter Eintrag','Move entry?':'Eintrag verschieben?','Moved':'Verschoben',
'Really delete this entry?':'Eintrag wirklich löschen?',
'The entry has child entries. Delete everything below it as well?':'Der Eintrag hat Unterelemente. Alles darunter ebenfalls löschen?',
'Deleted':'Gelöscht','Session expired':'Sitzung abgelaufen','Export failed':'Export fehlgeschlagen','Export as LDIF':'Als LDIF exportieren',
'This entry only':'Nur diesen Eintrag','Entry with all child entries':'Eintrag mit allen Unterelementen',
'Include password hashes (userPassword)':'Passwort-Hashes (userPassword) einschließen','Export downloaded':'Export heruntergeladen',
'Choose file':'Datei wählen','or paste LDIF':'oder LDIF einfügen','Skip existing entries':'Vorhandene Einträge überspringen',
'Continue with the next entry on errors':'Bei Fehlern mit dem nächsten Eintrag fortfahren','Check':'Prüfen',
'{0} of {1} imported, {2} skipped, {3} errors:':'{0} von {1} importiert, {2} übersprungen, {3} Fehler:',
'{0} imported':'{0} importiert',', {0} skipped':', {0} übersprungen','Import':'Importieren',
'to create':'neu anzulegen','to change':'zu ändern','to delete':'zu löschen','{0} entries recognized: ':'{0} Einträge erkannt: ',
'Only the first 100 results. Please refine your search.':'Nur die ersten 100 Treffer. Bitte genauer suchen.','No results.':'Keine Treffer.',
'Loading …':'Lade …','Close':'Schließen',
'Permissions are stored in the server configuration (cn=config). You need an account with write access to it, e.g. cn=admin,cn=config. The credentials are kept only in this session’s memory.':'Zugriffsrechte stehen in der Server-Konfiguration (cn=config). Dafür brauchst du ein Konto mit Schreibrecht darauf, z. B. cn=admin,cn=config. Die Zugangsdaten bleiben nur im Speicher dieser Sitzung.',
'Configuration DN':'Konfigurations-DN','Scope: {0}':'Bereich: {0}','Revoke':'Entziehen','Database: {0}':'Datenbank: {0}',
'Configuration account: {0}':'Konfigurations-Konto: {0}','Root DN (always has full rights): {0}':'Root-DN (hat immer volle Rechte): {0}',
'Write permissions':'Schreibrechte','No additional write permissions granted yet.':'Noch keine zusätzlichen Schreibrechte vergeben.',
'Grant new':'Neu vergeben','User or group':'Benutzer oder Gruppe','Type a name or paste a DN':'Name tippen oder DN einfügen',
'Scope':'Bereich','Level':'Stufe','write: read and write':'write: Lesen und Schreiben','manage: full administration':'manage: volle Verwaltung',
'Grant permission':'Recht vergeben','Other server rules (display only, not modified)':'Weitere Regeln des Servers (nur Anzeige, werden nicht verändert)',
'Permissions take effect immediately. The rules are placed at the very top and leave all other server rules unchanged. Anyone who receives write permissions logs in here with their own DN.':'Die Rechte gelten sofort. Die Regeln stehen ganz oben und lassen alle anderen Regeln des Servers unverändert weiterlaufen. Wer Schreibrechte erhält, meldet sich hier mit dem eigenen DN an.',
'Permission granted':'Recht vergeben','Revoke this permission?':'Dieses Recht entziehen?','Permission revoked':'Recht entzogen',
'Cancel':'Abbrechen','Save':'Speichern','Saved':'Gespeichert'};
// Sprache: Browsersprache (Deutsch oder Englisch), sonst Englisch; ?lang=de|en überschreibt (zum Testen)
const LANG=(()=>{
  const q=new URLSearchParams(location.search).get('lang');if(q==='de'||q==='en')return q;
  for(const l of (navigator.languages&&navigator.languages.length?navigator.languages:[navigator.language||'en'])){
    const c=String(l).toLowerCase();if(c.startsWith('de'))return 'de';if(c.startsWith('en'))return 'en'}
  return 'en';
})();
const t=(s,...a)=>{const r=LANG==='de'&&DE[s]!==undefined?DE[s]:s;return a.length?r.replace(/\{(\d+)\}/g,(m,i)=>a[i]):r};
function applyI18n(){
  document.documentElement.lang=LANG;
  document.querySelectorAll('[data-i18n]').forEach(el=>{for(const n of el.childNodes)if(n.nodeType===3&&n.data.trim()){n.data=n.data.replace(n.data.trim(),t(n.data.trim()));break}});
  document.querySelectorAll('[data-i18n-attr]').forEach(el=>el.dataset.i18nAttr.split(',').forEach(a=>el.setAttribute(a,t(el.getAttribute(a)))));
}
applyI18n();

let BASEDN='',ME='',cur=null,kids={},open=new Set(),sel='';
async function api(p,m='GET',b){
  const r=await fetch('/api/'+p,{method:m,headers:{'Content-Type':'application/json','Accept-Language':LANG},body:b?JSON.stringify(b):undefined});
  const d=await r.json().catch(()=>({}));
  if(r.status===401&&p!=='login'){show(false);throw new Error(d.error)}
  if(!r.ok)throw new Error(d.error||t('Request failed'));
  return d;
}
function toast(t){const e=$('#toast');e.textContent=t;e.classList.add('on');setTimeout(()=>e.classList.remove('on'),2200)}
function show(on){$('#login').classList.toggle('hidden',on);$('#app').classList.toggle('hidden',!on)}

$('#lf').onsubmit=async e=>{e.preventDefault();$('#le').textContent='';
  try{await api('login','POST',{user:$('#lu').value,password:$('#lp').value});$('#lp').value='';await start()}
  catch(x){$('#le').textContent=x.message}};
$('#out').onclick=async()=>{await api('logout','POST');show(false)};
$('#imp').onclick=()=>importForm();
$('#acl').onclick=()=>aclForm();
$('#sq').oninput=()=>{clearTimeout(sTimer);sTimer=setTimeout(runSearch,250)};
$('#sq').onkeydown=e=>{
  if(e.key==='Escape'){e.target.value='';runSearch()}
  if(e.key==='Enter'){const f=$('#sr .res');if(f)f.click()}
};
$('#sf').querySelectorAll('button').forEach(b=>b.onclick=()=>{sType=b.dataset.t;$('#sf').querySelectorAll('button').forEach(x=>x.setAttribute('aria-pressed',x===b));runSearch()});

async function start(){
  const m=await api('me');BASEDN=m.base;ME=m.dn;TPL.group.x='uniqueMember: '+ME;$('#base').textContent=m.base;show(true);await load();
}
async function load(){kids={};if(!sel)sel=BASEDN;renderTree();showEntry(sel);if(searchActive())runSearch()}
const TW_MIN=200,TW_MAX=600;
function treeManual(){try{return !!localStorage.getItem('tw2')}catch(e){return false}}
function autoWidth(){ // Spalte an den längsten sichtbaren Eintrag anpassen, solange nicht von Hand verstellt
  if(treeManual()||$('#tt').classList.contains('hidden'))return;
  const T=$('#tt'),L=T.getBoundingClientRect().left;
  let need=0;
  T.querySelectorAll('.tb span').forEach(x=>{need=Math.max(need,x.getBoundingClientRect().right-L)});
  $('#tree').style.setProperty('--tw',Math.round(Math.min(Math.max(need+32,TW_MIN),TW_MAX))+'px');
}
async function fetchKids(dn){kids[dn]=await api('tree?dn='+encodeURIComponent(dn))}
function nodeHtml(n){
  const o=open.has(n.dn),ch=kids[n.dn]||[];
  return `<li><div class="tn${sel===n.dn?' sel':''}" data-dn="${esc(n.dn)}" data-kind="${n.kind}" ${n.dn===BASEDN?'':'draggable="true"'}><button class="tg" data-t="${esc(n.dn)}" ${n.kids?'':'disabled'} aria-label="${o?'Zuklappen':'Aufklappen'}" aria-expanded="${o}">${n.kids?(o?'▾':'▸'):''}</button><button class="tb k-${n.kind}" data-s="${esc(n.dn)}" title="${esc(n.dn)}"><span>${esc(n.rdn)}</span></button></div>${o&&ch.length?`<ul>${ch.map(nodeHtml).join('')}</ul>`:''}</li>`;
}
async function renderTree(){
  open.add(BASEDN);
  await Promise.all([...open].filter(d=>!kids[d]).map(d=>fetchKids(d).catch(e=>{open.delete(d);toast(e.message)})));
  const T=$('#tt');
  T.innerHTML='<ul>'+nodeHtml({dn:BASEDN,rdn:BASEDN,kind:'ou',kids:true})+'</ul>';
  T.querySelectorAll('.tg:not([disabled])').forEach(b=>b.onclick=()=>{const d=b.dataset.t;open.has(d)?open.delete(d):open.add(d);renderTree()});
  T.querySelectorAll('.tb').forEach(b=>b.onclick=()=>{sel=b.dataset.s;renderTree();showEntry(sel)});
  T.querySelectorAll('.tn').forEach(r=>{
    r.ondragstart=e=>{e.dataTransfer.setData('text/plain',r.dataset.dn);e.dataTransfer.effectAllowed='move'};
    if(r.dataset.kind!=='ou')return;
    r.ondragover=e=>{e.preventDefault();r.classList.add('drop')};
    r.ondragleave=()=>r.classList.remove('drop');
    r.ondrop=e=>{e.preventDefault();r.classList.remove('drop');const dn=e.dataTransfer.getData('text/plain');if(dn&&dn!==r.dataset.dn)moveEntry(dn,r.dataset.dn,true)};
  });
  autoWidth();
}
async function showEntry(dn){
  const D=$('#td');
  try{
    const e=cur=await api('entry?dn='+encodeURIComponent(dn)),base=dn.toLowerCase()===BASEDN.toLowerCase();
    D.innerHTML=`<h2>${esc(dn.split(',')[0])}</h2><span class="dn">${esc(dn)}</span>
    <div class="acts"><button class="btn" id="b-new">${t('Create below')}</button><button class="btn ghost" id="b-ed">${t('Edit')}</button><button class="btn ghost" id="b-ex">${t('Export')}</button>${base?'':'<button class="btn ghost" id="b-mv">'+t('Move')+'</button><button class="btn bad" id="b-del">'+t('Delete')+'</button>'}</div>
    <dl>${Object.entries(e.attrs).map(([k,v])=>`<dt>${esc(k)}</dt><dd>${valHtml(k,v)}</dd>`).join('')}</dl>`;
    $('#b-new').onclick=()=>createForm(e.dn);
    $('#b-ed').onclick=()=>editForm(e);
    $('#b-ex').onclick=()=>exportForm(e);
    if(!base){$('#b-mv').onclick=()=>moveForm(e);$('#b-del').onclick=()=>deleteEntry(e)}
  }catch(x){D.innerHTML=`<p class="err">${esc(x.message)}</p>`}
}
const collator=new Intl.Collator(undefined,{sensitivity:'base',numeric:true});
function valHtml(k,v){ // mehrwertige Attribute alphabetisch anzeigen, lange Listen scrollbar
  const vals=v.length>1&&k.toLowerCase()!=='objectclass'?[...v].sort(collator.compare):v;
  const h=vals.map(esc).join('<br>');
  return v.length>8?`<div class="many">${h}</div><span class="hint">${t('{0} values, sorted alphabetically',v.length)}</span>`:h;
}
function parseAttrs(t){const o={};t.split('\n').forEach(l=>{const i=l.indexOf(':');if(i<1)return;const k=l.slice(0,i).trim(),v=l.slice(i+1).trim();if(v)(o[k]=o[k]||[]).push(v)});return o}

const TPL={
  ou:{t:t('Organizational unit'),oc:'organizationalUnit',rdn:'ou',x:''},
  user:{t:t('User'),oc:'inetOrgPerson',rdn:'uid',x:'cn: \nsn: \ngivenName: \nmail: '},
  group:{t:t('Group'),oc:'groupOfUniqueNames',rdn:'cn',x:'uniqueMember: '+ME},
  own:{t:t('Custom entry'),oc:'',rdn:'cn',x:''}};
function ocOf(t){return Object.entries(parseAttrs(t)).filter(([k])=>k.toLowerCase()==='objectclass').flatMap(([,v])=>v)}
function attrHelper(box,ta,ocs,extra){
  let key='',data=[],tm;
  const draw=()=>{
    if(!data.length){box.innerHTML='';return}
    const have=new Set(Object.keys(parseAttrs(ta.value)).map(k=>k.toLowerCase()));
    box.innerHTML=`<span class="hint">${t('Available attributes – click to insert a line (* = required, dimmed = already present)')}</span><div class="chips">${data.map(a=>`<button type="button" class="chip${a.must?' must':''}${have.has(a.name.toLowerCase())?' have':''}" data-n="${esc(a.name)}" title="${esc((a.desc||'')+(a.single?t(' (single value only)'):''))}">${esc(a.name)}${a.must?' *':''}</button>`).join('')}</div>`;
    box.querySelectorAll('.chip').forEach(b=>b.onclick=()=>{const v=ta.value.replace(/\s+$/,'');ta.value=(v?v+'\n':'')+b.dataset.n+': ';ta.focus();ta.selectionStart=ta.selectionEnd=ta.value.length;draw()});
  };
  const run=async()=>{
    const l=ocs(),k=l.join(',').toLowerCase();
    if(k!==key){key=k;data=[];if(l.length){try{data=await api('schema?oc='+encodeURIComponent(l.join(',')))}catch(x){box.textContent=x.message;return}}}
    draw();
  };
  const later=()=>{clearTimeout(tm);tm=setTimeout(run,250)};
  ta.addEventListener('input',later);(extra||[]).forEach(e=>e.addEventListener('input',later));
  run();
}
function createForm(parent){
  dialog(`<h2>${t('Create entry')}</h2><span class="dn">${t('below {0}',esc(parent))}</span>
  <label>${t('Type')}<select name="tpl">${Object.entries(TPL).map(([k,v])=>`<option value="${k}">${v.t}</option>`).join('')}</select></label>
  <div class="two"><label>${t('RDN attribute')}<input name="ra" required></label><label>${t('RDN value')}<input name="rv" required></label></div>
  <label>${t('Object classes (comma-separated)')}<input name="oc" required></label>
  <label>${t('More attributes (one line per value: name: value)')}<textarea name="x" rows="5" spellcheck="false"></textarea></label>
  <div class="attrs"></div>
  <label>${t('Password (optional)')}<input name="pw" type="password" autocomplete="new-password"></label>`,
  async d=>{const r=await api('entry','POST',{parent,ra:d.ra,rv:d.rv,oc:d.oc.split(',').map(x=>x.trim()).filter(Boolean),attrs:parseAttrs(d.x),password:d.pw});open.add(parent);sel=r.dn});
  const f=$('#df'),fill=()=>{const t=TPL[f.elements.tpl.value];f.elements.ra.value=t.rdn;f.elements.oc.value=t.oc;f.elements.x.value=t.x};
  fill();
  attrHelper(f.querySelector('.attrs'),f.elements.x,()=>f.elements.oc.value.split(',').map(x=>x.trim()).filter(Boolean),[f.elements.oc]);
  f.elements.tpl.onchange=()=>{fill();f.elements.oc.dispatchEvent(new Event('input'))};
}
function editForm(e){
  const ed=Object.entries(e.attrs).filter(([k,v])=>!/^userpassword$/i.test(k)&&!v.some(x=>/^‹(binary|binär)/.test(x)));
  const lines=ed.flatMap(([k,v])=>v.map(x=>k+': '+x)).join('\n');
  dialog(`<h2>${t('Edit entry')}</h2><span class="dn">${esc(e.dn)}</span>
  <label>${t('Attributes (one line per value; missing lines are removed)')}<textarea name="x" rows="12" spellcheck="false">${esc(lines)}</textarea></label>
  <div><button type="button" class="btn ghost" id="sortv" title="${t('Sorts the values within each attribute alphabetically')}">${t('Sort values')}</button></div>
  <div class="attrs"></div>
  <label>${t('New password')}<input name="pw" type="password" autocomplete="new-password" placeholder="${t('Leave empty to keep it')}"></label>`,
  async d=>{
    const o={},n={},ch={};
    ed.forEach(([k,v])=>o[k.toLowerCase()]={k,v});
    Object.entries(parseAttrs(d.x)).forEach(([k,v])=>n[k.toLowerCase()]={k,v});
    new Set([...Object.keys(o),...Object.keys(n)]).forEach(l=>{const a=(o[l]||{v:[]}).v,b=(n[l]||{v:[]}).v;if(a.join('\n')!==b.join('\n'))ch[(o[l]||n[l]).k]=b});
    await api('entry','PUT',{dn:e.dn,attrs:ch,password:d.pw});sel=e.dn;
  });
  const f=$('#df');
  attrHelper(f.querySelector('.attrs'),f.elements.x,()=>ocOf(f.elements.x.value));
  $('#sortv').onclick=()=>{
    const ta=f.elements.x,g=new Map();
    ta.value.split('\n').forEach(l=>{const i=l.indexOf(':');if(i<1)return;const k=l.slice(0,i).trim(),v=l.slice(i+1).trim();if(!v)return;const key=k.toLowerCase();if(!g.has(key))g.set(key,{k,v:[]});g.get(key).v.push(v)});
    ta.value=[...g.values()].flatMap(({k,v})=>(k.toLowerCase()==='objectclass'?v:[...v].sort(collator.compare)).map(x=>k+': '+x)).join('\n');
    ta.dispatchEvent(new Event('input'));
  };
}
async function moveForm(e){
  const dn=e.dn.toLowerCase();
  const cs=(await api('containers')).filter(d=>d.toLowerCase()!==dn&&!d.toLowerCase().endsWith(','+dn));
  dialog(`<h2>${t('Move entry')}</h2><span class="dn">${esc(e.dn)}</span>
  <label>${t('New parent entry')}<select name="t">${cs.map(d=>`<option ${d===e.parent?'selected':''}>${esc(d)}</option>`).join('')}</select></label>`,
  async d=>{const r=await api('move','POST',{dn:e.dn,target:d.t});open.add(d.t);sel=r.dn});
}
async function moveEntry(dn,target,ask){
  if(ask&&!confirm(t('Move entry?')+'\n\n'+dn+'\n→ '+target))return;
  try{const r=await api('move','POST',{dn,target});open.add(target);sel=r.dn;toast(t('Moved'));await load()}catch(x){toast(x.message)}
}
async function deleteEntry(e){
  if(!confirm(t('Really delete this entry?')+'\n\n'+e.dn))return;
  const u='entry?dn='+encodeURIComponent(e.dn);
  try{
    try{await api(u,'DELETE')}
    catch(x){if(!/NonLeaf/i.test(x.message))throw x;
      if(!confirm(t('The entry has child entries. Delete everything below it as well?')))return;
      await api(u+'&recursive=1','DELETE')}
    sel=e.parent;toast(t('Deleted'));await load();
  }catch(x){toast(x.message)}
}

async function download(path){
  const r=await fetch('/api/'+path,{headers:{'Accept-Language':LANG}});
  if(r.status===401){show(false);throw new Error(t('Session expired'))}
  if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.error||t('Export failed'))}
  const m=/filename="([^"]+)"/.exec(r.headers.get('Content-Disposition')||'');
  const a=document.createElement('a');a.href=URL.createObjectURL(await r.blob());a.download=m?m[1]:'export.ldif';
  document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),4000);
}
function exportForm(e){
  dialog(`<h2>${t('Export as LDIF')}</h2><span class="dn">${esc(e.dn)}</span>
  <label class="chk"><input type="radio" name="scope" value="base"> ${t('This entry only')}</label>
  <label class="chk"><input type="radio" name="scope" value="subtree" checked> ${t('Entry with all child entries')}</label>
  <label class="chk"><input type="checkbox" name="pw"> ${t('Include password hashes (userPassword)')}</label>`,
  async d=>{await download('export?dn='+encodeURIComponent(e.dn)+'&scope='+d.scope+'&pw='+(d.pw?1:0));return t('Export downloaded')},null,t('Export'));
}
function importForm(){
  dialog(`<h2>${t('Import LDIF')}</h2>
  <label>${t('Choose file')}<input type="file" id="imf" accept=".ldif,.txt,text/plain"></label>
  <label>${t('or paste LDIF')}<textarea name="ldif" rows="10" spellcheck="false"></textarea></label>
  <label class="chk"><input type="checkbox" name="skip" checked> ${t('Skip existing entries')}</label>
  <label class="chk"><input type="checkbox" name="cont"> ${t('Continue with the next entry on errors')}</label>
  <div><button type="button" class="btn ghost" id="imchk">${t('Check')}</button> <span class="hint" id="imsg"></span></div>`,
  async d=>{
    const r=await api('import','POST',{ldif:d.ldif,apply:true,skip:!!d.skip,cont:!!d.cont});
    if(r.errors.length){await load();throw new Error(t('{0} of {1} imported, {2} skipped, {3} errors:',r.ok,r.total,r.skipped,r.errors.length)+'\n'+r.errors.slice(0,5).join('\n')+(r.errors.length>5?'\n…':''))}
    return t('{0} imported',r.ok)+(r.skipped?t(', {0} skipped',r.skipped):'');
  },null,t('Import'));
  const f=$('#df'),names={add:t('to create'),modify:t('to change'),delete:t('to delete')};
  $('#imf').onchange=async e=>{const t=e.target.files[0];if(t)f.elements.ldif.value=await t.text()};
  $('#imchk').onclick=async()=>{
    try{const r=await api('import','POST',{ldif:f.elements.ldif.value});$('#imsg').textContent=t('{0} entries recognized: ',r.count)+Object.entries(r.ops).map(([k,v])=>v+' '+names[k]).join(', ')}
    catch(x){$('#imsg').textContent=x.message}
  };
}
let sTimer=0,sSeq=0,sType='all';
const searchActive=()=>$('#sq').value.trim().length>=2;
function reveal(dn){ // alle übergeordneten Einträge im Baum aufklappen
  const p=dn.split(/(?<!\\),/);
  for(let i=1;i<p.length;i++){const a=p.slice(i).join(',');if(a.toLowerCase().endsWith(BASEDN.toLowerCase()))open.add(a)}
}
async function runSearch(){
  const q=$('#sq').value.trim(),R=$('#sr');
  $('#tt').classList.toggle('hidden',q.length>=2);R.classList.toggle('hidden',q.length<2);
  if(q.length<2){renderTree();return}
  if(!treeManual())$('#tree').style.setProperty('--tw','340px'); // Platz für die Trefferliste
  const my=++sSeq;
  try{
    const r=await api('search?q='+encodeURIComponent(q)+'&type='+sType);
    if(my!==sSeq)return;
    R.innerHTML=r.items.length?r.items.map(i=>`<button class="res k-${i.kind}${i.dn===sel?' sel':''}" data-dn="${esc(i.dn)}"><span class="rw"><strong>${esc(i.cn)}</strong>${i.mail?`<span class="rm">${esc(i.mail)}</span>`:''}<span class="dn">${esc(i.dn)}</span></span></button>`).join('')+(r.more?'<div class="empty">'+t('Only the first 100 results. Please refine your search.')+'</div>':''):'<div class="empty">'+t('No results.')+'</div>';
    R.querySelectorAll('.res').forEach(b=>b.onclick=()=>{sel=b.dataset.dn;reveal(sel);R.querySelectorAll('.res').forEach(x=>x.classList.toggle('sel',x===b));showEntry(sel)});
  }catch(x){if(my===sSeq)R.innerHTML=`<p class="err">${esc(x.message)}</p>`}
}
function aclForm(){
  dialog('<h2>'+t('Permissions')+'</h2><div id="aclbox"><span class="hint">'+t('Loading …')+'</span></div>',async()=>false,null,t('Close'));
  $('#df').addEventListener('keydown',e=>{if(e.key==='Enter'&&e.target.tagName==='INPUT')e.preventDefault()});
  aclRender();
}
async function aclRender(){
  const B=$('#aclbox');
  let r;
  try{r=await api('acl')}catch(x){B.innerHTML=`<p class="err">${esc(x.message)}</p>`;return}
  if(r.needLogin){
    B.innerHTML=`<span class="hint">${t('Permissions are stored in the server configuration (cn=config). You need an account with write access to it, e.g. cn=admin,cn=config. The credentials are kept only in this session’s memory.')}</span>
    <label>${t('Configuration DN')}<input id="cd" value="${esc(r.dn)}"></label>
    <label>${t('Password')}<input id="cp" type="password" autocomplete="off"></label>
    <p class="err" id="ce"></p><div><button type="button" class="btn" id="cl">${t('Log in')}</button></div>`;
    const go=async()=>{try{await api('acl/login','POST',{dn:$('#cd').value,password:$('#cp').value});aclRender()}catch(x){$('#ce').textContent=x.message}};
    $('#cl').onclick=go;$('#cp').onkeydown=e=>{if(e.key==='Enter')go()};
    return;
  }
  const rows=r.grants.map(g=>`<div class="grant"><span class="tag">${g.kind==='group'?t('Group'):t('User')}</span><span class="dn">${esc(g.who)}${g.scope.toLowerCase()===BASEDN.toLowerCase()?'':'<br>'+t('Scope: {0}',esc(g.scope))}</span><span class="tag">${esc(g.level)}</span><button type="button" class="btn bad" data-r="${esc(g.rule)}">${t('Revoke')}</button></div>`).join('');
  B.innerHTML=`<span class="hint">${t('Database: {0}',esc(r.db))}<br>${t('Configuration account: {0}',esc(r.user))}${r.root?'<br>'+t('Root DN (always has full rights): {0}',esc(r.root)):''}</span>
  <h3>${t('Write permissions')}</h3>
  ${rows||'<span class="hint">'+t('No additional write permissions granted yet.')+'</span>'}
  <h3>${t('Grant new')}</h3>
  <label>${t('User or group')}<input id="aw" list="awl" placeholder="${t('Type a name or paste a DN')}" autocomplete="off"><datalist id="awl"></datalist></label>
  <div class="two"><label>${t('Scope')}<input id="as" value="${esc(BASEDN)}"></label>
  <label>${t('Level')}<select id="al"><option value="write">${t('write: read and write')}</option><option value="manage">${t('manage: full administration')}</option></select></label></div>
  <p class="err" id="ae"></p><div><button type="button" class="btn" id="ag">${t('Grant permission')}</button></div>
  <details><summary class="hint">${t('Other server rules (display only, not modified)')}</summary><pre>${esc(r.others.join('\n\n')||'–')}</pre></details>
  <span class="hint">${t('Permissions take effect immediately. The rules are placed at the very top and leave all other server rules unchanged. Anyone who receives write permissions logs in here with their own DN.')}</span>`;
  let tm;
  $('#aw').oninput=()=>{clearTimeout(tm);tm=setTimeout(async()=>{
    const q=$('#aw').value.trim();if(q.length<2||q.includes('='))return;
    try{const l=await api('lookup?q='+encodeURIComponent(q));$('#awl').innerHTML=l.map(x=>`<option value="${esc(x.dn)}">${esc(x.cn)} (${x.kind==='group'?t('Group'):t('User')})</option>`).join('')}catch(x){}
  },250)};
  $('#ag').onclick=async()=>{
    try{await api('acl/grant','POST',{who:$('#aw').value,scope:$('#as').value,level:$('#al').value});toast(t('Permission granted'));aclRender()}
    catch(x){$('#ae').textContent=x.message}
  };
  B.querySelectorAll('[data-r]').forEach(b=>b.onclick=async()=>{
    if(!confirm(t('Revoke this permission?')))return;
    try{await api('acl/revoke','POST',{rule:b.dataset.r});toast(t('Permission revoked'));aclRender()}catch(x){toast(x.message)}
  });
}
function dialog(html,onSave,onDelete,ok){
  const f=$('#df');
  f.innerHTML=html+`<p class="err" id="de"></p><div class="acts">${onDelete?'<button type="button" class="btn bad" id="dd">'+t('Delete')+'</button><span class="sp"></span>':''}<button type="button" class="btn ghost" id="dc">${t('Cancel')}</button><button class="btn">${ok||t('Save')}</button></div>`;
  $('#dc').onclick=()=>$('#dlg').close();
  if(onDelete)$('#dd').onclick=async()=>{if(!confirm(t('Really delete this entry?')))return;try{await onDelete();$('#dlg').close();toast(t('Deleted'));load()}catch(x){$('#de').textContent=x.message}};
  f.onsubmit=async e=>{e.preventDefault();try{const m=await onSave(Object.fromEntries(new FormData(f)));$('#dlg').close();if(m!==false)toast(typeof m==='string'?m:t('Saved'));load()}catch(x){$('#de').textContent=x.message}};
  $('#dlg').showModal();
}

(()=>{
  const S=$('#tree'),G=$('#gp');
  try{const w=parseInt(localStorage.getItem('tw2'));if(w>=160&&w<=600)S.style.setProperty('--tw',w+'px')}catch(e){}
  const set=x=>{const w=Math.max(160,Math.min(x,600,S.clientWidth-360))+'px';S.style.setProperty('--tw',w);try{localStorage.setItem('tw2',w)}catch(e){}};
  G.onpointerdown=e=>{G.setPointerCapture(e.pointerId);G.classList.add('on')};
  G.onpointermove=e=>{if(G.classList.contains('on'))set(e.clientX-S.getBoundingClientRect().left-8)};
  G.onpointerup=()=>G.classList.remove('on');
  G.ondblclick=()=>{try{localStorage.removeItem('tw2')}catch(e){};autoWidth()};
  G.onkeydown=e=>{const w=$('#tt').offsetWidth;if(e.key==='ArrowLeft')set(w-20);if(e.key==='ArrowRight')set(w+20)};
})();
api('me').then(start).catch(()=>show(false));
</script></body></html>
"""

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 8080)))
