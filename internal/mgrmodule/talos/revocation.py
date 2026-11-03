"""The agent CA's revocation list (plan 04, step 3).

- The revoked set: one config-key entry per revoked serial,
  `cephadm-talos/revoked/<serial>` (decimal) with `{not_after, reason}`,
  outside mgr/ and apart from the ledger, so no takeover's cutoff drops one.
  Written before any certificate or key it concerns is deleted, never
  changed afterwards; entries whose not_after passed a day ago are pruned by
  the active module.
- The list: an X.509 CRL the active module issues whenever the revoked set
  differs from its last list's and at least daily, valid for 7 days. Its CRL
  number is the leadership's mgr map epoch times 2^32 plus a counter of the
  lists issued in that leadership, so a predecessor's list always has a lower
  number. Published in chunks with a manifest (`cephadm-talos/crl/<number>/<i>`,
  `cephadm-talos/crl/manifest`), as the cluster state records are.
"""
import base64
import datetime
import hashlib
import json
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

REVOKED_PREFIX = 'cephadm-talos/revoked/'
CRL_PREFIX = 'cephadm-talos/crl/'
CRL_MANIFEST = CRL_PREFIX + 'manifest'
CRL_KEY_RE = re.compile(r'\Acephadm-talos/crl/(\d{1,40})/(\d{1,6})\Z')
SERIAL_RE = re.compile(r'\A[1-9][0-9]{0,49}\Z')
# base64 characters per chunk: below the bridge's value limit (48 KiB)
CHUNK = 32 << 10
MANIFEST_SCHEMA = 1
# the longest a list is valid (the agents refuse longer ones), and how often
# an unchanged set is issued again
MAX_VALID_HOURS = 168
REISSUE = datetime.timedelta(days=1)
# an entry is kept a day past its not_after, then pruned
PRUNE_AFTER = datetime.timedelta(days=1)
# a revocation without --until is kept as long as the longest lifetime issued
REVOKE_YEARS = 3
DEADLINE = 10.0

Mon = Callable[[Dict[str, Any], float], Optional[Tuple[int, str, str]]]


class CRLError(Exception):
    pass


def iso(t: datetime.datetime) -> str:
    return t.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_iso(s: Any) -> datetime.datetime:
    if not isinstance(s, str):
        raise ValueError('not a time')
    t = datetime.datetime.fromisoformat(s.replace('Z', '+00:00'))
    return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)


def not_after(cert: Any) -> datetime.datetime:
    # the Ceph image's cryptography may predate the *_utc attributes (naive UTC then)
    return getattr(cert, 'not_valid_after_utc', None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def add_years(t: datetime.datetime, years: int) -> datetime.datetime:
    try:
        return t.replace(year=t.year + years)
    except ValueError:  # February 29
        return t.replace(year=t.year + years, month=3, day=1)


def entry(until: datetime.datetime, reason: str) -> str:
    return json.dumps({'not_after': iso(until), 'reason': reason}, sort_keys=True)


def parse_serial(s: str) -> int:
    """A serial as the operator gives it: decimal, or hex with 0x or with colons
    (as openssl prints it)."""
    s = s.strip()
    try:
        if s.lower().startswith('0x'):
            n = int(s[2:], 16)
        elif ':' in s:
            n = int(s.replace(':', ''), 16)
        else:
            n = int(s, 10)
    except ValueError:
        raise ValueError('serial %r: decimal, 0x<hex> or colon-separated hex' % s)
    if n <= 0 or n.bit_length() > 160:
        raise ValueError('serial %r is not a certificate serial' % s)
    return n


def parse_revoked(dump: Dict[str, str], now: datetime.datetime) -> Tuple[Dict[int, datetime.datetime], List[str]]:
    """The revoked set from a dump of REVOKED_PREFIX: serial -> not_after for the
    entries kept, and the keys of the ones to prune. A malformed entry is
    kept as revoked for REVOKE_YEARS from now (never dropped by a reader)."""
    out: Dict[int, datetime.datetime] = {}
    old: List[str] = []
    for k, v in dump.items():
        if not k.startswith(REVOKED_PREFIX):
            continue
        s = k[len(REVOKED_PREFIX):]
        if not SERIAL_RE.match(s):
            continue
        try:
            until = parse_iso(json.loads(v)['not_after'])
        except (ValueError, KeyError, TypeError):
            until = now + datetime.timedelta(days=365 * REVOKE_YEARS)
        if until + PRUNE_AFTER < now:
            old.append(k)
            continue
        out[int(s)] = until
    return out, old


def read_revoked(mon: Mon, now: datetime.datetime) -> Tuple[Dict[int, datetime.datetime], List[str]]:
    res = mon({'prefix': 'config-key dump', 'key': REVOKED_PREFIX}, DEADLINE)
    if res is None or res[0] != 0:
        raise CRLError('cannot read the revoked set')
    try:
        dump = json.loads(res[1] or '{}')
    except ValueError:
        raise CRLError('cannot read the revoked set')
    return parse_revoked(dump if isinstance(dump, dict) else {}, now)


def cert_serial(pem: str) -> Tuple[int, datetime.datetime]:
    from cryptography import x509
    c = x509.load_pem_x509_certificate(pem.encode())
    return c.serial_number, not_after(c)


def check_cert(pem: Any, ca_cert_pem: bytes, fsid: str, role: str, host: str) -> Tuple[int, datetime.datetime]:
    """A certificate the leader passes to be revoked: one the agent CA issued
    to <role>/<host> of this cluster. Raises ValueError otherwise."""
    from cryptography import x509
    if not isinstance(pem, str) or len(pem) > 8192:
        raise ValueError('not a certificate')
    try:
        c = x509.load_pem_x509_certificate(pem.encode())
        ca = x509.load_pem_x509_certificate(ca_cert_pem)
        c.verify_directly_issued_by(ca)
    except Exception:
        raise ValueError('not issued by the agent CA')
    try:
        uris = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound:
        uris = []
    ids = [u for u in uris if u.lower().startswith('cephadm-talos:')]
    if ids != ['cephadm-talos://%s/%s/%s' % (fsid, role, host)]:
        raise ValueError('not the certificate of %s %s' % (role, host))
    return c.serial_number, not_after(c)


def issue_crl(ca_cert_pem: bytes, ca_key_pem: bytes, revoked: Dict[int, datetime.datetime], number: int,
              now: datetime.datetime, valid: datetime.timedelta) -> bytes:
    """The list (DER): every serial of the revoked set, signed with the agent CA's key."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from .bridge import authority_key_id
    ca = x509.load_pem_x509_certificate(ca_cert_pem)
    key = serialization.load_pem_private_key(ca_key_pem, password=None)
    b = (x509.CertificateRevocationListBuilder().issuer_name(ca.subject)
         .last_update(now).next_update(now + valid)
         .add_extension(x509.CRLNumber(number), critical=False)
         .add_extension(authority_key_id(ca), critical=False))  # type: ignore[arg-type]
    for serial in sorted(revoked):
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now).build())
    return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)  # type: ignore[arg-type]


def crl_number(der: bytes) -> int:
    from cryptography import x509
    return x509.load_der_x509_crl(der).extensions.get_extension_for_class(x509.CRLNumber).value.crl_number


def chunks(der: bytes, number: int) -> Tuple[Dict[str, str], str]:
    """The chunk entries of a list and its manifest."""
    enc = base64.b64encode(der).decode()
    parts = {'%s%d/%d' % (CRL_PREFIX, number, i): enc[o:o + CHUNK] for i, o in enumerate(range(0, len(enc), CHUNK))}
    manifest = {'schema': MANIFEST_SCHEMA, 'number': str(number), 'chunks': list(parts),
                'sha256': hashlib.sha256(der).hexdigest(), 'size': len(der)}
    return parts, json.dumps(manifest, sort_keys=True)


def read_manifest(raw: str) -> Dict[str, Any]:
    m = json.loads(raw)
    if not isinstance(m, dict) or m.get('schema') != MANIFEST_SCHEMA or not isinstance(m.get('number'), str) \
            or not m['number'].isdigit() or not isinstance(m.get('chunks'), list) or not m['chunks'] \
            or not isinstance(m.get('sha256'), str) or type(m.get('size')) is not int:
        raise ValueError('malformed CRL manifest')
    for c in m['chunks']:
        if not isinstance(c, str) or not CRL_KEY_RE.match(c) or CRL_KEY_RE.match(c).group(1) != m['number']:  # type: ignore[union-attr]
            raise ValueError('CRL chunk %r outside its number' % c)
    return m


def published(entries: Dict[str, str]) -> Optional[Tuple[int, bytes]]:
    """The published list (number, DER) from a dump of CRL_PREFIX, None without one."""
    raw = entries.get(CRL_MANIFEST)
    if raw is None:
        return None
    m = read_manifest(raw)
    der = base64.b64decode(''.join(entries[c] for c in m['chunks']), validate=True)
    if hashlib.sha256(der).hexdigest() != m['sha256'] or len(der) != m['size']:
        raise ValueError('the CRL does not match its manifest')
    return int(m['number']), der


class Issuer:
    """The lists of one leadership: their counter, the last one issued, and
    its publication."""

    def __init__(self, epoch: int) -> None:
        self.epoch = epoch
        self.counter = 0
        self.number = 0
        self.serials: Optional[Set[int]] = None
        self.at: Optional[datetime.datetime] = None
        self.der: Optional[bytes] = None
        self.published = False

    def due(self, revoked: Dict[int, datetime.datetime], now: datetime.datetime) -> bool:
        return self.serials is None or set(revoked) != self.serials or self.at is None or now - self.at >= REISSUE

    def tick(self, mon: Mon, ca_cert: bytes, revoked: Dict[int, datetime.datetime], stale: List[str],
             now: datetime.datetime, valid_hours: int) -> bool:
        """Prune, issue when due, publish; True when a new list was issued.
        Raises CRLError when it cannot issue or publish."""
        for k in stale:
            mon({'prefix': 'config-key rm', 'key': k}, DEADLINE)  # pruned again next time if unanswered
        res = mon({'prefix': 'config-key dump', 'key': CRL_PREFIX}, DEADLINE)
        if res is None or res[0] != 0:
            raise CRLError('cannot read the published list')
        try:
            entries = json.loads(res[1] or '{}')
            if not isinstance(entries, dict):
                raise ValueError('not an object')
        except ValueError:
            raise CRLError('cannot read the published list')
        try:
            m = read_manifest(entries[CRL_MANIFEST]) if CRL_MANIFEST in entries else None
        except (ValueError, KeyError):
            m = None
        theirs = int(m['number']) if m is not None else 0
        issued = False
        if self.due(revoked, now):
            key = mon({'prefix': 'config-key get', 'key': 'cephadm-talos/secrets/agent-ca.key'}, DEADLINE)
            if key is None or key[0] != 0 or not ca_cert:
                raise CRLError('the agent CA is not available')
            self.counter += 1
            number = (self.epoch << 32) + self.counter
            valid = datetime.timedelta(hours=max(1, min(MAX_VALID_HOURS, int(valid_hours))))
            self.der = issue_crl(ca_cert, key[1].encode(), revoked, number, now, valid)
            self.number, self.serials, self.at, self.published = number, set(revoked), now, False
            issued = True
        # published while the manifest has a lower number: a predecessor's late
        # write does not hide this list, and a successor's is never replaced
        if self.der is not None and theirs < self.number:
            parts, manifest = chunks(self.der, self.number)
            for k, v in list(parts.items()) + [(CRL_MANIFEST, manifest)]:
                w = mon({'prefix': 'config-key set', 'key': k, 'val': v}, DEADLINE)
                if w is None or w[0] != 0:
                    raise CRLError('the list %d was not published' % self.number)
            self.published = True
            # older numbers' chunks, after the manifest moved on
            for k in entries:
                mk = CRL_KEY_RE.match(k)
                if mk and int(mk.group(1)) < self.number:
                    mon({'prefix': 'config-key rm', 'key': k}, DEADLINE)
        return issued
