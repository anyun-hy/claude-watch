#!/usr/bin/env python3
"""Anonymous Net.Coffee GET transport with a private shared metadata cache."""
import argparse, contextlib, copy, datetime, fcntl, hashlib, ipaddress, json, os, re, signal, subprocess, tempfile, time
from pathlib import Path

ORIGIN = 'https://ip.net.coffee'
PROXY = 'http://127.0.0.1:7890'
METADATA_KINDS = frozenset(('lookup', 'geoip', 'risk'))
CACHE_TTL = 300
CACHE_MAX_BYTES = 8 * 1024 * 1024
CACHE_MAX_ENTRIES = 32

def _cache_root(cache_dir=None):
    return Path(cache_dir) if cache_dir is not None else Path.home() / 'Library/Application Support/ClaudeWatch/observations'

def _cache_name(key):
    return 'meta-' + hashlib.sha256(key.encode('ascii')).hexdigest()

def _valid_cache_key(key):
    if not isinstance(key, str): return False
    match = re.fullmatch(r'(lookup|geoip|risk|ipinfo):([0-9A-Fa-f:.]+)', key)
    if match:
        try: return ipaddress.ip_address(match[2]).is_global
        except ValueError: return False
    match = re.fullmatch(r'ripe-asn:([1-9][0-9]{0,9})', key)
    return bool(match and int(match[1]) <= 4_294_967_295)

@contextlib.contextmanager
def _cache_lock(root, key):
    if root.is_symlink(): raise ValueError('unsafe cache directory')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink(): raise ValueError('unsafe cache directory')
    root.chmod(0o700)
    lock = root / (_cache_name(key) + '.lock')
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)

def _read_cache(path):
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > CACHE_MAX_BYTES:
            return {}
        value = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(value, dict) or value.get('schema') != 1:
            return {}
        return value
    except (OSError, ValueError, UnicodeError):
        return {}

def _write_cache(path, value):
    value = {'schema': 1, **(value if isinstance(value, dict) else {})}
    raw = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    if len(raw.encode('utf-8')) > CACHE_MAX_BYTES:
        # A response that cannot fit is still returned to the caller, but is not
        # persisted and cannot evict a smaller known-good receipt.
        return
    fd, temporary = tempfile.mkstemp(prefix='.query-cache-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)

def _remove_if_prunable(path, now):
    """Delete one idle, non-cooling entry while holding its own lock."""
    lock = path.with_suffix('.lock')
    try:
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        return False
    try:
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: return False
        entry = _read_cache(path)
        failure = entry.get('failure') if isinstance(entry, dict) else None
        try: cooling = isinstance(failure, dict) and float(failure.get('retry_at', 0)) > now
        except (TypeError, ValueError): cooling = False
        if cooling or path.is_symlink() or not path.is_file(): return False
        path.unlink()
        return True
    except OSError:
        return False
    finally:
        os.close(fd)

def _prune_cache(root, current, now):
    """Prune only idle, non-cooling metadata entries owned by this module."""
    files = [path for path in root.glob('meta-*.json') if path != current and path.is_file() and not path.is_symlink()]
    excess = max(0, len(files) + 1 - CACHE_MAX_ENTRIES)
    for path in sorted(files, key=lambda item: item.stat().st_mtime):
        if excess <= 0: break
        if _remove_if_prunable(path, now): excess -= 1

def _cache_error(entry, now):
    failure = entry.get('failure', {}) if isinstance(entry, dict) else {}
    result = {'status': failure.get('status', 'error'), 'error': failure.get('error', 'metadata query is backing off'),
              'httpStatus': failure.get('httpStatus'), 'cache_state': 'backoff', 'queriedAt': failure.get('queriedAt', now),
              'finishedAt': failure.get('finishedAt', now), 'retry_after': max(0, failure.get('retry_at', now) - now),
              'raw': '', 'data': None, 'sourceURL': ''}
    for key in ('kind', 'query', 'sourceURL', 'transport'):
        if isinstance(entry.get(key), str): result[key] = entry[key]
    good = entry.get('last_good') if isinstance(entry, dict) else None
    if isinstance(good, dict): result['last_good'] = copy.deepcopy(good)
    return result

def _retry_delay(receipt, attempt):
    status = receipt.get('httpStatus') if isinstance(receipt, dict) else None
    explicit = receipt.get('retry_after') if isinstance(receipt, dict) else None
    try: explicit = max(0, float(explicit))
    except (TypeError, ValueError): explicit = 0
    if status == 429: return max(900, explicit)
    return min(900, max(15, 15 * (2 ** min(max(0, attempt - 1), 6)), explicit))

def cached_query(key, loader, ttl=CACHE_TTL, cache_dir=None, now=None):
    """Cross-process singleflight cache for one public-IP metadata query.

    A failed refresh never becomes a successful current receipt.  It can carry
    ``last_good`` for historical display, whose original timestamps remain
    untouched.
    """
    if not _valid_cache_key(key):
        raise ValueError('invalid cache key')
    live_clock = now is None
    root = _cache_root(cache_dir); path = root / (_cache_name(key) + '.json')
    with _cache_lock(root, key):
        # Reacquire the clock after waiting for this key's singleflight lock;
        # otherwise a waiter can see a just-written receipt as "from future"
        # and issue a duplicate request.
        now = time.time() if live_clock else float(now)
        entry = _read_cache(path)
        good = entry.get('last_good') if isinstance(entry, dict) else None
        try: finished = float(good.get('finishedAt')) if isinstance(good, dict) else -1
        except (TypeError, ValueError): finished = -1
        if isinstance(good, dict) and good.get('status') == 'complete' and 0 <= now - finished <= ttl:
            entry['used_at'] = now; _write_cache(path, entry)
            result = copy.deepcopy(good); result.update(cache_state='hit', cache_age=now - finished)
            return result
        failure = entry.get('failure') if isinstance(entry, dict) else None
        if isinstance(failure, dict) and now < failure.get('retry_at', 0):
            return _cache_error(entry, now)
        receipt = loader()
        completed_at = time.time() if live_clock else now
        if not isinstance(receipt, dict):
            receipt = {'status': 'error', 'error': 'metadata loader returned invalid receipt', 'httpStatus': None,
                       'queriedAt': completed_at, 'finishedAt': completed_at}
        result = copy.deepcopy(receipt); result['cache_state'] = 'miss'
        entry = {'used_at': completed_at}
        for key in ('kind', 'query', 'sourceURL', 'transport'):
            if isinstance(result.get(key), str): entry[key] = result[key]
        if result.get('status') == 'complete':
            entry['last_good'] = copy.deepcopy(result)
        else:
            old_attempt = failure.get('attempt', 0) if isinstance(failure, dict) else 0
            try: old_attempt = int(old_attempt)
            except (TypeError, ValueError): old_attempt = 0
            delay = _retry_delay(result, old_attempt + 1)
            entry['failure'] = {'status': result.get('status', 'error'), 'error': str(result.get('error') or 'metadata query failed')[:240],
                                'httpStatus': result.get('httpStatus'), 'queriedAt': result.get('queriedAt', now),
                                'finishedAt': result.get('finishedAt', completed_at), 'attempt': old_attempt + 1,
                                'retry_at': completed_at + delay}
            if isinstance(good, dict):
                entry['last_good'] = copy.deepcopy(good)
                result['last_good'] = copy.deepcopy(good)
        _write_cache(path, entry); _prune_cache(root, path, completed_at)
        return result

def endpoint(kind, query):
    if kind == 'trace':
        if query: raise ValueError('trace has no query')
        return 'https://1.1.1.1/cdn-cgi/trace'
    if kind == 'dns':
        if not re.fullmatch(r'[a-z0-9]{16,48}', query): raise ValueError('invalid DNS token')
        return ORIGIN + '/api/dns/result/' + query
    if "%" in query: raise ValueError("scoped IP not supported")
    ip = ipaddress.ip_address(query)
    if not ip.is_global or ip.is_multicast: raise ValueError('public IP required')
    if kind not in ('lookup', 'geoip', 'risk'): raise ValueError('unsupported API')
    return ORIGIN + {'lookup':'/api/ip/lookup/','geoip':'/api/geoip/','risk':'/api/iprisk/'}[kind] + str(ip)

def _request_uncached(kind, query):
    start = time.time()
    result = dict(kind=kind, query=query, sourceURL='', queriedAt=start, finishedAt=start,
                  status='error', httpStatus=None, raw='', data=None, error=None,
                  transport='HTTP CONNECT via 127.0.0.1:7890')
    try:
        url = endpoint(kind, query); result['sourceURL'] = url
        header_fd, header_path = tempfile.mkstemp(prefix='claude-watch-headers-')
        os.close(header_fd)
        task = subprocess.Popen(['/usr/bin/curl', '--disable', '--silent', '--show-error', '--proxy', PROXY,
            '--noproxy', '', '--connect-timeout', '5', '--max-time', '16', '--max-filesize', '524288',
            '--proto', '=https', '--max-redirs', '0', '--user-agent', 'ClaudeWatch-Diagnostics/1.0',
            '--dump-header', header_path,
            '--write-out', '\n%{http_code}', url], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def stop(*_):
            task.terminate()
        old = signal.signal(signal.SIGTERM, stop)
        try:
            out, err = task.communicate(timeout=18)
        except subprocess.TimeoutExpired:
            task.kill(); out, err = task.communicate(); raise TimeoutError('request timed out')
        finally:
            signal.signal(signal.SIGTERM, old)
        body, _, code = out.rpartition(b'\n')
        result['httpStatus'] = int(code) if code.isdigit() else None
        result['raw'] = body.decode('utf-8', 'replace')
        result['sha256'] = hashlib.sha256(body).hexdigest()
        if task.returncode: raise RuntimeError('transport timeout' if task.returncode == 28 else 'transport failed (%d)' % task.returncode)
        if result['httpStatus'] == 429:
            # Headers are consumed in memory only.  Never retain them in the
            # receipt/cache; they can contain cookies or infrastructure IDs.
            try: headers = Path(header_path).read_bytes()[:32 * 1024]
            except OSError: headers = b''
            retry = re.search(br'(?im)^retry-after:\s*([0-9]{1,8})\s*$', headers)
            if retry: result['retry_after'] = int(retry.group(1))
        if result['httpStatus'] != 200: raise RuntimeError('HTTP %s' % result['httpStatus'])
        if kind != 'trace':
            result['data'] = json.loads(result['raw'])
            if not isinstance(result['data'], dict): raise ValueError('JSON object required')
            if kind in ('lookup','risk'):
                if ipaddress.ip_address(result['data'].get('ip', '')) != ipaddress.ip_address(query):
                    raise ValueError('response IP mismatch')
            if kind == 'dns' and (not isinstance(result['data'].get('dns_servers'), list)
                or not all(isinstance(x, str) for x in result['data']['dns_servers'])):
                raise ValueError('invalid dns_servers')
        result['status'] = 'complete'
    except Exception as exc:
        result['error'] = str(exc); result['status'] = 'timeout' if 'tim' in str(exc).lower() else 'error'
    finally:
        try: os.unlink(header_path)
        except (OSError, UnboundLocalError): pass
    result['finishedAt'] = time.time()
    return result

def request(kind, query, *, cache_dir=None):
    """Fetch a receipt; only immutable public-IP metadata kinds are cached."""
    if kind not in METADATA_KINDS:
        return _request_uncached(kind, query)
    canonical = str(ipaddress.ip_address(query))
    if not ipaddress.ip_address(canonical).is_global:
        # Keep endpoint() as the single validator/error contract.
        endpoint(kind, query)
    return cached_query(kind + ':' + canonical, lambda: _request_uncached(kind, canonical), cache_dir=cache_dir)

def har_entry(receipt):
    raw = receipt['raw']; date = datetime.datetime.fromtimestamp(receipt['queriedAt'], datetime.timezone.utc).isoformat()
    return dict(startedDateTime=date, time=(receipt['finishedAt']-receipt['queriedAt'])*1000,
        request=dict(method='GET', url=receipt['sourceURL'], httpVersion='HTTP/1.1', headers=[], queryString=[], cookies=[], headersSize=-1, bodySize=0),
        response=dict(status=receipt['httpStatus'] or 0, statusText='', httpVersion='HTTP/1.1', headers=[], cookies=[], content=dict(size=len(raw.encode()), mimeType='text/plain' if receipt['kind']=='trace' else 'application/json', text=raw), redirectURL='', headersSize=-1, bodySize=len(raw.encode())),
        cache={}, timings=dict(send=0,wait=(receipt['finishedAt']-receipt['queriedAt'])*1000,receive=0),
        _provenance='Claude Watch own HTTP client response; not a packet/browser capture')

if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('kind', choices=['lookup','geoip','risk','dns','trace']); p.add_argument('query', nargs='?', default=''); p.add_argument('--record-har')
    args = p.parse_args(); receipt = request(args.kind, args.query)
    if args.record_har:
        with open(args.record_har, 'w') as f: json.dump({'log':{'version':'1.2','creator':{'name':'Claude Watch HTTP receipt exporter','version':'1'},'entries':[har_entry(receipt)]}}, f)
    print(json.dumps(receipt, ensure_ascii=False))
