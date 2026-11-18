#!/usr/bin/bash -p
set -euo pipefail

# Destructive database checks are opt-in and require an explicit disposable guard.
# This script never falls back to DATABASE_URL and never chooses a database itself.
# Provision a new, private cluster first; ECP_DATABASE_EXPECTED_DATA_DIR names
# its absolute data directory. Its owner must create a mode-0600 regular file
# .ecp-disposable.json in that directory, with schema_version
# forgeflow.ecp-disposable-database.v1 and exact data_directory,
# socket_directory, database and integer port fields. The socket directory is a
# 0700 sibling of the 0700 data directory inside a 0700 owned parent. The URI
# must name ecp_disposable_* and specify that socket as its sole query option.
# ops/ecp/tests/test_database_guard.py provides a complete isolated initdb,
# start, marker, verification, stop and cleanup example. Never add a marker to
# an existing service or database merely to pass this check.
url="${ECP_DATABASE_URL:-}"
run_store_test=0
output=""
output_fd=""
while (($#)); do
  case "$1" in
    --database-url) url="${2:?--database-url requires a value}"; shift 2 ;;
    --run-store-test) run_store_test=1; shift ;;
    --output) output="${2:?--output requires a path}"; shift 2 ;;
    --output-fd) output_fd="${2:?--output-fd requires a descriptor}"; shift 2 ;;
    *) echo '{"status":"FAIL","reason":"unknown argument"}' ; exit 10 ;;
  esac
done
if [[ -n "$output" && -n "$output_fd" ]]; then
  printf '%s\n' '{"status":"FAIL","reason":"output path and output fd are mutually exclusive","connections_attempted":0}'
  exit 10
fi
# A parent executor may pass an anonymous, empty, owned memfd so a child
# receipt can be checked for sensitive URL echoes before it is written to disk.
safe_memfd() {
  /usr/bin/python3 -I -S - "$1" "$output_fd" "${2:-}" <<'PY'
import fcntl,os,re,stat,sys
mode,raw,value=sys.argv[1:]
try:
    if not re.fullmatch(r'[0-9]{1,6}',raw):raise ValueError('invalid fd')
    fd=int(raw);info=os.fstat(fd)
    link=os.readlink('/proc/self/fd/'+raw)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=0 or
            stat.S_IMODE(info.st_mode)!=0o600 or not link.startswith('/memfd:forgeflow-p002-') or
            fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE != os.O_RDWR or info.st_size!=0):
        raise ValueError('unsafe anonymous receipt fd')
    if mode=='emit':
        data=(value+'\n').encode('utf-8','strict')
        if len(data)>65536:raise ValueError('receipt exceeds budget')
        os.lseek(fd,0,os.SEEK_SET);view=memoryview(data)
        while view:
            size=os.write(fd,view)
            if size<=0:raise OSError('short receipt write')
            view=view[size:]
    elif mode!='preflight':raise ValueError('invalid operation')
except (OSError,ValueError):
    sys.exit(10)
PY
}
if [[ -n "$output_fd" ]] && ! safe_memfd preflight; then
  printf '%s\n' '{"status":"BLOCKED","reason":"anonymous database receipt fd is unsafe; no database connection attempted","connections_attempted":0}'
  exit 10
fi
# The optional receipt is created only outside the actual source tree and via
# a no-follow directory FD. Record the parent inode before any DB operation;
# a replacement before/during emission is rejected and never overwritten.
safe_output() {
  /usr/bin/python3 -I -S - "$1" "$output" "${BASH_SOURCE[0]}" "${2:-}" "${3:-}" <<'PY'
import os, pathlib, posixpath, re, stat, sys
mode, raw, script, expected, value = sys.argv[1:]
def open_dir(path):
    path=pathlib.Path(os.path.abspath(path));fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        return fd
    except BaseException:
        os.close(fd);raise
def backing(path, table):
    absolute=os.path.abspath(path);selected=None
    for line in table.splitlines():
        left,sep,right=line.partition(' - ');fields=left.split()
        if not sep or len(fields)<6 or not right.split():raise ValueError('malformed mount table')
        decode=lambda value:re.sub(r'\\([0-7]{3})',lambda match:chr(int(match.group(1),8)),value)
        mount,fs_root=decode(fields[4]),decode(fields[3])
        if absolute==mount or absolute.startswith(mount.rstrip('/')+'/'):
            if selected is None or len(mount)>len(selected[1]):selected=(fields[2],mount,fs_root)
    if selected is None:raise ValueError('mount identity unavailable')
    device,mount,fs_root=selected
    suffix=absolute[len(mount):].lstrip('/') if mount!='/' else absolute.lstrip('/')
    return device,posixpath.normpath(posixpath.join(fs_root,suffix))
def aliases_source(source,parent):
    table=pathlib.Path('/proc/self/mountinfo').read_text(encoding='utf-8')
    source_dev,source_path=backing(source,table);parent_dev,parent_path=backing(parent,table)
    return source_dev==parent_dev and (parent_path==source_path or parent_path.startswith(source_path.rstrip('/')+'/'))
try:
    target=pathlib.Path(os.path.abspath(os.path.expanduser(raw)))
    source=pathlib.Path(script).resolve(strict=True).parents[2]
    if target == source or source in target.parents or target.name in ('','.','..'):
        raise ValueError('output inside source')
    sourcefd=open_dir(source)
    try: source_identity=(os.fstat(sourcefd).st_dev,os.fstat(sourcefd).st_ino)
    finally: os.close(sourcefd)
    if aliases_source(source,target.parent):raise ValueError('output aliases source mount')
    parentfd=open_dir(target.parent)
    try:
        parentinfo=os.fstat(parentfd);binding=f'{parentinfo.st_dev}:{parentinfo.st_ino}'
        probe=os.dup(parentfd);seen=set()
        try:
            for _ in range(256):
                info=os.fstat(probe);identity=(info.st_dev,info.st_ino)
                if identity==source_identity:raise ValueError('output ancestor is source')
                if identity in seen:break
                seen.add(identity);up=os.open('..',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=probe)
                os.close(probe);probe=up
            else:raise ValueError('output ancestor depth exceeds limit')
        finally:os.close(probe)
        if expected and binding!=expected:raise ValueError('output parent changed')
        try:os.stat(target.name,dir_fd=parentfd,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise FileExistsError('output already exists')
        if mode=='preflight':
            print(binding)
        elif mode=='emit':
            data=(value+'\n').encode('utf-8','strict')
            if len(data)>65536:raise ValueError('receipt exceeds budget')
            fd=os.open(target.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parentfd)
            try:
                view=memoryview(data)
                while view:
                    n=os.write(fd,view)
                    if n<=0:raise OSError('short receipt write')
                    view=view[n:]
                written=os.fstat(fd);current=os.stat(target.name,dir_fd=parentfd,follow_symlinks=False)
                if not stat.S_ISREG(written.st_mode) or (written.st_dev,written.st_ino)!=(current.st_dev,current.st_ino):
                    raise ValueError('receipt identity changed')
            finally:os.close(fd)
            current_parent=open_dir(target.parent)
            try:
                info=os.fstat(current_parent)
                if (info.st_dev,info.st_ino)!=(parentinfo.st_dev,parentinfo.st_ino):
                    raise ValueError('output parent changed; created receipt retained')
            finally:os.close(current_parent)
        else:raise ValueError('invalid output operation')
    finally:os.close(parentfd)
except (OSError,ValueError,RuntimeError):
    sys.exit(10)
PY
}
output_binding=""
if [[ -n "$output" ]]; then
  if ! output_binding="$(safe_output preflight)"; then
    printf '%s\n' '{"status":"BLOCKED","reason":"database evidence output is unsafe or unavailable; no database connection attempted","connections_attempted":0}'
    printf '%s\n' 'FAIL: could not create immutable database evidence output' >&2
    exit 10
  fi
fi
emit() {
  local value="$1"
  if [[ -n "$output_fd" ]] && ! safe_memfd emit "$value"; then
    printf '%s\n' "$value"
    printf '%s\n' 'FAIL: could not create anonymous database evidence output' >&2
    return 10
  fi
  if [[ -n "$output" ]]; then
    if ! safe_output emit "$output_binding" "$value"; then
      printf '%s\n' "$value"
      printf '%s\n' 'FAIL: could not create immutable database evidence output' >&2
      return 10
    fi
  fi
  printf '%s\n' "$value"
}
# The historical Store test called Cargo directly without the coordinated
# build lock, shared target budget or artifact/source binding. Until a
# reviewed P0-05 executor supplies those guarantees, refuse before connecting
# to any database or starting a process that could build.
if [[ "$run_store_test" == 1 ]]; then
  emit '{"status":"BLOCKED","reason":"Store migration execution requires the coordinated bounded build executor; no database connection or build attempted","connections_attempted":0,"store_migration_test":"NOT_RUN"}'
  exit 20
fi
if [[ "${ECP_DATABASE_DISPOSABLE:-}" != "1" ]]; then
  emit '{"status":"BLOCKED","reason":"set ECP_DATABASE_DISPOSABLE=1 explicitly; no database connection attempted","connections_attempted":0}'
  exit 20
fi
if [[ -z "$url" ]]; then
  emit '{"status":"BLOCKED","reason":"ECP_DATABASE_URL or --database-url is required","connections_attempted":0}'
  exit 20
fi
# A boolean alone cannot identify a disposable database. Bind the URI to a
# private local cluster, its live postmaster, and an explicit marker before any
# connection. Deliberately reject remote/ambiguous libpq options. The local
# metadata checks cannot authenticate a server or its adjacent client, so no
# client is launched until independent execution and peer identity exist.
if identity="$(ECP_DATABASE_GUARD_URL="$url" /usr/bin/python3 -I -S - <<'PY'
import json, os, pathlib, re, stat, sys, urllib.parse

def block(reason):
    print(json.dumps({'status':'BLOCKED','reason':reason,'connections_attempted':0}))
    sys.exit(20)

try:
    raw = os.environ.get('ECP_DATABASE_EXPECTED_DATA_DIR', '')
    if not raw:
        block('ECP_DATABASE_EXPECTED_DATA_DIR is required')
    data = pathlib.Path(raw)
    if not data.is_absolute() or data.resolve(strict=True) != data:
        block('database data directory must be an absolute non-symlink path')
    parent = data.parent
    for directory in (parent, data):
        info = directory.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            block('disposable cluster and parent must be private and owned by the caller')
    marker_path = data / '.ecp-disposable.json'
    marker_info = marker_path.lstat()
    if not stat.S_ISREG(marker_info.st_mode) or marker_info.st_uid != os.getuid() or stat.S_IMODE(marker_info.st_mode) != 0o600:
        block('disposable cluster marker must be an owned 0600 regular file')
    marker = json.loads(marker_path.read_text())
    if set(marker) != {'schema_version','data_directory','socket_directory','database','port'} or marker['schema_version'] != 'forgeflow.ecp-disposable-database.v1':
        block('invalid disposable cluster marker')
    parsed = urllib.parse.urlsplit(os.environ['ECP_DATABASE_GUARD_URL'])
    query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
    database = urllib.parse.unquote(parsed.path.lstrip('/'))
    user = urllib.parse.unquote(parsed.username or '')
    if (parsed.scheme not in ('postgres','postgresql') or parsed.hostname not in ('localhost','127.0.0.1','::1')
            or parsed.password is not None or parsed.fragment or set(query) != {'host'} or len(query['host']) != 1
            or not re.fullmatch(r'ecp_disposable_[a-z0-9_]+', database)
            or not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_]*', user)):
        block('database URI must name an unambiguous local disposable socket and database')
    sock = pathlib.Path(query['host'][0])
    port = parsed.port
    if not sock.is_absolute() or sock.resolve(strict=True) != sock or sock.parent != parent:
        block('database socket must be a private sibling of the disposable data directory')
    info = sock.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        block('database socket directory must be private and owned by the caller')
    if (marker['data_directory'] != str(data) or marker['socket_directory'] != str(sock)
            or marker['database'] != database or type(marker['port']) is not int or marker['port'] != port):
        block('database URI does not match the disposable cluster marker')
    pid_lines = (data / 'postmaster.pid').read_text().splitlines()
    if len(pid_lines) < 5 or pathlib.Path(pid_lines[1]).resolve(strict=True) != data or int(pid_lines[3]) != port or pathlib.Path(pid_lines[4]).resolve(strict=True) != sock:
        block('live PostgreSQL cluster identity does not match the marker')
    pid = int(pid_lines[0])
    proc = pathlib.Path('/proc') / str(pid)
    executable = pathlib.Path(os.readlink(proc/'exe')).resolve(strict=True)
    if proc.stat().st_uid != os.getuid() or executable.name != 'postgres':
        block('postmaster process is not the expected owned PostgreSQL server')
    psql = executable.with_name('psql').resolve(strict=True)
    if psql.parent != executable.parent or not psql.is_file() or not os.access(psql, os.X_OK):
        block('the PostgreSQL server installation does not contain its own psql')
    socket_file = sock / ('.s.PGSQL.' + str(port))
    info = socket_file.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
        block('expected owned PostgreSQL socket is unavailable')
except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
    block('disposable cluster identity could not be verified')

print(json.dumps({'status':'INCONCLUSIVE',
    'reason':'client and server identity are not independently authenticated; no PostgreSQL client was launched',
    'connections_attempted':0, 'client_process_invocations':0, 'identity_authority':'UNVERIFIED',
    'store_migration_test':'NOT_RUN'}))
sys.exit(20)
PY
)"; then :; else
  code=$?
  emit "$identity"
  exit "$code"
fi
# The embedded guard has no success exit until an independent trust root is
# implemented. Treat any unexpected zero exit as an invalid guard result.
emit '{"status":"INCONCLUSIVE","reason":"database guard unexpectedly returned without authenticated client/server identity","connections_attempted":null,"identity_authority":"UNVERIFIED","store_migration_test":"NOT_RUN"}'
exit 20
