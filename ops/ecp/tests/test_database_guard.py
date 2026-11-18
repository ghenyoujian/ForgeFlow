from __future__ import annotations
import json, os, pathlib, shutil, signal, socket, stat, subprocess, tempfile, time, unittest, urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[3]
SCRIPT = ROOT / 'ops/ecp/test_database.sh'

def run_bounded(argv, env, timeout):
    """Return only after the command exits; retain data on an unkillable child."""
    proc = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        try:
            terminate_injected_process(proc)
            ensure_process_group_gone(proc.pid)
        except (subprocess.TimeoutExpired, RuntimeError) as cleanup:
            raise RuntimeError('database command termination unconfirmed; retain fixture') from cleanup
        raise RuntimeError('database command timed out; retain fixture') from exc
    ensure_process_group_gone(proc.pid)
    return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)

def stop_nested_cluster(parent, pgroot, env):
    """Stop only an identified nested fixture; retain anything uncertain."""
    parent = pathlib.Path(parent)
    children = list(parent.iterdir())
    for root in children:
        if root.is_symlink() or not root.name.startswith('ecp-p002-') or not root.is_dir():
            raise RuntimeError('unexpected nested fixture entry; retained: ' + str(root))
        for directory in (parent, root, root/'data', root/'socket'):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise RuntimeError('nested fixture is not a private owned directory; retained: ' + str(root))
        data, sock = root/'data', root/'socket'
        pid_file = data/'postmaster.pid'
        info = pid_file.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise RuntimeError('nested postmaster identity unavailable; retained: ' + str(root))
        lines = pid_file.read_text().splitlines()
        if len(lines) < 5 or pathlib.Path(lines[1]) != data or pathlib.Path(lines[4]) != sock:
            raise RuntimeError('nested postmaster identity mismatch; retained: ' + str(root))
        pid = int(lines[0])
        proc = pathlib.Path('/proc')/str(pid)
        if (pid <= 1 or proc.stat().st_uid != os.getuid()
                or pathlib.Path(os.readlink(proc/'exe')).resolve() != (pgroot/'postgres').resolve()):
            raise RuntimeError('nested postmaster process mismatch; retained: ' + str(root))
        args = (proc/'cmdline').read_bytes().split(b'\0')
        encoded_data = os.fsencode(str(data))
        if not any(args[i] == b'-D' and args[i+1] == encoded_data for i in range(len(args)-1)):
            raise RuntimeError('nested postmaster data directory mismatch; retained: ' + str(root))
        status = run_bounded([str(pgroot/'pg_ctl'), '-D', str(data), 'status'], env, 10)
        if status.returncode != 0:
            raise RuntimeError('nested postmaster status unknown; retained: ' + str(root))
        stopped = run_bounded([str(pgroot/'pg_ctl'), '-D', str(data), '-m', 'fast', '-w', 'stop'], env, 20)
        if stopped.returncode:
            raise RuntimeError('nested postmaster stop failed; retained: ' + str(root))
        status = run_bounded([str(pgroot/'pg_ctl'), '-D', str(data), 'status'], env, 10)
        if status.returncode != 3 or pid_file.exists():
            raise RuntimeError('nested postmaster stop unconfirmed; retained: ' + str(root))
        shutil.rmtree(root)

def terminate_injected_process(proc):
    """Reap only the dedicated child process group, with bounded waits."""
    if proc.returncode is not None:
        return proc.communicate(timeout=3)
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        return proc.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return proc.communicate(timeout=5)

def ensure_process_group_gone(pgid, timeout=5):
    """Do not discard a fixture while an unreaped or uninterruptible child remains."""
    deadline = time.monotonic()+timeout
    while True:
        members = []
        for proc in pathlib.Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                raw = (proc/'stat').read_text()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise RuntimeError('cannot prove child process group is gone; retain fixture') from exc
            fields = raw[raw.rfind(')')+2:].split()
            if len(fields) < 3:
                raise RuntimeError('cannot parse process group; retain fixture')
            if int(fields[2]) == pgid and fields[0] != 'Z':
                members.append(proc.name)
        if not members:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError('child process group still running; retain fixture: ' + ','.join(members))
        time.sleep(.1)

def refuse_unconfirmed_nested(root):
    nested = pathlib.Path(root)/'failure-injection'
    if nested.exists() and any(nested.iterdir()):
        raise RuntimeError('Nested fixture stop not confirmed; retain parent data directory: ' + str(root))

def postgres_bin_dir():
    configured = os.environ.get('ECP_PG_BINDIR')
    if configured:
        result = pathlib.Path(configured)
    elif shutil.which('initdb'):
        result = pathlib.Path(shutil.which('initdb')).parent
    elif shutil.which('pg_config'):
        result = pathlib.Path(subprocess.check_output(['pg_config', '--bindir'], text=True).strip())
    else:
        raise RuntimeError('BLOCKED: set ECP_PG_BINDIR or install PostgreSQL client and server tools')
    if not all((result/name).is_file() and os.access(result/name,os.X_OK) for name in ('initdb','pg_ctl','createdb','psql')):
        raise RuntimeError('BLOCKED: PostgreSQL initdb, pg_ctl, createdb and psql are required')
    return result

class DatabaseEvidenceOutput(unittest.TestCase):
    def test_counterfeit_local_postgres_never_launches_untrusted_psql(self):
        # This is not PostgreSQL: the owned process binds a private AF_UNIX
        # socket but never listens, accepts or connects. Its adjacent psql
        # would write a marker if the guard mistakenly executed it.
        import select
        with tempfile.TemporaryDirectory(prefix='p002-counterfeit-',dir='/tmp') as directory:
            root=pathlib.Path(directory); binary=root/'bin'; data=root/'data'; sock=root/'socket'
            for p in (binary,data,sock): p.mkdir(mode=0o700)
            executable=binary/'postgres';shutil.copy2('/usr/bin/python3',executable);executable.chmod(0o700)
            marker=root/'psql-executed'; client=binary/'psql'
            client.write_text('#!/bin/sh\nprintf invoked > "'+str(marker)+'"\nexit 0\n');client.chmod(0o700)
            port=55477; socket_path=sock/('.s.PGSQL.'+str(port))
            code=('import socket,signal,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);'
                  's.bind(sys.argv[1]);print(s.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN),flush=True);signal.pause()')
            proc=subprocess.Popen([str(executable),'-I','-S','-c',code,str(socket_path)],
                                  stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
            try:
                ready,_,_=select.select([proc.stdout],[],[],10)
                self.assertTrue(ready,'counterfeit process did not become ready')
                self.assertEqual(proc.stdout.readline().strip(),'0','fixture socket must not listen')
                (data/'postmaster.pid').write_text(f'{proc.pid}\n{data}\n0\n{port}\n{sock}\n')
                meta={'schema_version':'forgeflow.ecp-disposable-database.v1','data_directory':str(data),
                      'socket_directory':str(sock),'database':'ecp_disposable_counterfeit','port':port}
                (data/'.ecp-disposable.json').write_text(json.dumps(meta));(data/'.ecp-disposable.json').chmod(0o600)
                env={k:v for k,v in os.environ.items() if not k.startswith(('PG','ECP_DATABASE_'))
                     and k not in ('BASH_ENV','ENV','PYTHONPATH')}
                env.update(ECP_DATABASE_DISPOSABLE='1',ECP_DATABASE_EXPECTED_DATA_DIR=str(data),
                           ECP_DATABASE_URL=f'postgresql://fixture@localhost:{port}/ecp_disposable_counterfeit?host='+urllib.parse.quote(str(sock),safe=''))
                result=subprocess.run([str(SCRIPT)],env=env,capture_output=True,text=True,timeout=20)
                receipt=json.loads(result.stdout)
                self.assertEqual((result.returncode,receipt['status']),(20,'INCONCLUSIVE'),result.stderr)
                self.assertEqual((receipt['connections_attempted'],receipt['client_process_invocations']),(0,0))
                self.assertEqual(receipt['identity_authority'],'UNVERIFIED')
                self.assertFalse(marker.exists(),'untrusted adjacent client must never run')
            finally:
                terminate_injected_process(proc)
                ensure_process_group_gone(proc.pid)

    def test_store_execution_is_blocked_before_database_or_cargo(self):
        with tempfile.TemporaryDirectory(prefix='p002-block-cargo-') as temp:
            root=pathlib.Path(temp);fake=root/'bin';fake.mkdir();marker=root/'invoked'
            for name in ('cargo','psql'):
                command=fake/name
                command.write_text('#!/bin/sh\nprintf invoked >> "$TEST_INVOCATION_MARKER"\nexit 0\n')
                command.chmod(0o755)
            env=dict(os.environ,PATH=str(fake)+':/usr/bin:/bin',TEST_INVOCATION_MARKER=str(marker),
                     ECP_DATABASE_DISPOSABLE='1',ECP_DATABASE_URL='postgresql://fake@localhost/ecp_disposable_fake')
            completed=subprocess.run([str(SCRIPT),'--run-store-test'],env=env,text=True,capture_output=True,timeout=10)
            payload=json.loads(completed.stdout.strip().splitlines()[-1])
            self.assertEqual((completed.returncode,payload['status'],payload['connections_attempted']), (20,'BLOCKED',0))
            self.assertEqual(payload['store_migration_test'],'NOT_RUN')
            self.assertFalse(marker.exists(), 'must not invoke Cargo or connect to a database')

    def test_anonymous_receipt_fd_is_written_and_disk_fd_is_rejected(self):
        import ctypes
        with tempfile.TemporaryDirectory(prefix='p002-memfd-') as directory:
            env={k:v for k,v in os.environ.items() if not k.startswith('ECP_DATABASE_') and k not in ('BASH_ENV','ENV')}
            if hasattr(os,'memfd_create'):
                fd=os.memfd_create('forgeflow-p002-test',1)
            else:
                libc=ctypes.CDLL(None,use_errno=True);libc.memfd_create.argtypes=(ctypes.c_char_p,ctypes.c_uint)
                libc.memfd_create.restype=ctypes.c_int;fd=libc.memfd_create(b'forgeflow-p002-test',1)
                if fd < 0:
                    self.skipTest('memfd unavailable')
            try:
                os.fchmod(fd,0o600)
                result=subprocess.run([str(SCRIPT),'--output-fd',str(fd)],env=env,pass_fds=(fd,),capture_output=True,timeout=10)
                self.assertEqual(result.returncode,20,result.stderr)
                self.assertEqual(os.pread(fd,65537,0),result.stdout)
                self.assertEqual(json.loads(result.stdout)['status'],'BLOCKED')
            finally:
                os.close(fd)
            path=pathlib.Path(directory)/'disk';path.write_text('retain')
            fd=os.open(path,os.O_RDWR)
            try:
                result=subprocess.run([str(SCRIPT),'--output-fd',str(fd)],env=env,pass_fds=(fd,),capture_output=True,timeout=10)
                self.assertEqual(result.returncode,10)
                self.assertEqual(path.read_text(),'retain')
                self.assertEqual(json.loads(result.stdout)['connections_attempted'],0)
            finally:
                os.close(fd)

    def test_direct_output_mount_alias_rejected_by_backing_map(self):
        import posixpath, re
        from unittest.mock import patch
        content=SCRIPT.read_text()
        start=content.index('def backing(path, table):')
        end=content.index('try:\n    target=pathlib.Path',start)
        namespace={'os':os,'pathlib':pathlib,'posixpath':posixpath,'re':re}
        exec(content[start:end],namespace)
        table=('41 1 0:1 / / rw - ext4 /dev/a rw\n'
               '42 41 0:2 /tree /source rw - ext4 /dev/b rw\n'
               '43 41 0:2 /tree/ops /alias rw - ext4 /dev/b rw\n')
        with patch.object(pathlib.Path,'read_text',return_value=table):
            self.assertTrue(namespace['aliases_source'](pathlib.Path('/source'),pathlib.Path('/alias')))
            self.assertFalse(namespace['aliases_source'](pathlib.Path('/source'),pathlib.Path('/other')))

    def test_live_process_group_is_never_reported_stopped(self):
        proc = subprocess.Popen(['/bin/sleep', '30'], start_new_session=True)
        try:
            with self.assertRaisesRegex(RuntimeError, 'still running'):
                ensure_process_group_gone(proc.pid, timeout=0)
        finally:
            terminate_injected_process(proc)
            ensure_process_group_gone(proc.pid)

    def test_unknown_nested_cluster_is_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            outer = pathlib.Path(directory)
            parent = outer/'failure-injection'; parent.mkdir(mode=0o700)
            cluster = parent/'ecp-p002-unknown'; cluster.mkdir(mode=0o700)
            (cluster/'data').mkdir(mode=0o700)
            (cluster/'socket').mkdir(mode=0o700)
            marker = cluster/'data'/'retain-original'
            marker.write_text('do not remove')
            with self.assertRaises((OSError, RuntimeError, ValueError)):
                stop_nested_cluster(parent, pathlib.Path('/not-a-postgres-installation'), dict(os.environ))
            with self.assertRaises(RuntimeError):
                refuse_unconfirmed_nested(outer)
            self.assertEqual(marker.read_text(), 'do not remove')

    def test_blocked_receipt_cannot_overwrite_files_or_symlinks(self):
        # This path must be safe even when no PostgreSQL installation is present.
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            original = root/'failure.json'
            original.write_text('original failure evidence\n')
            linked = root/'linked.json'
            linked.symlink_to(original)
            missing = root/'missing.json'
            dangling = root/'dangling.json'
            dangling.symlink_to(missing)
            env = {k:v for k,v in os.environ.items()
                   if not k.startswith('ECP_DATABASE_') and k not in ('BASH_ENV', 'ENV')}
            for target in (original, linked, dangling):
                with self.subTest(target=target):
                    result = subprocess.run([str(SCRIPT), '--output', str(target)],
                                            env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 10, result.stderr)
                    self.assertEqual(json.loads(result.stdout)['status'], 'BLOCKED')
                    self.assertIn('could not create immutable database evidence output', result.stderr)
                    self.assertEqual(original.read_text(), 'original failure evidence\n')
                    self.assertFalse(missing.exists())
            (root/'new').mkdir()
            fresh = root/'new'/'blocked.json'
            result = subprocess.run([str(SCRIPT), '--output', str(fresh)],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 20, result.stderr)
            self.assertEqual(json.loads(fresh.read_text()), json.loads(result.stdout))

    def test_direct_output_rejects_source_and_symlink_parent_before_connection(self):
        with tempfile.TemporaryDirectory(prefix='p002-output-safety-') as directory:
            root=pathlib.Path(directory);source_output=ROOT/'ops/ecp'/'_unsafe_p002_receipt.json'
            self.assertFalse(source_output.exists())
            alias=root/'link';alias.symlink_to(root,target_is_directory=True)
            env={k:v for k,v in os.environ.items() if not k.startswith('ECP_DATABASE_') and k not in ('BASH_ENV','ENV')}
            for output in (source_output,alias/'receipt.json'):
                with self.subTest(output=output):
                    result=subprocess.run([str(SCRIPT),'--output',str(output)],env=env,capture_output=True,text=True,timeout=10)
                    self.assertEqual(result.returncode,10,result.stderr)
                    self.assertEqual(json.loads(result.stdout)['connections_attempted'],0)
                    self.assertFalse(output.exists())

    def test_untrusted_path_and_shell_python_hooks_do_not_run(self):
        with tempfile.TemporaryDirectory(prefix='p002-hooks-') as directory:
            root=pathlib.Path(directory);parent=root/'output';parent.mkdir()
            fake=root/'bin';fake.mkdir();marker=root/'unexpected-execution'
            for name in ('python3','bash','psql'):
                command=fake/name
                command.write_text('#!/bin/sh\nprintf invoked >> "'+str(marker)+'"\nexit 1\n');command.chmod(0o755)
            hook=root/'bash-env';hook.write_text('printf invoked >> "'+str(marker)+'"\n')
            (fake/'sitecustomize.py').write_text('open('+repr(str(marker))+',"a").write("invoked")\n')
            env=dict(os.environ,PATH=str(fake)+':/usr/bin:/bin',BASH_ENV=str(hook),PYTHONPATH=str(fake),
                     ECP_DATABASE_DISPOSABLE='1',ECP_DATABASE_URL='postgresql://fake@localhost/ecp_disposable_fake',
                     ECP_DATABASE_EXPECTED_DATA_DIR=str(root/'missing'))
            result=subprocess.run([str(SCRIPT),'--output',str(parent/'receipt.json')],env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,20,result.stderr)
            self.assertEqual(json.loads(result.stdout)['status'],'BLOCKED')
            self.assertEqual(json.loads((parent/'receipt.json').read_text()),json.loads(result.stdout))
            self.assertFalse(marker.exists())

    def test_instrumented_copy_detects_output_parent_replacement(self):
        # Instrument only a temporary copy immediately after preflight; the
        # production safe_output function and script under test stay intact.
        with tempfile.TemporaryDirectory(prefix='p002-output-race-') as directory:
            root=pathlib.Path(directory); parent=root/'output';parent.mkdir(); old=root/'old'
            script=root/'source/ops/ecp/test_database.sh';script.parent.mkdir(parents=True)
            original=SCRIPT.read_text(); hookpoint='\nfi\nemit() {\n'
            self.assertEqual(original.count(hookpoint),1)
            hook=('\nfi\n/usr/bin/python3 -I -S - "$P002_SWAP_PARENT" <<\'PY\'\n'
                  'import pathlib,sys\n'
                  'p=pathlib.Path(sys.argv[1]);p.rename(p.with_name("old"));p.mkdir();'
                  '(p/"sentinel").write_text("preserve")\nPY\nemit() {\n')
            instrumented=original.replace(hookpoint,hook)
            a=original[original.index('safe_output() {'):original.index('output_binding=""')]
            b=instrumented[instrumented.index('safe_output() {'):instrumented.index('output_binding=""')]
            self.assertEqual(a,b,'the production safety function must not be instrumented')
            script.write_text(instrumented);script.chmod(0o755)
            env={k:v for k,v in os.environ.items() if not k.startswith('ECP_DATABASE_') and k not in ('BASH_ENV','ENV')}
            env['P002_SWAP_PARENT']=str(parent)
            result=subprocess.run([str(script),'--output',str(parent/'receipt.json')],env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,10,result.stderr)
            self.assertEqual((parent/'sentinel').read_text(),'preserve')
            self.assertFalse((parent/'receipt.json').exists())
            self.assertFalse((old/'receipt.json').exists())

    def test_unwritable_output_is_reported_as_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory)/'not-a-directory'
            parent.write_text('preserve')
            env = {k:v for k,v in os.environ.items()
                   if not k.startswith('ECP_DATABASE_') and k not in ('BASH_ENV', 'ENV')}
            result = subprocess.run([str(SCRIPT), '--output', str(parent/'receipt')],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 10, result.stderr)
            self.assertEqual(json.loads(result.stdout)['status'], 'BLOCKED')
            self.assertIn('could not create immutable database evidence output', result.stderr)
            self.assertEqual(parent.read_text(), 'preserve')

class RealDisposableDatabaseGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pgroot = postgres_bin_dir()
        cls.root = pathlib.Path(tempfile.mkdtemp(prefix='ecp-p002-', dir=os.environ.get('ECP_TEST_TMP_ROOT','/tmp')))
        cls.data, cls.sock = cls.root/'data', cls.root/'socket'
        cls.start_requested = False
        cls.nested_cleanup_unconfirmed = False
        cls.sock.mkdir(mode=0o700)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); cls.port = sock.getsockname()[1]
        cls.env = {k:v for k,v in os.environ.items() if not k.startswith('PG') and not k.startswith('ECP_DATABASE_') and k not in ('DATABASE_URL','ECP_ALLOW_REMOTE_DISPOSABLE')}
        cls.env.update(PATH=str(cls.pgroot)+':'+cls.env['PATH'],
                       PGHOST=str(cls.sock), PGPORT=str(cls.port), PGUSER='ecp_probe', PGDATABASE='postgres')
        if os.environ.get('ECP_PG_LIBDIR'):
            cls.env['LD_LIBRARY_PATH'] = os.environ['ECP_PG_LIBDIR']
        def cleanup():
            status=run_bounded([str(cls.pgroot/'pg_ctl'),'-D',str(cls.data),'status'],cls.env,10)
            if status.returncode==0:
                result=run_bounded([str(cls.pgroot/'pg_ctl'),'-D',str(cls.data),'-m','fast','-w','stop'],cls.env,20)
                if result.returncode:
                    raise RuntimeError('Disposable PostgreSQL stop failed; retain its data directory')
                stopped=run_bounded([str(cls.pgroot/'pg_ctl'),'-D',str(cls.data),'status'],cls.env,10)
                if stopped.returncode!=3:
                    raise RuntimeError('Disposable PostgreSQL stop not confirmed; retain its data directory')
            elif cls.start_requested and status.returncode!=3:
                raise RuntimeError('Disposable PostgreSQL status unknown; retain its data directory')
            if cls.nested_cleanup_unconfirmed:
                raise RuntimeError('Nested child process termination unconfirmed; retain parent data directory: ' + str(cls.root))
            refuse_unconfirmed_nested(cls.root)
            shutil.rmtree(cls.root)
        cls.addClassCleanup(cleanup)
        subprocess.run([str(cls.pgroot/'initdb'),'-D',str(cls.data),'-U','ecp_probe','--auth-local=trust','--auth-host=reject','--no-instructions'], env=cls.env, capture_output=True, check=True)
        cls.start_requested = True
        subprocess.run([str(cls.pgroot/'pg_ctl'),'-D',str(cls.data),'-l',str(cls.root/'postgres.log'),'-o',f'-k {cls.sock} -p {cls.port} -h ""','-w','start'],env=cls.env,capture_output=True,check=True)
        if os.environ.get('ECP_TEST_INJECT_START_FAILURE') == '1':
            raise RuntimeError('intentional failure immediately after cluster start')
        if os.environ.get('ECP_TEST_INJECT_START_HANG') == '1':
            (cls.root/'hang-after-start.ready').write_text('started\n')
            time.sleep(300)
        subprocess.run([str(cls.pgroot/'createdb'),'ecp_disposable_expected'],env=cls.env,capture_output=True,check=True)
        subprocess.run([str(cls.pgroot/'createdb'),'ecp_disposable_other'],env=cls.env,capture_output=True,check=True)
        cls.url = f'postgresql://ecp_probe@localhost:{cls.port}/ecp_disposable_expected?host='+urllib.parse.quote(str(cls.sock),safe='')
        marker={'schema_version':'forgeflow.ecp-disposable-database.v1','data_directory':str(cls.data),'socket_directory':str(cls.sock),'database':'ecp_disposable_expected','port':cls.port}
        (cls.data/'.ecp-disposable.json').write_text(json.dumps(marker)); (cls.data/'.ecp-disposable.json').chmod(0o600)
        cls.guarded=dict(cls.env,ECP_DATABASE_URL=cls.url,ECP_DATABASE_DISPOSABLE='1',ECP_DATABASE_EXPECTED_DATA_DIR=str(cls.data))

    def probe(self, **changes):
        env=dict(self.guarded, **changes)
        proc=subprocess.run([str(SCRIPT)],env=env,capture_output=True,text=True,timeout=20)
        return proc.returncode,json.loads(proc.stdout)

    def test_matching_real_temporary_cluster_is_not_authenticated(self):
        code, result=self.probe()
        self.assertEqual((code,result['status']),(20,'INCONCLUSIVE'), result)
        self.assertEqual((result['connections_attempted'],result['client_process_invocations']),(0,0))
        self.assertEqual(result['identity_authority'],'UNVERIFIED')

    def test_other_database_is_blocked_before_connection(self):
        code, result=self.probe(ECP_DATABASE_URL=self.url.replace('ecp_disposable_expected?', 'ecp_disposable_other?'))
        self.assertEqual(code,20,result)
        self.assertEqual(result['connections_attempted'],0)

    def test_unexpected_effective_host_is_blocked_before_connection(self):
        code, result=self.probe(ECP_DATABASE_URL=self.url+'&hostaddr=127.0.0.1')
        self.assertEqual(code,20,result)
        self.assertEqual(result['connections_attempted'],0)

    def test_missing_or_forged_cluster_binding_is_blocked(self):
        for value in ['', str(self.root/'missing')]:
            with self.subTest(value=value):
                code,result=self.probe(ECP_DATABASE_EXPECTED_DATA_DIR=value)
                self.assertEqual(code,20,result)
                self.assertEqual(result['connections_attempted'],0)

    def test_existing_guard_still_blocks_without_connection(self):
        code,result=self.probe(ECP_DATABASE_DISPOSABLE='0')
        self.assertEqual(code,20,result)
        self.assertEqual(result['connections_attempted'],0)

    def test_forged_marker_and_symlinked_socket_are_rejected(self):
        marker = self.data/'.ecp-disposable.json'
        original = marker.read_text()
        try:
            value = json.loads(original); value['database'] = 'ecp_disposable_other'
            marker.write_text(json.dumps(value))
            code, result = self.probe()
            self.assertEqual(code, 20, result)
            self.assertEqual(result['connections_attempted'], 0)
        finally:
            marker.write_text(original)
        alias = self.root/'alias'
        alias.symlink_to(self.sock, target_is_directory=True)
        try:
            bad = self.url.replace(urllib.parse.quote(str(self.sock), safe=''), urllib.parse.quote(str(alias), safe=''))
            code, result = self.probe(ECP_DATABASE_URL=bad)
            self.assertEqual(code, 20, result)
            self.assertEqual(result['connections_attempted'], 0)
        finally:
            alias.unlink()

    def test_marker_with_insecure_permissions_is_rejected(self):
        marker = self.data/'.ecp-disposable.json'
        marker.chmod(0o644)
        try:
            code, result = self.probe()
            self.assertEqual(code, 20, result)
            self.assertEqual(result['connections_attempted'], 0)
        finally:
            marker.chmod(0o600)

    def test_environment_host_override_cannot_redirect_the_connection(self):
        code, result = self.probe(PGHOSTADDR='127.0.0.1', PGSERVICE='untrusted-service')
        self.assertEqual((code,result['status']),(20,'INCONCLUSIVE'), result)
        self.assertEqual(result['client_process_invocations'],0)

    def test_psql_path_hijack_is_not_used_for_identity(self):
        bindir=self.root/'fake-psql'; bindir.mkdir()
        fake=bindir/'psql'; marker=self.root/'fake-psql-ran'
        fake.write_text('#!/bin/sh\ntouch "'+str(marker)+'"\nexit 0\n')
        fake.chmod(0o755)
        code, result = self.probe(PATH=str(bindir)+':'+self.env['PATH'])
        self.assertEqual((code,result['status']),(20,'INCONCLUSIVE'), result)
        self.assertEqual(result['client_process_invocations'],0)
        self.assertFalse(marker.exists())

    def test_store_test_is_blocked_before_cargo_or_database(self):
        bindir=self.root/'fake-bin'; bindir.mkdir()
        cargo=bindir/'cargo'
        cargo.write_text('#!/usr/bin/python3\nimport json,os\nopen(os.environ["TEST_ENV_OUTPUT"],"w").write(json.dumps({"pg":[k for k in os.environ if k.startswith("PG")],"url":os.environ.get("DATABASE_URL"),"test_url":os.environ.get("FORGEFLOW_TEST_DATABASE_URL")}))\n')
        cargo.chmod(0o755)
        output=self.root/'observed-env.json'
        env=dict(self.guarded, PATH=str(bindir)+':'+self.env['PATH'], TEST_ENV_OUTPUT=str(output), PGHOSTADDR='127.0.0.1', PGREQUIREAUTH='scram-sha-256')
        result=subprocess.run([str(SCRIPT),'--run-store-test'],env=env,capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,20,result.stdout+result.stderr)
        observed=json.loads(result.stdout.strip().splitlines()[-1])
        self.assertEqual(observed['status'],'BLOCKED')
        self.assertEqual(observed['connections_attempted'],0)
        self.assertEqual(observed['store_migration_test'],'NOT_RUN')
        self.assertFalse(output.exists())

    def test_startup_failure_stops_and_removes_its_own_cluster(self):
        self.assertFalse(self.__class__.nested_cleanup_unconfirmed, 'previous nested fixture not safely cleaned')
        parent=self.root/'failure-injection'; parent.mkdir(mode=0o700, exist_ok=True)
        env=dict(os.environ,ECP_TEST_TMP_ROOT=str(parent),ECP_TEST_INJECT_START_FAILURE='1',
                 ECP_PG_BINDIR=str(self.pgroot))
        env.pop('ECP_TEST_INJECT_START_HANG', None)
        self.__class__.nested_cleanup_unconfirmed = True
        proc=subprocess.Popen([os.sys.executable,'-m','unittest',
            'ops.ecp.tests.test_database_guard.RealDisposableDatabaseGuard.test_existing_guard_still_blocks_without_connection'],
            cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
        try:
            stdout, stderr = proc.communicate(timeout=120)
        except subprocess.TimeoutExpired as exc:
            terminate_injected_process(proc)
            ensure_process_group_gone(proc.pid)
            stop_nested_cluster(parent, self.pgroot, self.env)
            self.__class__.nested_cleanup_unconfirmed = False
            raise AssertionError('startup-failure fixture timed out; nested cluster stopped if identifiable') from exc
        ensure_process_group_gone(proc.pid)
        self.assertNotEqual(proc.returncode,0)
        self.assertIn('intentional failure immediately after cluster start',stderr)
        self.assertEqual(list(parent.iterdir()),[],'failed startup left a cluster or unconfirmed stop')
        self.__class__.nested_cleanup_unconfirmed = False

    def test_timed_out_startup_stops_and_removes_its_own_cluster(self):
        self.assertFalse(self.__class__.nested_cleanup_unconfirmed, 'previous nested fixture not safely cleaned')
        parent=self.root/'failure-injection'; parent.mkdir(mode=0o700, exist_ok=True)
        env=dict(os.environ,ECP_TEST_TMP_ROOT=str(parent),ECP_TEST_INJECT_START_HANG='1',
                 ECP_PG_BINDIR=str(self.pgroot))
        env.pop('ECP_TEST_INJECT_START_FAILURE', None)
        self.__class__.nested_cleanup_unconfirmed = True
        proc=subprocess.Popen([os.sys.executable,'-m','unittest',
            'ops.ecp.tests.test_database_guard.RealDisposableDatabaseGuard.test_existing_guard_still_blocks_without_connection'],
            cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
        ready = False
        try:
            deadline = time.monotonic()+120
            while time.monotonic() < deadline:
                if any(parent.glob('ecp-p002-*/hang-after-start.ready')):
                    ready = True
                    break
                if proc.poll() is not None:
                    break
                time.sleep(.05)
            if not ready:
                raise AssertionError('nested PostgreSQL did not signal startup within the bounded wait')
            try:
                proc.communicate(timeout=.25)
            except subprocess.TimeoutExpired:
                pass
            else:
                raise AssertionError('startup hang exited before the injected timeout')
        finally:
            terminate_injected_process(proc)
            ensure_process_group_gone(proc.pid)
            stop_nested_cluster(parent, self.pgroot, self.env)
            self.__class__.nested_cleanup_unconfirmed = False
        self.assertEqual(list(parent.iterdir()),[], 'timed out nested cluster was not removed after confirmed stop')

if __name__=='__main__': unittest.main()
