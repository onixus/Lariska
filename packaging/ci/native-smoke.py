#!/usr/bin/env python3
"""Real native install, authenticated-heartbeat upgrade, watchdog restart and rollback.

Run only on a disposable administrator/root CI host. Packages are never published.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import subprocess
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument('--kind', choices=['deb', 'rpm', 'msi', 'pkg'], required=True)
parser.add_argument('--dist', type=Path, default=Path('dist'))
parser.add_argument('--evidence', type=Path, default=Path('dist/native-smoke.json'))
args = parser.parse_args()
versions = ['0.4.0', '0.4.1', '0.4.2']
packages = {version: next((args.dist / version).glob('*.' + args.kind)).resolve() for version in versions}
manifests = {version: json.loads(artifact.with_suffix(artifact.suffix + '.manifest.json').read_text()) for version, artifact in packages.items()}
trust = json.loads(Path('packaging/trust/public-trust.json').read_text())
windows = platform.system() == 'Windows'
macos = platform.system() == 'Darwin'
if windows:
    config = Path(r'C:\ProgramData\Lariska\config\lariska.toml')
    state = Path(r'C:\ProgramData\Lariska\state')
    private = Path(r'C:\ProgramData\LariskaUpdater')
    executable = Path(r'C:\Program Files\Lariska\lariska.exe')
    stable = private / 'supervisor.exe'
elif macos:
    config = Path('/Library/Application Support/Lariska/lariska.toml')
    state = Path('/Library/Application Support/Lariska/state')
    private = Path('/Library/Application Support/LariskaUpdater')
    executable = Path('/usr/local/bin/lariska')
    stable = private / 'supervisor'
else:
    config = Path('/etc/lariska/lariska.toml')
    state = Path('/var/lib/lariska')
    private = Path('/var/lib/lariska-updater')
    executable = Path('/usr/bin/lariska')
    stable = private / 'supervisor'
clean_env = {key: value for key, value in os.environ.items() if not key.startswith('LARISKA_')}

def run(*command, check=True, environment=None):
    result = subprocess.run(list(map(str, command)), check=False, env=clean_env if environment is None else environment, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(f'Native command {command[0]} failed ({result.returncode}): {result.stdout[-8192:]} {result.stderr[-8192:]}')
    return result

def ps(script):
    # pwsh 7 launches this harness in CI; its module paths are incompatible with
    # the Windows PowerShell 5.1 process used for service/task control.
    modules = r'C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
    environment = dict(clean_env, PSModulePath=modules, WinPSModulePath=modules)
    environment.pop('PSModuleAnalysisCachePath', None)
    prelude = "$env:PSModulePath='" + modules + "';$env:WinPSModulePath=$env:PSModulePath;$ErrorActionPreference='Stop';"
    return run(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', '-NoProfile', '-NonInteractive', '-Command', prelude + script, environment=environment)

def install(artifact):
    if windows:
        result = run('msiexec.exe', '/i', artifact, '/qn', '/norestart', '/l*v', str(args.dist.resolve() / 'msi-install.log'), check=False)
        if result.returncode not in (0, 3010):
            raise RuntimeError(f'MSI installation failed with {result.returncode}; see msi-install.log')
    elif macos:
        run('/usr/sbin/installer', '-pkg', artifact, '-target', '/')
    elif args.kind == 'deb':
        run('/usr/bin/dpkg', '--install', artifact)
    else:
        run('/usr/bin/rpm', '-U', '--replacepkgs', artifact)

observed = {'agent_ids': set(), 'registered_versions': [], 'inventories': 0, 'heartbeats': 0, 'failed_health_responses': {'register': 0, 'heartbeat': 0}}
desired = {'version': None, 'fail_health': False}
registered = {}
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass
    def reply(self, status, payload):
        content = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)
    def do_GET(self):
        version = self.path.removeprefix('/packages/')
        if not self.path.startswith('/packages/') or version not in packages:
            return self.reply(404, {})
        artifact = packages[version]
        self.send_response(200)
        self.send_header('Content-Length', str(artifact.stat().st_size))
        self.end_headers()
        with artifact.open('rb') as stream:
            while data := stream.read(64 * 1024):
                self.wfile.write(data)
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
        if self.path == '/api/v1/auth/agent/token':
            return self.reply(200, {'access_token': 'native-smoke-token', 'expires_in': 7200})
        if self.headers.get('Authorization') != 'Bearer native-smoke-token':
            return self.reply(401, {})
        agent_id = request['agent_id']
        info = {'agent_id': agent_id, 'status': 'idle', 'inventory_schema_version': 2}
        if self.path == '/api/v1/agent/register':
            registered[agent_id] = request['version']
            observed['agent_ids'].add(agent_id)
            observed['registered_versions'].append(request['version'])
            # Registration and heartbeat both acknowledge health. Record the
            # installed version before rejecting it so supervisor recovery is
            # tested without allowing registration to mark the bad release healthy.
            if desired['fail_health'] and request['version'] == '0.4.2':
                observed['failed_health_responses']['register'] += 1
                return self.reply(503, {'detail': 'Deliberate native health failure'})
            return self.reply(200, info)
        if self.path == '/api/v1/agent/heartbeat':
            observed['heartbeats'] += 1
            if desired['fail_health'] and registered.get(agent_id) == '0.4.2':
                observed['failed_health_responses']['heartbeat'] += 1
                return self.reply(503, {'detail': 'Deliberate native health failure'})
            version = desired['version']
            if version and registered.get(agent_id) != version:
                signed = manifests[version]
                manifest = signed['manifest']
                info['managed_update'] = {'version': version, 'platform': manifest['platform'], 'sha256': manifest['sha256'], 'size_bytes': manifest['size_bytes'], 'url': '/packages/' + version, 'signed_manifest': signed}
            return self.reply(200, info)
        if self.path == '/api/v1/endpoint/inventory':
            observed['inventories'] += 1
            return self.reply(200, {'snapshot_id': request['snapshot_id'], 'status': 'accepted', 'device_id': 'native-ci-device', 'asset_id': None, 'software_count': len(request['software'])})
        self.reply(404, {})

server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()

def wait_for(label, check, seconds=180):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(1)
    raise RuntimeError(f'Timed out waiting for {label}')

def ledger():
    try:
        return json.loads((private / 'update-state.json').read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def control(component, restart=False):
    if windows:
        if component == 'agent':
            ps("Microsoft.PowerShell.Management\\Restart-Service Lariska" if restart else "Microsoft.PowerShell.Management\\Start-Service Lariska")
        else:
            ps(("ScheduledTasks\\Stop-ScheduledTask -TaskName LariskaUpdater; Microsoft.PowerShell.Utility\\Start-Sleep -Seconds 2; " if restart else '') + "ScheduledTasks\\Start-ScheduledTask -TaskName LariskaUpdater")
    elif macos:
        label = 'com.shapoclyack.lariska' + ('-updater' if component == 'updater' else '')
        if restart:
            run('/bin/launchctl', 'kickstart', '-k', 'system/' + label)
        else:
            run('/bin/launchctl', 'bootstrap', 'system', '/Library/LaunchDaemons/' + label + '.plist')
    else:
        run('/usr/bin/systemctl', 'restart' if restart else 'start', 'lariska' + ('-updater' if component == 'updater' else '') + '.service')

try:
    install(packages['0.4.0'])
    assert run(executable, '--version').stdout.strip() == '0.4.0'
    stable_hash = hashlib.sha256(stable.read_bytes()).hexdigest()
    config.parent.mkdir(parents=True, exist_ok=True)
    state.mkdir(parents=True, exist_ok=True)
    key = config.parent / 'provisioning.key'
    key.write_text('native-smoke-enrollment')
    quote = lambda path: "'" + str(path) + "'"
    text = f'''server_url = "http://127.0.0.1:{server.server_port}"
provisioning_key_file = {quote(key)}
state_dir = {quote(state)}
inventory_interval_secs = 10
heartbeat_interval_secs = 10
request_timeout_secs = 10
allow_plain_http = true
allow_insecure_updates = true
[updates]
package_kind = "{args.kind}"
health_timeout_secs = 30
native_state_dir = {quote(private)}
'''
    if windows:
        text += 'allow_self_signed_native = true\nwindows_signer_thumbprint = "' + trust['certificates']['windows']['thumbprint'] + '"\n'
    elif macos:
        text += 'allow_self_signed_native = true\nmacos_signer_sha256 = "' + trust['certificates']['macos']['sha256'] + '"\n'
    text += '[[updates.trusted_keys]]\nid = "' + trust['key_id'] + '"\npublic_key = "' + trust['public_key'] + '"\n'
    config.write_text(text)
    if not windows:
        os.chmod(config, 0o640)
        os.chmod(key, 0o640)
        import grp, pwd
        account = '_lariska' if macos else 'lariska'
        gid = grp.getgrnam(account).gr_gid
        os.chown(config, 0, gid)
        os.chown(key, 0, gid)
        os.chown(state, pwd.getpwnam(account).pw_uid, gid)
    run(stable, 'update-seed', '--config', config, '--manifest', packages['0.4.0'].with_suffix('.' + args.kind + '.manifest.json'), '--artifact', packages['0.4.0'])
    control('agent')
    control('updater')
    wait_for('initial enrolled heartbeat', lambda: observed['heartbeats'] > 0)
    desired['version'] = '0.4.1'
    wait_for('healthy native upgrade committed', lambda: any(item['version'] == '0.4.1' and item['outcome'] == 'healthy' for item in ledger().get('history', [])))
    assert run(executable, '--version').stdout.strip() == '0.4.1'
    assert hashlib.sha256(stable.read_bytes()).hexdigest() == stable_hash
    desired.update(version='0.4.2', fail_health=True)
    wait_for('failed release installed', lambda: '0.4.2' in observed['registered_versions'])
    desired['version'] = None
    # A separate stable supervisor must recover even if it restarts mid-update.
    control('updater', restart=True)
    wait_for('automatic native rollback', lambda: any(item['version'] == '0.4.2' and item['outcome'] == 'rolled_back' for item in ledger().get('history', [])))
    assert run(executable, '--version').stdout.strip() == '0.4.1'
    wait_for('recovered agent registration', lambda: observed['registered_versions'][-1] == '0.4.1')
    assert observed['failed_health_responses']['register'] > 0, observed
    rollback = next(item for item in ledger()['history'] if item['version'] == '0.4.2' and item['outcome'] == 'rolled_back')
    assert rollback['reason'] == 'healthy_heartbeat_timeout', rollback
    assert not any(item['version'] == '0.4.2' and item['outcome'] == 'healthy' for item in ledger().get('history', [])), ledger()
    assert len(observed['agent_ids']) == 1, observed
    assert hashlib.sha256(stable.read_bytes()).hexdigest() == stable_hash
    assert ledger().get('pending') is None
    observed['agent_ids'] = sorted(observed['agent_ids'])
    args.evidence.write_text(json.dumps({'status': 'success', 'kind': args.kind, 'system': platform.system(), 'observed': observed, 'ledger': ledger(), 'stable_watchdog_sha256': stable_hash}, indent=2) + '\n')
    print(f'Native {args.kind} install, healthy upgrade, supervisor restart, rollback and identity persistence passed')
finally:
    if not args.evidence.exists():
        observed['agent_ids'] = sorted(observed['agent_ids'])
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps({'status': 'failed', 'kind': args.kind, 'observed': observed, 'ledger': ledger()}, indent=2) + '\n')
    server.shutdown()
