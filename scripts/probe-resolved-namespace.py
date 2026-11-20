#!/usr/bin/env python3
"""Development probe; runs only in new user/mount/network namespaces."""
import json, os, pathlib, socket, struct, subprocess, sys, tempfile, threading, time
if len(sys.argv) == 1:
    env=os.environ.copy()
    env['ECH_PROBE_HOST_NETNS']=os.readlink('/proc/self/ns/net')
    with tempfile.TemporaryDirectory(prefix='ech-dns-runtime-') as stage:
        env['ECH_RUNTIME_STAGE']=stage
        result=subprocess.call(['unshare','--user',('--map-current-user' if env.get('ECH_DNS_CURRENT_USER') else '--map-root-user'),'--keep-caps','--net','--mount',sys.executable,str(pathlib.Path(__file__).resolve()),'--inside'],env=env)
    raise SystemExit(result)
assert os.readlink('/proc/self/ns/net')!=os.environ['ECH_PROBE_HOST_NETNS']
subprocess.run(['mount','--make-rprivate','/'],check=True)
saved_runtime=None
if os.environ.get('ECH_DNS_CURRENT_USER'):
    saved_runtime=os.environ['ECH_RUNTIME_STAGE']
    subprocess.run(['mount','--rbind',os.environ['XDG_RUNTIME_DIR'],saved_runtime],check=True)
for target in ['/run','/etc']:
    subprocess.run(['mount','-t','tmpfs','-o','mode=0755','tmpfs',target],check=True)
if saved_runtime:
    pathlib.Path(os.environ['XDG_RUNTIME_DIR']).mkdir(parents=True,exist_ok=True)
    subprocess.run(['mount','--rbind',saved_runtime,os.environ['XDG_RUNTIME_DIR']],check=True)
pathlib.Path('/etc/passwd').write_text(f'root:x:0:0:root:/root:/bin/bash\nuser:x:{os.getuid()}:{os.getgid()}:user:/:/bin/bash\nsystemd-resolve:x:{os.getuid()}:{os.getgid()}:resolver:/:/usr/sbin/nologin\n')
pathlib.Path('/etc/group').write_text(f'root:x:0:\nuser:x:{os.getgid()}:\nsystemd-resolve:x:{os.getgid()}:\n')
pathlib.Path('/etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files dns\n')
pathlib.Path('/etc/machine-id').write_text('f31b91864e274567ba1b12717a71e719\n')
pathlib.Path('/etc/systemd').mkdir()
pathlib.Path('/etc/systemd/resolved.conf').write_text('[Resolve]\nDNS=\nFallbackDNS=\nDNSStubListener=yes\nLLMNR=no\nMulticastDNS=no\nDNSSEC=no\n')
pathlib.Path('/run/dbus').mkdir()
pathlib.Path('/run/systemd/resolve').mkdir(parents=True)
pathlib.Path('/etc/resolv.conf').symlink_to('/run/systemd/resolve/stub-resolv.conf')
pathlib.Path('/run/dbus/probe.conf').write_text('<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
subprocess.run(['/usr/bin/ip','link','set','lo','up'],check=True)
env={'PATH':'/usr/bin:/usr/sbin','DBUS_SYSTEM_BUS_ADDRESS':'unix:path=/run/dbus/system_bus_socket','SYSTEMD_LOG_TARGET':'console','SYSTEMD_LOG_LEVEL':'info'}
if os.environ.get('LD_LIBRARY_PATH'):
    env['LD_LIBRARY_PATH']=os.environ['LD_LIBRARY_PATH']
bus=subprocess.Popen(['/usr/bin/dbus-daemon','--nofork','--config-file=/run/dbus/probe.conf'],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
resolved=None
try:
    for _ in range(50):
        if pathlib.Path('/run/dbus/system_bus_socket').exists(): break
        time.sleep(.02)
    resolved_exec=os.environ.get('ECH_RESOLVED_EXEC','/usr/lib/systemd/systemd-resolved')
    resolved=subprocess.Popen([resolved_exec],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    for _ in range(100):
        if resolved.poll() is not None: break
        r=subprocess.run(['/usr/bin/busctl','--system','--no-pager','--timeout=1','get-property','org.freedesktop.resolve1','/org/freedesktop/resolve1','org.freedesktop.resolve1.Manager','ResolvConfMode'],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        if r.returncode==0:
            print('Private systemd-resolved is ready.')
            break
        time.sleep(.02)
    else: raise RuntimeError('private resolved did not become ready')
    if resolved.poll() is not None: raise RuntimeError('private resolved exited')
    if os.environ.get('ECH_DNS_CURRENT_USER'):
        diag=subprocess.run(['/usr/bin/systemd-run','--user','--scope','--quiet','--collect','/usr/bin/true'],env=dict(env,XDG_RUNTIME_DIR=os.environ['XDG_RUNTIME_DIR']),capture_output=True,text=True,timeout=5)
        print('User scope preflight:',diag.returncode,diag.stderr.strip())
    if os.environ.get('ECH_DNS_TEST_EXEC'):
        test_env=env.copy()
        test_env.update(ECH_RESOLVED_NAMESPACE='1',ECH_PROBE_HOST_NETNS=os.environ['ECH_PROBE_HOST_NETNS'])
        if os.environ.get('ECH_ALIAS_WORKER'):
            test_env['ECH_ALIAS_WORKER']=os.environ['ECH_ALIAS_WORKER']
        if os.environ.get('ECH_DNS_CURRENT_USER'):
            test_env.update(EASYCONNECT_HELPER_NAMESPACE='1',EASYCONNECT_CAPTURE_HOST_NETNS=os.environ['ECH_PROBE_HOST_NETNS'],XDG_RUNTIME_DIR=os.environ['XDG_RUNTIME_DIR'])
        test_timeout=150 if os.environ.get('ECH_ALIAS_WORKER') else 45
        subprocess.run([os.environ['ECH_DNS_TEST_EXEC'],'-test.run='+os.environ.get('ECH_DNS_TEST_PATTERN','^TestResolvedNamespaceLifecycle$'),'-test.v',f'-test.timeout={test_timeout}s'],env=test_env,check=True,timeout=test_timeout+5)
    server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    server.bind(('127.0.0.1',0))
    server.settimeout(2)
    queries=[]
    server_errors=[]
    def serve_dns():
        try:
            while True:
                packet,peer=server.recvfrom(4096)
                queries.append(packet)
                assert len(packet)>=12
                end=12
                while packet[end]!=0: end+=1+packet[end]
                end+=5
                response=packet[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+packet[12:end]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton('10.42.0.8')
                server.sendto(response,peer)
        except OSError: pass
        except Exception as exc: server_errors.append(str(exc))
    thread=threading.Thread(target=serve_dns,daemon=True);thread.start()
    def run(*args):
        result=subprocess.run(args,env=env,capture_output=True,text=True,timeout=8)
        if result.returncode: raise RuntimeError(' '.join(args)+': '+result.stderr)
        return result.stdout.strip()
    run('/usr/bin/ip','link','add','echprobe','type','dummy')
    run('/usr/bin/ip','addr','add','192.0.2.1/32','dev','echprobe')
    run('/usr/bin/ip','link','set','echprobe','up')
    index=str(socket.if_nametoindex('echprobe'))
    time.sleep(.05)
    def call(method,signature,*args):
        return run('/usr/bin/busctl','--system','--timeout=5','call','org.freedesktop.resolve1','/org/freedesktop/resolve1','org.freedesktop.resolve1.Manager',method,signature,*args)
    call('SetLinkDNSEx','ia(iayqs)',index,'1','2','4','127','0','0','1',str(server.getsockname()[1]),'')
    call('SetLinkDefaultRoute','ib',index,'false')
    call('SetLinkDomains','ia(sb)',index,'1','corp.test','true')
    answer=call('ResolveHostname','isit','0','app.corp.test','2','6145')
    assert '10 42 0 8' in answer, answer
    assert queries and not server_errors
    def domains():
        out=run('/usr/bin/busctl','--system','--json=short','get-property','org.freedesktop.resolve1','/org/freedesktop/resolve1','org.freedesktop.resolve1.Manager','Domains')
        return json.loads(out)['data']
    assert any('corp.test' in str(item) for item in domains())
    # A separate existing link's routing domain must survive our cleanup.
    run('/usr/bin/ip','link','add','foreignprobe','type','dummy')
    run('/usr/bin/ip','addr','add','192.0.2.2/32','dev','foreignprobe')
    run('/usr/bin/ip','link','set','foreignprobe','up')
    foreign_index=str(socket.if_nametoindex('foreignprobe'))
    time.sleep(.05)
    call('SetLinkDomains','ia(sb)',foreign_index,'1','other.test','true')
    before=len(queries)
    unrelated=subprocess.run(['/usr/bin/busctl','--system','--timeout=2','call','org.freedesktop.resolve1','/org/freedesktop/resolve1','org.freedesktop.resolve1.Manager','ResolveHostname','isit','0','public.example','2','6145'],env=env,capture_output=True,text=True,timeout=4)
    assert unrelated.returncode!=0 and len(queries)==before, 'non-internal query reached private DNS'
    print('PASS: internal domain reaches loopback DNS; unrelated query does not.')
    run('/usr/bin/ip','link','delete','echprobe')
    time.sleep(.05)
    remaining=str(domains())
    assert 'corp.test' not in remaining and 'other.test' in remaining, remaining
    run('/usr/bin/ip','link','delete','foreignprobe')
    server.close()
    print('PASS: deleting owned link removes its DNS policy and retains foreign policy.')

finally:
    for process in [resolved,bus]:
        if process is not None:
            process.terminate()
            try: output=process.communicate(timeout=3)[0]
            except subprocess.TimeoutExpired: process.kill();output=process.communicate()[0]
            if sys.exc_info()[0] is not None: print(output[-3000:])
