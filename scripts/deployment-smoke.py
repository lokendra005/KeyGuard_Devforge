#!/usr/bin/env python3
"""Isolated real TLS deployment check: one authority, three separate-cache containers.
Requires a locally built keyguard-track4:review image, Docker, Node and OpenSSL.
No published ports, pulls, live state or external network are used.
"""
from pathlib import Path
import json, os, shutil, subprocess, tempfile, uuid

ROOT = Path(__file__).resolve().parents[1]
image = os.environ.get('KIG_REVIEW_IMAGE', 'keyguard-track4:review')
name = 'kig-deploy-' + uuid.uuid4().hex[:10]
containers = []

def run(args, **kw):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw)

def save(path, value):
    path.write_text(json.dumps(value)); path.chmod(0o600)

with tempfile.TemporaryDirectory(prefix='keyguard-deployment-') as temporary:
    base = Path(temporary)
    keys, config, clients = base/'keys', base/'config', base/'clients'
    config.mkdir(mode=0o700); clients.mkdir(mode=0o700)
    run(['node', str(ROOT/'track4/examples/init.cjs'), str(keys)])
    authority = base/'authority'; authority.mkdir(mode=0o700)
    run(['node', str(ROOT/'track4/cli.cjs'), 'init', '--state', str(authority), '--input', str(keys/'setup.json')])
    query = base/'status.json'; save(query, {'op':'status'})
    status = json.loads(run(['node', str(ROOT/'track4/cli.cjs'), 'local', '--state', str(authority), '--body', str(query)]).stdout)
    save(config/'trust.json', {'authority':status['authority'], 'public_key':status['checkpoint']['public_key']})
    run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=api','-addext','subjectAltName=DNS:api,DNS:node-a,DNS:node-b,DNS:node-c','-keyout',str(config/'key.pem'),'-out',str(config/'cert.pem')])
    (config/'key.pem').chmod(0o600)
    for identity in ['operator','owner']:
        shutil.copy2(keys/(identity+'.json'),clients/(identity+'.json'))
    shutil.copy2(config/'cert.pem',clients/'ca.pem')
    for node in ['node-a','node-b','node-c']:
        state=base/node; state.mkdir(mode=0o700)
        binding=config/(node+'-binding.json'); key=config/(node+'-key.json')
        run(['node',str(ROOT/'track4/cli.cjs'),'replica-init','--state',str(state),'--node',node,'--trust',str(config/'trust.json'),'--out',str(binding)])
        run(['node',str(ROOT/'track4/cli.cjs'),'keygen','--out',str(key)])
        # Trusted local enrollment still checks possession and binds this unique node key.
        enrollment=base/(node+'-enroll.cjs')
        enrollment.write_text("const fs=require('node:fs'),C=require("+json.dumps(str(ROOT/'track4/crypto.cjs'))+");const key=JSON.parse(fs.readFileSync(process.argv[2])),binding=JSON.parse(fs.readFileSync(process.argv[3])),authority=process.argv[4],actor=process.argv[5];console.log(JSON.stringify({op:'enroll',actor,role:'replicator',public_key:key.public_key,...binding,proof:C.sign(key.private_key,'KIG/enroll/v1',{authority,actor,role:'replicator',...binding})}));")
        body=base/(node+'-enroll.json'); body.write_text(run(['node',str(enrollment),str(key),str(binding),status['authority'],node]).stdout)
        run(['node',str(ROOT/'track4/cli.cjs'),'local','--state',str(authority),'--body',str(body)])
        save(config/(node+'.json'),{'upstream':'https://api:8444','actor':node,'key_file':'/config/'+key.name,'trust_file':'/config/trust.json','ca_file':'/config/cert.pem','lease_ms':5000,'sync_ms':100})
    script = clients/'check.cjs'
    script.write_text('''"use strict";
const fs=require("node:fs"), A=require("node:assert/strict"), {client}=require("/app/track4/client.cjs");
const C=require("/app/track4/crypto.cjs");
const key=(name)=>JSON.parse(fs.readFileSync("/clients/"+name+".json"));
const peers=["api","node-a","node-b","node-c"];
(async()=>{
  for(const host of peers){
    const r=client("https://"+host+":8444",key("owner"),"owner","/clients/ca.pem");
    let ready=false;
    for(let i=0;i<80;i++){try{ready=(await r.request("/healthz")).ready;if(ready)break;}catch{}await new Promise(resolve=>setTimeout(resolve,100));}
    A.ok(ready,host+" not ready");
    const answer=await r.call({op:"read",actor:"owner",asset:"document",request_id:C.random()}); A.equal(answer.decision,"allow");
  }
  const admin=client("https://api:8444",key("operator"),"operator","/clients/ca.pem");
  A.equal((await admin.call({op:"revoke",actor:"owner"})).revoked,true);
  const started=performance.now(), measured=[];
  for(const host of peers.slice(1)){
    const r=client("https://"+host+":8444",key("owner"),"owner","/clients/ca.pem");
    let denied=false;
    for(let i=0;i<80;i++){
      try{await r.call({op:"read",actor:"owner",asset:"document",request_id:C.random()});}
      catch(e){A.ok(["UNAUTHORIZED","LEASE_EXPIRED"].includes(e.code),e.code);denied=true;break;}
      await new Promise(resolve=>setTimeout(resolve,100));
    }
    A.ok(denied,host+" did not revoke"); measured.push({node:host,observed_ms:Math.ceil(performance.now()-started)});
  }
  console.log(JSON.stringify({result:"PASS",tls:"1.3 with explicit CA",authority_containers:1,independent_replica_containers:3,external_network:false,read_before_revoke:true,denied_after_revoke:measured}));
})().catch(e=>{console.error(e.message);process.exitCode=1;});
''')
    run(['docker','network','create','--internal',name])
    try:
        for host in ['api','node-a','node-b','node-c']:
            state = authority if host=='api' else base/host
            state.mkdir(mode=0o700,exist_ok=True)
            container=name+'-'+host; containers.append(container)
            args=['docker','run','-d','--pull','never','--name',container,'--network',name,'--network-alias',host,'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','512m','--pids-limit','64','--user',f'{os.getuid()}:{os.getgid()}','--tmpfs','/tmp:rw,noexec,nosuid,size=64m','-v',f'{state}:/state','-v',f'{config}:/config:ro',image,'node','track4/cli.cjs','serve','--state','/state','--host','0.0.0.0','--port','8444','--cert','/config/cert.pem','--tls-key','/config/key.pem','--origin',f'https://{host}:8444']
            if host!='api': args+=['--replica','/config/'+host+'.json','--node',host]
            run(args)
        checked=run(['docker','run','--rm','--pull','never','--network',name,'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','512m','--user',f'{os.getuid()}:{os.getgid()}','-v',f'{clients}:/clients:ro',image,'node','/clients/check.cjs'])
        print(checked.stdout,end='')
    except Exception:
        for container in containers:
            logs=subprocess.run(['docker','logs','--tail','5',container],capture_output=True,text=True)
            print(container,logs.stdout,logs.stderr)
        raise
    finally:
        for container in containers:
            subprocess.run(['docker','rm','-f',container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(['docker','network','rm',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
