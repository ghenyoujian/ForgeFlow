#!/usr/bin/env python3
"""Export implemented route inventory from the Axum composition source."""
import json,pathlib,re
root=pathlib.Path(__file__).resolve().parents[1]
source=(root/'crates/api/src/lib.rs').read_text()
routes=[]
for match in re.finditer(r'\.route\(\s*"([^"]+)"\s*,',source):
 start=match.end();depth=1;position=start
 while position<len(source) and depth:
  char=source[position]
  if char=='(':depth+=1
  elif char==')':depth-=1
  position+=1
 expression=source[start:position-1]
 methods=sorted(set(re.findall(r'\b(get|post|patch|delete|put)\(',expression)))
 path=match.group(1)
 if path!='/healthz':path='/api/v1'+path
 routes.append({'path':path,'methods':[m.upper() for m in methods],'owner':'A09','priority':'P0','source':'auth.json' if path.endswith(('/me','/session','/logout')) else 'postgresql','handlers':expression.strip()})
# The restricted physical-recovery router reuses two ordinary Owner routes.
# One public inventory entry per path must retain the union of actual methods.
unique={}
for route in routes:
 prior=unique.get(route['path'])
 if prior:
  prior['methods']=sorted(set(prior['methods'])|set(route['methods']))
 else:unique[route['path']]=route
routes=sorted(unique.values(),key=lambda r:r['path'])
(root/'crates/api/routes.json').write_text(json.dumps({'schema_version':'forgeflow.routes.v1','routes':routes},indent=2)+'\n')
existing_path=root/'crates/api/openapi.json'
existing=json.loads(existing_path.read_text()) if existing_path.exists() else {}
paths={}
for route in routes:
 operations={}
 for method in route['methods']:
  parameters=[{'name':name,'in':'path','required':True,'schema':{'type':'string'}} for name in re.findall(r'\{([^}]+)\}',route['path'])]
  public=route['path'].endswith(('/healthz','/session','/registrations','/tutorials/personal-site')) or '/plugins/dsh-forgeflow-network/' in route['path']
  operations[method.lower()]={'parameters':parameters,'operationId':method.lower()+'_'+re.sub('[^a-zA-Z0-9]','_',route['path']).strip('_'),'x-owner':'A09','x-priority':'P0','security':[] if public else [{'bearerAuth':[]}],'responses':{'200':{'description':'Query or command receipt; canonical DTO references are documented in HTTP_CONTRACT.md'},'401':{'description':'Authentication required or revoked'},'403':{'description':'Workspace, project, role or connector permission denied'},'409':{'description':'Revision, fencing, idempotency or business conflict'},'422':{'description':'Invalid canonical request or domain invariant'}}}
  if method not in ('GET','HEAD'):
   if not route['path'].endswith(('/session','/registrations','/heartbeat','/worker-events','/execution-result','/handoff-result','/native-controller','/capsule-checks')) and not '/agent-network/' in route['path'] and not '/invitations' in route['path'] and not '/members/' in route['path'] and not '/account' in route['path']:
    operations[method.lower()]['parameters'].append({'name':'Idempotency-Key','in':'header','required':True,'schema':{'type':'string','minLength':1,'maxLength':200}})
   operations[method.lower()]['requestBody']={'required':False,'content':{'application/json':{'schema':{'type':'object'}}}}
 for method in operations:
  prior=existing.get('paths',{}).get(route['path'],{}).get(method)
  if prior is not None:
   operations[method]=prior
 paths[route['path']]=operations
openapi={'openapi':'3.1.0','info':{'title':'ForgeFlow Control API','version':'0.1.0'},'paths':paths,'components':existing.get('components',{'securitySchemes':{'bearerAuth':{'type':'http','scheme':'bearer'}}})}
(root/'crates/api/openapi.json').write_text(json.dumps(openapi,indent=2)+'\n')
print(json.dumps({'routes':len(routes),'operations':sum(len(r['methods']) for r in routes),'scope':'implemented route inventory; full canonical DTO schemas live in contracts/' }))
