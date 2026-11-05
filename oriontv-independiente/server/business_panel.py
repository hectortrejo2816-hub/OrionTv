"""Business operations without credits. Additive SQLite migrations and owner scoping."""
import asyncio, hashlib, http.client, ipaddress, json, re, secrets, socket, sqlite3, ssl, threading, time
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import urlsplit, urlencode
from fastapi import Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

PERMISSIONS = {'create': True, 'edit': True, 'renew': True, 'delete': False, 'demo': False, 'reset': False, 'announce': False, 'payments': True, 'diagnostics': True, 'mateo': True}
ERRORS = {'network','timeout','codec','audio','video','playback','unknown'}

def install_business(ns):
 app, db, operator, admin, device, check = (ns[k] for k in ('app','db','operator','admin','device','check'))
 root=Path(__file__).parent; data=ns['DATA']; backup_dir=data/'backups'; backup_dir.mkdir(exist_ok=True)
 with db() as c:
  for table,col,decl in [('licenses','deleted_at','INTEGER'),('licenses','before_delete_enabled','INTEGER'),('licenses','contact',"TEXT NOT NULL DEFAULT ''")]:
   if col not in {r['name'] for r in c.execute('PRAGMA table_info('+table+')')}:c.execute('ALTER TABLE '+table+' ADD COLUMN '+col+' '+decl)
  c.executescript('''
CREATE TABLE IF NOT EXISTS business_resellers(name TEXT PRIMARY KEY REFERENCES admins(name),permissions TEXT NOT NULL,brand TEXT NOT NULL DEFAULT '',whatsapp TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS business_payments(id TEXT PRIMARY KEY,license_id TEXT NOT NULL REFERENCES licenses(id),amount_cents INTEGER NOT NULL,currency TEXT NOT NULL,paid_at INTEGER NOT NULL,due_at INTEGER,method TEXT NOT NULL,reference TEXT NOT NULL,actor TEXT NOT NULL,created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS business_audit(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT NOT NULL,owner_id TEXT,license_id TEXT,action TEXT NOT NULL,at INTEGER NOT NULL,detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS business_telemetry(device_id TEXT PRIMARY KEY REFERENCES devices(id),version_code INTEGER NOT NULL,version_name TEXT NOT NULL,sdk INTEGER NOT NULL,model TEXT NOT NULL,last_seen INTEGER NOT NULL,error_code TEXT NOT NULL DEFAULT '',error_at INTEGER,engine TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS business_notices(id TEXT PRIMARY KEY,owner_id TEXT,license_ids TEXT NOT NULL,title TEXT NOT NULL,body TEXT NOT NULL,expires INTEGER NOT NULL,created INTEGER NOT NULL,actor TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS business_proposals(id TEXT PRIMARY KEY,actor TEXT NOT NULL,payload TEXT NOT NULL,state TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS business_sources(license_id TEXT NOT NULL,profile_id TEXT NOT NULL,status TEXT NOT NULL,expires INTEGER,checked INTEGER NOT NULL,PRIMARY KEY(license_id,profile_id));
CREATE TRIGGER IF NOT EXISTS business_trash_disabled AFTER UPDATE OF enabled ON licenses WHEN NEW.deleted_at IS NOT NULL AND NEW.enabled!=0 BEGIN UPDATE licenses SET enabled=0 WHERE id=NEW.id; END;
''')
 def now():return int(time.time())
 def clean(b,key,n=100):
  v=b.get(key,'');check(isinstance(v,str) and len(v)<=n,'Campo inválido: '+key);return v.strip()
 def require(actor,perm):
  if actor['role']=='admin':return
  with db() as c:r=c.execute('SELECT permissions FROM business_resellers WHERE name=?',(actor['name'],)).fetchone()
  perms=PERMISSIONS| (json.loads(r[0]) if r else {})
  check(perms.get(perm,False),'No tienes permiso: '+perm,403)
 def owned(c,actor,lid,trash=False):
  r=c.execute('SELECT * FROM licenses WHERE id=?',(lid,)).fetchone()
  check(r and (actor['role']=='admin' or r['owner_id']==actor['name']),'Cliente no encontrado',404)
  check(trash or r['deleted_at'] is None,'Este cliente está en la papelera',409);return dict(r)
 def audit(c,actor,action,l=None,detail=''):
  c.execute('INSERT INTO business_audit(actor,owner_id,license_id,action,at,detail) VALUES(?,?,?,?,?,?)',(actor['name'],l.get('owner_id') if l else None,l.get('id') if l else None,action,now(),detail[:300]))
 def related(c,did):
  d=c.execute('SELECT mac FROM devices WHERE id=?',(did,)).fetchone()
  if not d:return None
  r=c.execute('SELECT * FROM licenses WHERE mac=? OR device_id=? OR id IN(SELECT license_id FROM license_devices WHERE device_id=?) ORDER BY expires DESC LIMIT 1',(d['mac'],did,did)).fetchone()
  return dict(r) if r else None
 @app.middleware('http')
 async def permissions_and_audit(req,call_next):
  actor=None;payload=None;path=req.url.path
  if path.startswith('/api/admin/') and req.method not in ('GET','HEAD') and path not in ('/api/admin/login','/api/admin/logout'):
   try:
    actor=operator(req)
    if path=='/api/admin/license':
     b=await req.json();payload=b
     if not isinstance(b,dict):raise HTTPException(400,'Solicitud inválida')
     if b.get('id'):
      ns['own_license'](actor,b['id'])
      with db() as c:old=owned(c,actor,b['id'])
      require(actor,'edit')
      if int(b.get('months',0)):require(actor,'renew')
      if str(b.get('mac','')).upper().replace('-',':')!=str(old['mac'] or ''):require(actor,'reset')
     else:require(actor,'create')
    if path.startswith('/api/admin/mateo/'):require(actor,'mateo')
    if path.endswith('/playlists') or path=='/api/admin/channels':require(actor,'edit')
   except HTTPException as e:return JSONResponse({'detail':e.detail},status_code=e.status_code)
   except (TypeError,ValueError):return JSONResponse({'detail':'Solicitud inválida'},status_code=400)
  response=await call_next(req)
  if actor and response.status_code<300 and not path.startswith('/api/admin/business'):
   with db() as c:
    l=None
    if payload is not None:
     row=c.execute('SELECT id,owner_id FROM licenses WHERE id=? OR (mode=? AND mac=?) OR (mode=? AND username=?)',(payload.get('id'), 'mac',str(payload.get('mac','')).upper().replace('-',':'),'credentials',str(payload.get('username','')).lower())).fetchone()
     l=dict(row) if row else None
    audit(c,actor,'panel:'+path.rsplit('/',1)[-1],l)
  return response
 @app.get('/gestion',include_in_schema=False)
 def management(actor=Depends(operator)):return FileResponse(root/'gestion.html')
 @app.get('/api/admin/business')
 def overview(actor=Depends(operator)):
  with db() as c:
   rows=[dict(r) for r in c.execute('SELECT id,name,mode,mac,username,expires,enabled,owner_id,device_id,contact,deleted_at FROM licenses ORDER BY name') if actor['role']=='admin' or r['owner_id']==actor['name']]
   ids={r['id'] for r in rows}; clients=[]
   published=c.execute('SELECT payload FROM apk_publication WHERE id=1').fetchone();target=json.loads(published[0]).get('version_code') if published else None
   for r in rows:
    dids=[x[0] for x in c.execute('SELECT id FROM devices WHERE mac=? OR id=? OR id IN(SELECT device_id FROM license_devices WHERE license_id=?)',(r['mac'],r['device_id'],r['id']))]
    r['devices']=[]
    for did in dids:
     t=c.execute('SELECT * FROM business_telemetry WHERE device_id=?',(did,)).fetchone()
     item=dict(t) if t else {'device_id':did,'version_code':None,'last_seen':None}
     item['update_status']='Sin reporte' if not t else 'Sin versión publicada' if target is None else 'Actualizada' if t['version_code']>=target else 'Pendiente'
     r['devices'].append(item)
    r['sources']=[dict(x) for x in c.execute('SELECT profile_id,status,expires,checked FROM business_sources WHERE license_id=?',(r['id'],))]
    r['last_payment']=dict(p) if (p:=c.execute('SELECT amount_cents,currency,paid_at,due_at,method,reference FROM business_payments WHERE license_id=? ORDER BY created DESC,rowid DESC LIMIT 1',(r['id'],)).fetchone()) else None
    clients.append(r)
   payments=[dict(x) for x in c.execute('SELECT * FROM business_payments ORDER BY created DESC LIMIT 1000') if x['license_id'] in ids]
   # Owner scoping in SQL before limiting prevents other reseller activity consuming the window.
   clause='' if actor['role']=='admin' else ' WHERE owner_id=? OR actor=?'
   args=() if actor['role']=='admin' else (actor['name'],actor['name'])
   history=[dict(x) for x in c.execute('SELECT * FROM business_audit'+clause+' ORDER BY id DESC LIMIT 200',args)]
   resellers=[dict(x) for x in c.execute("SELECT a.name,a.display_name,COALESCE(b.permissions,'{}') permissions,COALESCE(b.brand,'') brand,COALESCE(b.whatsapp,'') whatsapp FROM admins a LEFT JOIN business_resellers b ON b.name=a.name WHERE a.role='reseller'")] if actor['role']=='admin' else []
   own=c.execute('SELECT * FROM business_resellers WHERE name=?',(actor['name'],)).fetchone()
   notices=[dict(x) for x in c.execute('SELECT id,title,body,expires,owner_id FROM business_notices ORDER BY created DESC') if actor['role']=='admin' or x['owner_id']==actor['name']]
  return {'clients':clients,'payments':payments,'history':history,'resellers':resellers,'permissions':PERMISSIONS|(json.loads(own['permissions']) if own else {}),'brand':own['brand'] if own else '', 'whatsapp':own['whatsapp'] if own else '', 'role':actor['role'],'notices':notices,'target_version':target}
 @app.put('/api/admin/business/reseller/{name}')
 async def reseller_settings(name:str,req:Request,actor=Depends(admin)):
  b=await req.json();perms=b.get('permissions',{})
  check(isinstance(perms,dict) and set(perms)<=set(PERMISSIONS) and all(type(v)is bool for v in perms.values()),'Permisos inválidos')
  brand=clean(b,'brand',80);wa=clean(b,'whatsapp',20);check(not wa or re.fullmatch(r'\+?[0-9]{7,15}',wa),'WhatsApp: código de país y números')
  with db() as c:
   check(c.execute("SELECT 1 FROM admins WHERE name=? AND role='reseller'",(name,)).fetchone(),'Revendedor no encontrado',404)
   c.execute('INSERT INTO business_resellers VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET permissions=excluded.permissions,brand=excluded.brand,whatsapp=excluded.whatsapp',(name,json.dumps(PERMISSIONS|perms),brand,wa));audit(c,actor,'Permisos y marca de revendedor',detail=name)
  return {'ok':True}
 @app.post('/api/admin/business/payment')
 async def payment(req:Request,actor=Depends(operator)):
  require(actor,'payments');b=await req.json()
  try:
   value=Decimal(str(b.get('amount')));check(value.is_finite() and value>0 and value<=10000000 and value.as_tuple().exponent>=-2,'Importe inválido');cents=int(value*100)
   paid=int(b.get('paid_at',now()));due=int(b['due_at']) if b.get('due_at') else None
  except (ValueError,TypeError,InvalidOperation):raise HTTPException(400,'Importe o fecha inválidos')
  currency=b.get('currency','MXN');check(currency in ('MXN','USD') and 0<paid<=now()+86400 and (due is None or 0<due<4102444800),'Moneda o fecha inválida')
  with db() as c:
   l=owned(c,actor,b.get('license_id'));c.execute('INSERT INTO business_payments VALUES(?,?,?,?,?,?,?,?,?,?)',(secrets.token_hex(16),l['id'],cents,currency,paid,due,clean(b,'method',40),clean(b,'reference',100),actor['name'],now()));audit(c,actor,'Pago registrado',l, str(cents)+' '+currency)
  return {'ok':True}
 @app.put('/api/admin/business/contact/{lid}')
 async def contact(lid:str,req:Request,actor=Depends(operator)):
  require(actor,'edit');b=await req.json();value=clean(b,'contact',100)
  with db() as c:l=owned(c,actor,lid);c.execute('UPDATE licenses SET contact=? WHERE id=?',(value,lid));audit(c,actor,'Contacto actualizado',l)
  return {'ok':True}
 def ids_from(b):
  ids=b.get('ids');check(isinstance(ids,list) and 0<len(ids)<=100 and len(set(ids))==len(ids) and all(isinstance(i,str) for i in ids),'Selecciona de 1 a 100 clientes');return ids
 def apply_batch(c,actor,b):
  ids=ids_from(b);action=b.get('action');check(action in ('renew','suspend','enable','trash','restore'),'Acción inválida')
  require(actor,{'renew':'renew','trash':'delete','restore':'delete'}.get(action,'edit'))
  clients=[owned(c,actor,i,trash=action=='restore') for i in ids]
  months=b.get('months',1);check(type(months)is int and 1<=months<=12,'Meses inválidos')
  for l in clients:
   if action=='restore':
    check(l['deleted_at'] is not None,'El cliente no está en papelera');c.execute('UPDATE licenses SET deleted_at=NULL,enabled=COALESCE(before_delete_enabled,0),before_delete_enabled=NULL WHERE id=?',(l['id'],))
   elif action=='trash':c.execute('UPDATE licenses SET deleted_at=?,before_delete_enabled=enabled,enabled=0 WHERE id=?',(now(),l['id']))
   elif action=='renew':c.execute('UPDATE licenses SET expires=? WHERE id=?',(ns['months_after'](max(now(),l['expires']),months),l['id']))
   else:c.execute('UPDATE licenses SET enabled=? WHERE id=?',(int(action=='enable'),l['id']))
   audit(c,actor,action,l,str(months) if action=='renew' else '')
  return {'ok':True,'count':len(clients)}
 @app.post('/api/admin/business/batch')
 async def batch(req:Request,actor=Depends(operator)):
  b=await req.json()
  with db() as c:c.execute('BEGIN IMMEDIATE');return apply_batch(c,actor,b)
 @app.post('/api/admin/business/reset-device/{lid}')
 async def reset_device(lid:str,req:Request,actor=Depends(operator)):
  require(actor,'reset');b=await req.json();code=clean(b,'code',30).upper().replace('-',':')
  with db() as c:
   c.execute('BEGIN IMMEDIATE');l=owned(c,actor,lid)
   if l['mode']=='mac':
    target=c.execute('SELECT id FROM devices WHERE mac=?',(code,)).fetchone();check(target,'El código nuevo debe estar registrado por la app')
    check(not c.execute('SELECT 1 FROM licenses WHERE id!=? AND (mac=? OR device_id=? OR id IN(SELECT license_id FROM license_devices WHERE device_id=?))',(lid,code,target['id'],target['id'])).fetchone(),'El dispositivo ya tiene una cuenta',409)
    c.execute('UPDATE licenses SET mac=?,device_id=? WHERE id=?',(code,target['id'],lid))
   else:
    # Rotate the activation password so the former client cannot immediately rebind.
    password=clean(b,'password',128);check(len(password)>=8,'Agrega una contraseña nueva de mínimo 8 caracteres')
    c.execute('UPDATE licenses SET device_id=NULL,password=? WHERE id=?',(ns['pw_hash'](password),lid))
   c.execute('DELETE FROM license_devices WHERE license_id=?',(lid,));audit(c,actor,'Dispositivo liberado o sustituido',l)
  return {'ok':True,'expires':l['expires']}
 @app.post('/api/admin/business/demo')
 async def give_demo(req:Request,actor=Depends(operator)):
  require(actor,'demo');b=await req.json();code=clean(b,'code',30).upper();did=None
  with db() as c:
   c.execute('BEGIN IMMEDIATE');conf=c.execute('SELECT * FROM config WHERE id=1').fetchone();check(conf['enabled'],'El administrador debe habilitar la cuenta demo')
   if actor['role']!='admin':check(ns['allowed_dns'](c,actor,conf['dns_id']),'El DNS demo no está autorizado',403)
   d=c.execute('SELECT * FROM devices WHERE mac=?',(code,)).fetchone();check(d,'Código no registrado');check(not related(c,d['id']),'Ya tiene cuenta asignada',409);check(not d['demo_used'],'Este equipo ya usó su demo',409)
   c.execute('UPDATE devices SET demo_used=1,demo_started=?,demo_expires=? WHERE id=?',(now(),now()+7200,d['id']));audit(c,actor,'Demo iniciada',detail=code)
  return {'ok':True}
 @app.post('/api/admin/business/notice')
 async def notice(req:Request,actor=Depends(operator)):
  require(actor,'announce');b=await req.json();title=clean(b,'title',100);body=clean(b,'body',1000);days=b.get('days',7);ids=b.get('ids',[])
  check(title and body and type(days)is int and 1<=days<=30 and isinstance(ids,list) and len(ids)<=100 and all(isinstance(i,str) for i in ids),'Aviso inválido')
  with db() as c:
   for i in ids:owned(c,actor,i)
   c.execute('INSERT INTO business_notices VALUES(?,?,?,?,?,?,?,?)',(secrets.token_hex(16),None if actor['role']=='admin' else actor['name'],json.dumps(ids),title,body,now()+days*86400,now(),actor['name']));audit(c,actor,'Aviso publicado',detail='seleccionados' if ids else 'todos los propios')
  return {'ok':True}
 @app.delete('/api/admin/business/notice/{nid}')
 def remove_notice(nid:str,actor=Depends(operator)):
  require(actor,'announce')
  with db() as c:
   n=c.execute('SELECT owner_id FROM business_notices WHERE id=?',(nid,)).fetchone();check(n and (actor['role']=='admin' or n['owner_id']==actor['name']),'Aviso no encontrado',404);c.execute('DELETE FROM business_notices WHERE id=?',(nid,));audit(c,actor,'Aviso retirado')
  return {'ok':True}
 @app.post('/api/device/report')
 async def report(req:Request,d=Depends(device)):
  ns['throttle'](req,'report:'+d['id'],6);b=await req.json();v=b.get('version_code');sdk=b.get('sdk');error=clean(b,'error_code',20);engine=clean(b,'engine',20)
  check(type(v)is int and 1<=v<=2147483647 and type(sdk)is int and 23<=sdk<=10000 and error in ERRORS|{''} and engine in ('','VLC','IJK','Media3'),'Reporte inválido')
  with db() as c:
   c.execute('INSERT INTO business_telemetry VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET version_code=excluded.version_code,version_name=excluded.version_name,sdk=excluded.sdk,model=excluded.model,last_seen=excluded.last_seen,error_code=CASE WHEN excluded.error_code!=\'\' THEN excluded.error_code ELSE business_telemetry.error_code END,error_at=CASE WHEN excluded.error_code!=\'\' THEN excluded.error_at ELSE business_telemetry.error_at END,engine=excluded.engine',(d['id'],v,clean(b,'version_name',100),sdk,clean(b,'model',100),now(),error,now() if error else None,engine))
   l=related(c,d['id']);profile=c.execute('SELECT brand,whatsapp FROM business_resellers WHERE name=?',(l['owner_id'],)).fetchone() if l and l['deleted_at'] is None else None
   notices=[]
   if l and l['enabled'] and l['deleted_at'] is None and l['expires']>now():
    for r in c.execute('SELECT * FROM business_notices WHERE expires>? ORDER BY created DESC',(now(),)):
     ids=json.loads(r['license_ids'])
     if (r['owner_id'] is None or r['owner_id']==l['owner_id']) and (not ids or l['id'] in ids):notices.append({k:r[k] for k in ('id','title','body','expires')})
  return {'ok':True,'notices':notices[:10],'support':dict(profile) if profile else {'brand':'OrionTV Premium','whatsapp':''}}
 # MATEO prepares a concrete action; confirmation checks ownership, permissions and state again.
 @app.post('/api/admin/business/mateo/prepare')
 async def prepare_action(req:Request,actor=Depends(operator)):
  b=await req.json();ids=ids_from(b);check(b.get('action') in ('renew','assign_list'),'Acción MATEO inválida')
  require(actor,'mateo');require(actor,'renew' if b['action']=='renew' else 'edit')
  with db() as c:
   clients=[owned(c,actor,i) for i in ids]
   if b['action']=='renew':check(type(b.get('months'))is int and 1<=b['months']<=12,'Meses inválidos');payload={'ids':ids,'action':'renew','months':b['months']}
   else:
    check(len(ids)==1,'Selecciona un cliente');dns=clean(b,'dns_id',100)
    check(c.execute('SELECT 1 FROM dns WHERE id=?',(dns,)).fetchone() and ns['allowed_dns'](c,actor,dns),'Lista no autorizada',403)
    l=clients[0]
    if l['owner_id']:check(ns['allowed_dns'](c,{'role':'reseller','name':l['owner_id']},dns),'Lista no autorizada al propietario',403)
    check(dns!=l['dns_id'] and not c.execute('SELECT 1 FROM license_playlists WHERE license_id=? AND dns_id=?',(l['id'],dns)).fetchone(),'La lista ya está asignada')
    # Credentials belong to each provider; never copy one provider's credentials to another.
    su=clean(b,'service_user',128);sp=clean(b,'service_password',256);check(su and sp,'Completa las credenciales de esa lista')
    count=c.execute('SELECT count(*) FROM license_playlists WHERE license_id=?',(l['id'],)).fetchone()[0];check(count<4,'Máximo 5 listas por cliente')
    payload={'ids':ids,'action':'assign_list','dns_id':dns,'service_user':su,'service_password':ns['seal'](sp)}
   state=json.dumps([(l['id'],l['expires'],l['enabled'],l['owner_id'],l['deleted_at']) for l in clients]);pid=secrets.token_urlsafe(24)
   c.execute('DELETE FROM business_proposals WHERE expires<?',(now(),));c.execute('INSERT INTO business_proposals VALUES(?,?,?,?,?)',(pid,actor['name'],json.dumps(payload),state,now()+300))
   return {'proposal_id':pid,'message':('Renovar '+str(b['months'])+' mes(es): ' if b['action']=='renew' else 'Añadir lista a: ')+', '.join(l['name'] for l in clients),'expires_in':300}
 @app.post('/api/admin/business/mateo/confirm')
 async def confirm_action(req:Request,actor=Depends(operator)):
  b=await req.json();require(actor,'mateo')
  with db() as c:
   c.execute('BEGIN IMMEDIATE');p=c.execute('SELECT * FROM business_proposals WHERE id=? AND actor=? AND expires>?',(b.get('proposal_id'),actor['name'],now())).fetchone();check(p,'Propuesta vencida o no disponible',409)
   payload=json.loads(p['payload']);clients=[owned(c,actor,i) for i in payload['ids']]
   check(json.dumps([(l['id'],l['expires'],l['enabled'],l['owner_id'],l['deleted_at']) for l in clients])==p['state'],'El cliente cambió; prepara otra propuesta',409)
   if payload['action']=='renew':result=apply_batch(c,actor,payload)
   else:
    require(actor,'edit');l=clients[0];dns=payload['dns_id']
    check(ns['allowed_dns'](c,actor,dns),'Lista no autorizada',403)
    if l['owner_id']:check(ns['allowed_dns'](c,{'role':'reseller','name':l['owner_id']},dns),'Lista retirada al propietario',403)
    n=c.execute('SELECT name FROM dns WHERE id=?',(dns,)).fetchone();check(n,'Lista no disponible')
    check(c.execute('SELECT count(*) FROM license_playlists WHERE license_id=?',(l['id'],)).fetchone()[0]<4 and l['dns_id']!=dns and not c.execute('SELECT 1 FROM license_playlists WHERE license_id=? AND dns_id=?',(l['id'],dns)).fetchone(),'Límite o lista duplicada',409)
    c.execute('INSERT INTO license_playlists(id,license_id,dns_id,name,service_user,service_password) VALUES(?,?,?,?,?,?)',(secrets.token_hex(16),l['id'],dns,n['name'],payload['service_user'],payload['service_password']));audit(c,actor,'MATEO: lista añadida',l);result={'ok':True}
   c.execute('DELETE FROM business_proposals WHERE id=?',(p['id'],));return result
 # Daily encrypted database backups; /data remains the persistent source of truth.
 backup_lock=threading.Lock(); stop=threading.Event()
 def make_backup():
  with backup_lock:
   import tempfile
   with tempfile.TemporaryDirectory() as temp:
    f=Path(temp)/'snapshot.sqlite'
    with sqlite3.connect(data/'orion.sqlite') as source, sqlite3.connect(f) as target:source.backup(target)
    dest=backup_dir/(str(time.time_ns())+'.orionbackup');tmp=dest.with_suffix('.tmp')
    tmp.write_bytes(ns['cipher'].encrypt(f.read_bytes()));tmp.chmod(0o600);tmp.replace(dest)
   for old in sorted(backup_dir.glob('*.orionbackup'),reverse=True)[7:]:old.unlink()
   return dest.name
 def backup_loop():
  while not stop.is_set():
   try:
    newest=max((f.stat().st_mtime for f in backup_dir.glob('*.orionbackup')),default=0)
    if time.time()-newest>=86400:make_backup()
   except Exception:pass
   stop.wait(3600)
 from contextlib import asynccontextmanager
 previous_lifespan=app.router.lifespan_context
 @asynccontextmanager
 async def lifespan(application):
  async with previous_lifespan(application):
   threading.Thread(target=backup_loop,daemon=True).start()
   try:yield
   finally:stop.set()
 app.router.lifespan_context=lifespan
 @app.get('/api/admin/business/backups')
 def backups(actor=Depends(admin)):
  return {'files':[{'name':f.name,'created':int(f.stat().st_mtime),'size':f.stat().st_size} for f in sorted(backup_dir.glob('*.orionbackup'),reverse=True)]}
 @app.post('/api/admin/business/backups')
 def create_backup(actor=Depends(admin)):
  name=make_backup()
  with db() as c:audit(c,actor,'Respaldo creado')
  return {'ok':True,'name':name}
 @app.get('/api/admin/business/backups/{name}')
 def download_backup(name:str,actor=Depends(admin)):
  check(re.fullmatch(r'[0-9]+\.orionbackup',name),'Nombre inválido');file=backup_dir/name;check(file.is_file(),'Respaldo no encontrado',404)
  return FileResponse(file,filename=name,media_type='application/octet-stream')
 # Real provider check, pinned to a resolved public address; no redirects/private network access.
 def provider_fetch(url,user,password):
  u=urlsplit(url);check(u.scheme in ('https','http') and u.hostname,'DNS inválido')
  host=u.hostname;port=u.port or (443 if u.scheme=='https' else 80)
  addresses=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)
  check(addresses and all(ipaddress.ip_address(a[4][0]).is_global for a in addresses),'Este destino no está permitido')
  ip=addresses[0][4][0]
  connection=http.client.HTTPConnection(host,port,timeout=4)
  connection.sock=socket.create_connection((ip,port),timeout=4)
  if u.scheme=='https':connection.sock=ssl.create_default_context().wrap_socket(connection.sock,server_hostname=host)
  path=u.path.rstrip('/')+'/player_api.php?'+urlencode({'username':user,'password':password})
  try:
   connection.request('GET',path,headers={'Accept':'application/json','Host':host+(':'+str(port) if port not in (80,443) else '')})
   response=connection.getresponse();check(response.status==200,'El proveedor no respondió correctamente');raw=response.read(524289);check(len(raw)<=524288,'Respuesta demasiado grande');return json.loads(raw)
  finally:connection.close()
 @app.post('/api/admin/business/check-lists/{lid}')
 async def check_lists(lid:str,req:Request,actor=Depends(operator)):
  require(actor,'diagnostics');ns['throttle'](req,'provider:'+actor['name'],3)
  with db() as c:
   l=owned(c,actor,lid)
   rows=[dict(c.execute('SELECT ?,n.url,? service_user,? service_password FROM dns n WHERE id=?',(lid,l['service_user'],l['service_password'],l['dns_id'])).fetchone())]
   rows[0]['id']='primary'
   rows.extend(dict(r) for r in c.execute('SELECT p.id,n.url,p.service_user,p.service_password FROM license_playlists p JOIN dns n ON n.id=p.dns_id WHERE p.license_id=?',(lid,)))
  results=[]
  for r in rows:
   status='Sin respuesta';expiry=None
   try:
    result=await asyncio.to_thread(provider_fetch,r['url'],r['service_user'],ns['unseal'](r['service_password']));info=result.get('user_info',{});status='Activa' if str(info.get('auth'))=='1' and str(info.get('status','')).lower()=='active' else 'No autorizada o vencida'
    if str(info.get('exp_date','')).isdigit():expiry=int(info['exp_date']);check(0<=expiry<4102444800,'Fecha inválida')
   except Exception:status='Sin respuesta';expiry=None
   results.append({'profile_id':r['id'],'status':status,'expires':expiry,'checked':now()})
  with db() as c:
   owned(c,actor,lid)
   for r in results:c.execute('INSERT OR REPLACE INTO business_sources VALUES(?,?,?,?,?)',(lid,r['profile_id'],r['status'],r['expires'],r['checked']))
   audit(c,actor,'Listas comprobadas',l)
  return {'results':results,'note':'Comprueba cuenta y vencimiento del proveedor; no garantiza reproducción de cada canal.'}
