"""OrionTV original activation service. No third-party app endpoints or code."""
import os,sqlite3,secrets,hashlib,hmac,time,calendar,json,threading
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime,timezone
from urllib.parse import urlparse
from fastapi import FastAPI,Request,HTTPException,Depends
from fastapi.responses import FileResponse,JSONResponse
from fastapi.staticfiles import StaticFiles
from cryptography.fernet import Fernet
DATA=Path(os.getenv('ORION_DATA','./data'));DATA.mkdir(parents=True,exist_ok=True)
PUBLIC=os.getenv('PUBLIC_URL','http://127.0.0.1:8099').rstrip('/')
KEY=DATA/'service.key'
if not KEY.exists():
 try:
  fd=os.open(KEY,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'wb') as f:f.write(Fernet.generate_key())
 except FileExistsError:pass
cipher=Fernet(KEY.read_bytes())
@contextmanager
def db():
 c=sqlite3.connect(DATA/'orion.sqlite',timeout=10);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON')
 try:yield c;c.commit()
 except: c.rollback();raise
 finally:c.close()
with db() as c:c.executescript('''
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS admins(name TEXT PRIMARY KEY,password TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS dns(id TEXT PRIMARY KEY,name TEXT NOT NULL,url TEXT UNIQUE NOT NULL,is_default INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,installation TEXT UNIQUE NOT NULL,mac TEXT UNIQUE NOT NULL,token TEXT NOT NULL,demo_started INTEGER,demo_expires INTEGER,demo_used INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS licenses(id TEXT PRIMARY KEY,name TEXT NOT NULL,mode TEXT NOT NULL,mac TEXT UNIQUE,username TEXT UNIQUE,password TEXT,device_id TEXT, dns_id TEXT REFERENCES dns(id),service_user TEXT NOT NULL,service_password TEXT NOT NULL,expires INTEGER NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,notes TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS config(id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL DEFAULT 0,dns_id TEXT REFERENCES dns(id),service_user TEXT NOT NULL DEFAULT '',service_password TEXT NOT NULL DEFAULT '');
INSERT OR IGNORE INTO config(id) VALUES(1);
''')
# Additive migration for existing independent installations.
with db() as c:
 if 'device_limit' not in {r['name'] for r in c.execute('PRAGMA table_info(licenses)')}:
  c.execute('ALTER TABLE licenses ADD COLUMN device_limit INTEGER NOT NULL DEFAULT 1')
 for column,default in [('channel_catalog','[]'),('channel_policy','{"hidden_ids":[],"hidden_categories":[],"order":[]}')]:
  if column not in {r['name'] for r in c.execute('PRAGMA table_info(licenses)')}:
   c.execute(f"ALTER TABLE licenses ADD COLUMN {column} TEXT NOT NULL DEFAULT '{default}'")
 c.execute('CREATE TABLE IF NOT EXISTS license_devices (license_id TEXT NOT NULL REFERENCES licenses(id),device_id TEXT NOT NULL REFERENCES devices(id),PRIMARY KEY(license_id,device_id))')
 c.execute("INSERT OR IGNORE INTO license_devices SELECT l.id,l.device_id FROM licenses l JOIN devices d ON d.id=l.device_id WHERE l.mode='credentials'")
with db() as c:
 for table,column,decl in [('admins','role',"TEXT NOT NULL DEFAULT 'admin'"),('admins','enabled','INTEGER NOT NULL DEFAULT 1'),('admins','display_name',"TEXT NOT NULL DEFAULT ''"),('sessions','username','TEXT'),('dns','alternatives',"TEXT NOT NULL DEFAULT '[]'"),('licenses','owner_id','TEXT')]:
  if column not in {r['name'] for r in c.execute('PRAGMA table_info('+table+')')}:c.execute('ALTER TABLE '+table+' ADD COLUMN '+column+' '+decl)
# Per-reseller DNS permissions, additive and disabled by default.
with db() as c:
 for table,column,decl in [('admins','can_add_dns','INTEGER NOT NULL DEFAULT 0'),('dns','owner_id','TEXT')]:
  if column not in {r['name'] for r in c.execute('PRAGMA table_info('+table+')')}:
   c.execute('ALTER TABLE '+table+' ADD COLUMN '+column+' '+decl)
 c.execute('CREATE TABLE IF NOT EXISTS reseller_dns (reseller TEXT NOT NULL REFERENCES admins(name),dns_id TEXT NOT NULL REFERENCES dns(id),PRIMARY KEY(reseller,dns_id))')
def allowed_dns(c, actor, dns_id):
 return actor['role']=='admin' or bool(c.execute('SELECT 1 FROM dns WHERE id=? AND (owner_id=? OR EXISTS (SELECT 1 FROM reseller_dns r WHERE r.dns_id=dns.id AND r.reseller=?))',(dns_id,actor['name'],actor['name'])).fetchone())
# Appearance is independent of licenses and survives container rebuilds in /data.
with db() as c:
 c.execute("CREATE TABLE IF NOT EXISTS app_appearance (id INTEGER PRIMARY KEY CHECK(id=1),theme TEXT NOT NULL DEFAULT 'orion',revision INTEGER NOT NULL DEFAULT 1)")
 c.execute('INSERT OR IGNORE INTO app_appearance(id) VALUES(1)')
def app_appearance(c):
 row=c.execute('SELECT theme,revision FROM app_appearance WHERE id=1').fetchone()
 return dict(row)
def digest(s):return hashlib.sha256(s.encode()).hexdigest()
def pw_hash(s):
 salt=secrets.token_bytes(16);return salt.hex()+':'+hashlib.pbkdf2_hmac('sha256',s.encode(),salt,310000).hex()
def pw_ok(s,stored):
 try:salt,value=stored.split(':');return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',s.encode(),bytes.fromhex(salt),310000).hex(),value)
 except:return False
def seal(s):return cipher.encrypt(s.encode()).decode()
def unseal(s):return cipher.decrypt(s.encode()).decode()
def check(condition,msg,status=400):
 if not condition:raise HTTPException(status,msg)
def text(b,k,maximum=256):
 v=str(b.get(k,'')).strip();check(len(v)<=maximum,'Campo demasiado largo: '+k);return v
def months_after(timestamp,months):
 d=datetime.fromtimestamp(timestamp,timezone.utc);m=d.month-1+months;y=d.year+m//12;m=m%12+1
 return int(d.replace(year=y,month=m,day=min(d.day,calendar.monthrange(y,m)[1])).timestamp())
limits={};limit_lock=threading.Lock()
def throttle(req,bucket,max_count):
 key=(req.client.host if req.client else 'unknown',bucket);now=time.time()
 with limit_lock:
  old=[t for t in limits.get(key,[]) if t>now-60];check(len(old)<max_count,'Espera un minuto antes de volver a intentar.',429);old.append(now);limits[key]=old
  if len(limits)>5000:
   for k in list(limits):
    if not limits[k] or limits[k][-1]<now-60:limits.pop(k,None)
app=FastAPI(title='OrionTV independent activation',docs_url=None,redoc_url=None)
@app.middleware('http')
async def security(req,call_next):
 if req.url.path.startswith('/api/admin') and req.method not in ('GET','HEAD'):
  if req.headers.get('origin')!=PUBLIC:return JSONResponse({'detail':'Origen no permitido'},status_code=403)
 r=await call_next(req);r.headers['X-Content-Type-Options']='nosniff';r.headers['X-Frame-Options']='DENY';r.headers['Referrer-Policy']='no-referrer'
 if req.url.path.startswith('/api'):r.headers['Cache-Control']='no-store'
 return r
def operator(req:Request):
 token=req.cookies.get('orion_admin','')
 with db() as c:r=c.execute('SELECT a.* FROM sessions s JOIN admins a ON a.name=s.username WHERE s.token=? AND s.expires>? AND a.enabled=1',(digest(token),int(time.time()))).fetchone()
 check(r,'Inicia sesión',401);return dict(r)
def admin(req:Request):
 actor=operator(req);check(actor['role']=='admin','Solo el administrador puede realizar esta acción',403);return actor
def own_license(actor,id):
 with db() as c:r=c.execute('SELECT owner_id FROM licenses WHERE id=?',(id,)).fetchone()
 check(r,'Cliente no encontrado',404);check(actor['role']=='admin' or r['owner_id']==actor['name'],'Acceso no permitido',403)
def device(req:Request):
 token=req.headers.get('authorization','').removeprefix('Bearer ')
 check(len(token)>20,'Dispositivo no registrado',401)
 with db() as c:d=c.execute('SELECT * FROM devices WHERE token=?',(digest(token),)).fetchone()
 check(d,'Dispositivo no registrado',401);return dict(d)
@app.post('/api/admin/login')
async def login(req:Request):
 throttle(req,'login',10);b=await req.json()
 with db() as c:
  a=c.execute('SELECT password,enabled FROM admins WHERE name=?',(text(b,'username',100),)).fetchone()
  check(a and a['enabled'] and pw_ok(str(b.get('password','')),a['password']),'Usuario o contraseña incorrectos',401)
  token=secrets.token_urlsafe(32);c.execute('DELETE FROM sessions WHERE expires<?',(int(time.time()),));c.execute('INSERT INTO sessions(token,expires,username) VALUES (?,?,?)',(digest(token),int(time.time())+28800,text(b,'username',100)))
 r=JSONResponse({'ok':True});r.set_cookie('orion_admin',token,httponly=True,secure=PUBLIC.startswith('https://'),samesite='strict',max_age=28800);return r
@app.post('/api/admin/logout',dependencies=[Depends(operator)])
async def logout(req:Request):
 with db() as c:c.execute('DELETE FROM sessions WHERE token=?',(digest(req.cookies.get('orion_admin','')),))
 r=JSONResponse({'ok':True});r.delete_cookie('orion_admin');return r
@app.get('/api/admin/data')
def data(actor=Depends(operator)):
 with db() as c:
  dns=[dict(x) for x in c.execute('SELECT * FROM dns ORDER BY is_default DESC,name')]
  licenses=[dict(x) for x in c.execute('SELECT id,name,mode,mac,username,device_id,device_limit,owner_id,dns_id,service_user,expires,enabled,notes FROM licenses ORDER BY expires DESC')]
  devices=[dict(x) for x in c.execute('SELECT id,mac,demo_started,demo_expires,demo_used,created FROM devices ORDER BY created DESC')]
  config=dict(c.execute('SELECT * FROM config WHERE id=1').fetchone());config['has_password']=bool(config.pop('service_password'))
  resellers=[dict(x) for x in c.execute("SELECT name,display_name,enabled,can_add_dns FROM admins WHERE role='reseller' ORDER BY name")] if actor['role']=='admin' else []
  if actor['role']!='admin':
   dns=[{'id':d['id'],'name':d['name'],'is_default':0,'owned':d.get('owner_id')==actor['name']} for d in dns if allowed_dns(c,actor,d['id'])]
   licenses=[l for l in licenses if l['owner_id']==actor['name']]
   allowed={l['device_id'] for l in licenses};codes={l['mac'] for l in licenses}
   allowed.update(r[0] for r in c.execute('SELECT ld.device_id FROM license_devices ld JOIN licenses l ON l.id=ld.license_id WHERE l.owner_id=?',(actor['name'],)))
   devices=[d for d in devices if d['id'] in allowed or d['mac'] in codes];config={}
  return {'dns':dns,'licenses':licenses,'devices':devices,'demo':config,'resellers':resellers,'role':actor['role'],'actor':actor['name'],'can_add_dns':bool(actor.get('can_add_dns',0)),'app_theme':app_appearance(c),'server_time':int(time.time())}
@app.post('/api/admin/app-theme',dependencies=[Depends(admin)])
async def save_app_theme(req:Request):
 b=await req.json();theme=b.get('theme')
 check(isinstance(theme,str) and theme in ('orion','ibo','midnight'),'Selecciona un tema válido')
 with db() as c:
  c.execute('UPDATE app_appearance SET revision=revision+CASE WHEN theme<>? THEN 1 ELSE 0 END,theme=? WHERE id=1',(theme,theme))
  return app_appearance(c)
@app.post('/api/admin/resellers',dependencies=[Depends(admin)])
async def save_reseller(req:Request):
 b=await req.json();name=text(b,'username',64).lower();display=text(b,'display_name',100);password=text(b,'password',128)
 import re
 check(re.fullmatch(r'[a-z0-9._-]{3,64}',name),'Usuario inválido')
 with db() as c:
  old=c.execute('SELECT * FROM admins WHERE name=?',(name,)).fetchone();check(not old or old['role']=='reseller','Este usuario está reservado',409)
  check((old and not password) or len(password)>=8,'Contraseña: mínimo 8 caracteres')
  hashed=pw_hash(password) if password else old['password']
  c.execute("INSERT INTO admins(name,password,role,enabled,display_name) VALUES (?,?,'reseller',?,?) ON CONFLICT(name) DO UPDATE SET password=excluded.password,enabled=excluded.enabled,display_name=excluded.display_name",(name,hashed,int(b.get('enabled',True)),display))
  c.execute('DELETE FROM sessions WHERE username=?',(name,))
 return {'ok':True}
@app.post('/api/admin/dns')
async def save_dns(req:Request,actor=Depends(operator)):
 check(actor['role']=='admin' or actor.get('can_add_dns'),'No tienes permiso para agregar DNS',403)
 b=await req.json();name=text(b,'name',100);url=text(b,'url',2048).rstrip('/');parsed=urlparse(url);check(name and parsed.scheme in ('http','https') and parsed.hostname and not parsed.username and not parsed.password,'Nombre o URL inválidos')
 alternatives=b.get('alternatives',[]);check(isinstance(alternatives,list) and len(alternatives)<=3,'Agrega hasta 3 direcciones alternativas')
 cleaned=[]
 for value in alternatives:
  check(isinstance(value,str),'Dirección alternativa inválida');value=value.strip().rstrip('/');target=urlparse(value)
  try:port=target.port
  except ValueError:raise HTTPException(400,'Puerto inválido')
  check(len(value)<=2048 and target.scheme in ('http','https') and target.hostname and not target.username and not target.password and not target.query and not target.fragment and port!=0,'Dirección alternativa inválida')
  check(not (parsed.scheme=='https' and target.scheme!='https'),'Los respaldos de un servicio HTTPS deben usar HTTPS')
  if value!=url and value not in cleaned:cleaned.append(value)
 with db() as c:
  i=text(b,'id',100) or secrets.token_hex(16)
  existing=c.execute('SELECT owner_id FROM dns WHERE id=?',(i,)).fetchone()
  check(actor['role']=='admin' or (actor.get('can_add_dns') and (not existing or existing['owner_id']==actor['name'])), 'No tienes permiso para agregar o modificar este DNS',403)
  check(actor['role']=='admin' or not b.get('is_default'),'Solo el administrador configura el DNS predeterminado',403)
  if b.get('is_default'):c.execute('UPDATE dns SET is_default=0')
  try:c.execute('INSERT INTO dns(id,name,url,is_default,alternatives) VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,url=excluded.url,is_default=excluded.is_default,alternatives=excluded.alternatives',(i,name,url,int(bool(b.get('is_default'))),json.dumps(cleaned)))
  except sqlite3.IntegrityError:raise HTTPException(409,'No se pudo guardar este DNS; consulta al administrador')
  if actor['role']!='admin' and not existing:c.execute('UPDATE dns SET owner_id=? WHERE id=?',(actor['name'],i))
 return {'ok':True}
@app.post('/api/admin/demo',dependencies=[Depends(admin)])
async def save_demo(req:Request):
 b=await req.json();u=text(b,'service_user',128);p=text(b,'service_password',256);dns=text(b,'dns_id',100);enabled=bool(b.get('enabled'))
 with db() as c:
  old=c.execute('SELECT * FROM config WHERE id=1').fetchone();password=seal(p) if p else old['service_password']
  check(not enabled or (u and password and c.execute('SELECT id FROM dns WHERE id=?',(dns,)).fetchone()),'Completa el DNS, usuario y contraseña demo')
  c.execute('UPDATE config SET enabled=?,dns_id=?,service_user=?,service_password=? WHERE id=1',(int(enabled),dns or None,u,password))
 return {'ok':True}
@app.post('/api/admin/license')
async def save_license(req:Request,actor=Depends(operator)):
 b=await req.json();name=text(b,'name',100);mode=text(b,'mode',20);mac=text(b,'mac',30).upper().replace('-',':');username=text(b,'username',64).lower();p=text(b,'password',128);su=text(b,'service_user',128);sp=text(b,'service_password',256);dns=text(b,'dns_id',100);i=text(b,'id',100)
 check(name and mode in ('mac','credentials'),'Completa nombre y modo');check(su,'Agrega el usuario del servicio')
 if mode=='mac':
  import re
  check(re.fullmatch(r'[A-Z0-9]{8}|([0-9A-F]{2}:){5}[0-9A-F]{2}',mac),'Código inválido: usa los 8 caracteres de la app')
 else:check(len(username)>=3,'Usuario de activación: mínimo 3 caracteres')
 with db() as c:
  old=c.execute('SELECT * FROM licenses WHERE id=?',(i,)).fetchone() if i else None
  if i:own_license(actor,i)
  owner=(text(b,'owner_id',64) or None) if actor['role']=='admin' else actor['name']
  if owner:check(c.execute("SELECT name FROM admins WHERE name=? AND role='reseller'",(owner,)).fetchone(),'Revendedor no encontrado')
  check(not i or old,'Registro no encontrado',404);check(c.execute('SELECT id FROM dns WHERE id=?',(dns,)).fetchone(),'Selecciona un DNS guardado')
  check(allowed_dns(c,actor,dns),'Lista no autorizada para este revendedor',403)
  if owner:
   check(allowed_dns(c,{'role':'reseller','name':owner},dns),'Autoriza primero esta lista al revendedor',403)
   if old and old['owner_id']!=owner:
    check(all(allowed_dns(c,{'role':'reseller','name':owner},r[0]) for r in c.execute('SELECT dns_id FROM license_playlists WHERE license_id=?',(i,))),'Las listas adicionales no están autorizadas al nuevo revendedor',403)
  service_password=seal(sp) if sp else (old['service_password'] if old else '')
  check(service_password,'Agrega la contraseña del servicio')
  password=pw_hash(p) if p else (old['password'] if old else None)
  check(mode!='credentials' or (password and (not p or len(p)>=8)),'Contraseña de activación: mínimo 8 caracteres')
  months=int(b.get('months',0));check(0<=months<=12,'Duración inválida')
  check(old or months>=1,'Selecciona de 1 a 12 meses')
  expires=months_after(max(int(time.time()),old['expires'] if old else 0),months) if months else old['expires']
  limit=int(b.get('device_limit',old['device_limit'] if old else 1)) if mode=='credentials' else 1
  check(1<=limit<=4,'Selecciona de 1 a 4 dispositivos')
  if old:check(c.execute('SELECT count(*) FROM license_devices WHERE license_id=?',(i,)).fetchone()[0]<=limit,'La cuenta tiene más dispositivos vinculados. Suspéndela o conserva su límite actual.')
  row=(i or secrets.token_hex(16),name,mode,mac if mode=='mac' else None,username if mode=='credentials' else None,password if mode=='credentials' else None,old['device_id'] if old else None,dns,su,service_password,expires,int(b.get('enabled',True)),text(b,'notes',1000),limit,owner)
  try:c.execute('INSERT INTO licenses(id,name,mode,mac,username,password,device_id,dns_id,service_user,service_password,expires,enabled,notes,device_limit,owner_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,mode=excluded.mode,mac=excluded.mac,username=excluded.username,password=excluded.password,dns_id=excluded.dns_id,service_user=excluded.service_user,service_password=excluded.service_password,expires=excluded.expires,enabled=excluded.enabled,notes=excluded.notes,device_limit=excluded.device_limit,owner_id=excluded.owner_id',row)
  except sqlite3.IntegrityError:raise HTTPException(409,'MAC o usuario ya registrados')
 return {'ok':True}
@app.get('/api/admin/channels')
def get_channels(id:str,actor=Depends(operator)):
 own_license(actor,id)
 with db() as c:r=c.execute('SELECT channel_catalog,channel_policy FROM licenses WHERE id=?',(id,)).fetchone()
 check(r,'Cliente no encontrado',404);return {'channels':json.loads(r['channel_catalog']),'policy':json.loads(r['channel_policy'])}
@app.post('/api/admin/channels')
async def save_channels(req:Request,actor=Depends(operator)):
 b=await req.json();id=text(b,'id',100);channels=b.get('channels',[]);policy=b.get('policy',{})
 own_license(actor,id)
 check(isinstance(channels,list) and len(channels)<=10000 and isinstance(policy,dict),'Catálogo inválido')
 clean=[];seen=set()
 for r in channels:
  check(isinstance(r,dict),'Canal inválido');row={k:str(r.get(k,'')) for k in ('id','name','category','categoryName')}
  check(row['id'] and row['id'] not in seen and max(map(len,row.values()))<=300,'Canal inválido o duplicado');seen.add(row['id']);clean.append(row)
 rules={}
 for key in ('hidden_ids','hidden_categories','order'):
  items=policy.get(key,[]);check(isinstance(items,list) and len(items)<=10000 and all(isinstance(v,str) and len(v)<=300 for v in items),'Reglas inválidas');rules[key]=list(dict.fromkeys(items))
 catalog=json.dumps(clean);saved=json.dumps(rules);check(len(catalog)+len(saved)<=2000000,'Catálogo demasiado grande')
 with db() as c:check(c.execute('UPDATE licenses SET channel_catalog=?,channel_policy=? WHERE id=?',(catalog,saved,id)).rowcount,'Cliente no encontrado',404)
 return {'ok':True}
@app.post('/api/register')
async def register(req:Request):
 throttle(req,'register',20);b=await req.json();installation=text(b,'installation_id',100);check(len(installation)>=32,'Identificador inválido')
 with db() as c:
  registration_secret=text(b,'registration_secret',128)
  if registration_secret:
   import re
   check(re.fullmatch(r'[A-Za-z0-9_-]{40,128}',registration_secret),'Secreto de registro inválido')
  numeric=b.get('id_format')=='numeric8'
  alphanumeric=b.get('id_format')=='alphanumeric8'
  new_code=f'{int.from_bytes(hashlib.sha256(installation.encode()).digest()[:4],"big")%100000000:08d}'
  if alphanumeric:
   hashed=hashlib.sha256(installation.encode()).digest()
   new_code=''.join(chr((65 if j in (0,1,4,5) else 48)+hashed[j]%(26 if j in (0,1,4,5) else 10)) for j in range(8))
  old=c.execute('SELECT * FROM devices WHERE installation=?',(installation,)).fetchone()
  if old:
   check(registration_secret and hmac.compare_digest(old['token'],digest(registration_secret)),'Este dispositivo ya está registrado; utiliza su token guardado.',409)
   current_code=old['mac']
   if (numeric or alphanumeric) and current_code!=new_code:
    check(not c.execute('SELECT id FROM devices WHERE mac=? AND id!=?',(new_code,old['id'])).fetchone(),'Código ocupado; contacta al administrador.',409)
    check(not c.execute('SELECT id FROM licenses WHERE mac=?',(new_code,)).fetchone() or not c.execute('SELECT id FROM licenses WHERE mac=?',(current_code,)).fetchone(),'Hay dos registros de activación; revisa el panel.',409)
    c.execute('UPDATE devices SET mac=? WHERE id=?',(new_code,old['id']))
    c.execute('UPDATE licenses SET mac=? WHERE mac=?',(new_code,current_code));current_code=new_code
   return {'device_id':old['id'],'mac':current_code,'device_token':registration_secret}
  if registration_secret:raw=bytearray(hashlib.sha256(installation.encode()).digest()[:6]);token=registration_secret
  else:raw=bytearray(secrets.token_bytes(6));token=secrets.token_urlsafe(32)
  raw[0]=(raw[0]|2)&254;mac=new_code if (numeric or alphanumeric) else ':'.join(f'{x:02X}' for x in raw);i=secrets.token_hex(16)
  check(not c.execute('SELECT id FROM devices WHERE mac=?',(mac,)).fetchone(),'ID ya registrado. Contacta al administrador.',409)
  c.execute('INSERT INTO devices(id,installation,mac,token,created) VALUES (?,?,?,?,?)',(i,installation,mac,digest(token),int(time.time())))
 return {'device_id':i,'mac':mac,'device_token':token}
def access(d):
 now=int(time.time())
 with db() as c:
  license=c.execute('SELECT l.*,n.url,n.alternatives FROM licenses l JOIN dns n ON n.id=l.dns_id WHERE l.mac=? OR l.device_id=? OR EXISTS (SELECT 1 FROM license_devices ld WHERE ld.license_id=l.id AND ld.device_id=?) ORDER BY l.expires DESC LIMIT 1',(d['mac'],d['id'],d['id'])).fetchone()
  if license:
   check(license['enabled'] and license['expires']>now,'Tu activación venció o está suspendida.',403)
   return {'app_theme':app_appearance(c),'status':'active','expires_at':license['expires'],'server_time':now,'dns':license['url'],'dns_alternatives':json.loads(license['alternatives']),'username':license['service_user'],'password':unseal(license['service_password']),'channel_policy':json.loads(license['channel_policy'])}
  check(d['demo_expires'] and d['demo_expires']>now,'Tu prueba terminó. Contacta a tu distribuidor.' if d['demo_used'] else 'Pendiente de activación',403)
  conf=c.execute('SELECT c.*,n.url,n.alternatives FROM config c JOIN dns n ON n.id=c.dns_id WHERE c.id=1').fetchone();check(conf and conf['enabled'],'Las pruebas están suspendidas',403)
  return {'app_theme':app_appearance(c),'status':'demo','expires_at':d['demo_expires'],'server_time':now,'dns':conf['url'],'dns_alternatives':json.loads(conf['alternatives']),'username':conf['service_user'],'password':unseal(conf['service_password']),'channel_policy':{'hidden_ids':[],'hidden_categories':[],'order':[]}}
@app.get('/api/access')
def get_access(d=Depends(device)):return access(d)
@app.post('/api/demo/start')
async def start_demo(req:Request,d=Depends(device)):
 throttle(req,'demo',30);now=int(time.time())
 with db() as c:
  conf=c.execute('SELECT * FROM config WHERE id=1').fetchone();check(conf['enabled'],'Las pruebas no están habilitadas',403)
  check(not c.execute('SELECT l.id FROM licenses l WHERE mac=? OR device_id=? OR EXISTS(SELECT 1 FROM license_devices ld WHERE ld.license_id=l.id AND ld.device_id=?)',(d['mac'],d['id'],d['id'])).fetchone(),'Este equipo ya tiene una activación; pulsa consultar acceso.',409)
  c.execute('UPDATE devices SET demo_used=1,demo_started=?,demo_expires=? WHERE id=? AND demo_used=0',(now,now+7200,d['id']))
  updated=dict(c.execute('SELECT * FROM devices WHERE id=?',(d['id'],)).fetchone())
 return access(updated)
@app.post('/api/activate')
async def activate(req:Request,d=Depends(device)):
 throttle(req,'activate',15);b=await req.json()
 with db() as c:
  c.execute('BEGIN IMMEDIATE')
  l=c.execute("SELECT * FROM licenses WHERE mode='credentials' AND username=?",(text(b,'username',64).lower(),)).fetchone();check(l and pw_ok(str(b.get('password','')),l['password']),'Credenciales incorrectas',401)
  check(l['enabled'] and l['expires']>int(time.time()),'Activación vencida o suspendida',403)
  bound=c.execute('SELECT 1 FROM license_devices WHERE license_id=? AND device_id=?',(l['id'],d['id'])).fetchone()
  if not bound:
   count=c.execute('SELECT count(*) FROM license_devices WHERE license_id=?',(l['id'],)).fetchone()[0]
   check(count<l['device_limit'],'Esta cuenta alcanzó su límite de dispositivos.',409)
   c.execute('INSERT INTO license_devices VALUES (?,?)',(l['id'],d['id']))
  c.execute('UPDATE licenses SET device_id=? WHERE id=? AND device_id IS NULL',(d['id'],l['id']))
 return access(d)
@app.get('/api/panel-version')
def panel_version():
 h=hashlib.sha256(Path(__file__).read_bytes())
 for p in sorted((Path(__file__).parent/'static').glob('*')):
  if p.is_file():h.update(p.read_bytes())
 return {'version':h.hexdigest()[:16]}
@app.get('/health')
def health():return {'status':'ok','application':'oriontv-independent'}
@app.get('/')
def index():return FileResponse(Path(__file__).parent/'static/index.html')
app.mount('/static',StaticFiles(directory=Path(__file__).parent/'static'),name='static')



@app.get('/api/admin/resellers/{name}/dns',dependencies=[Depends(admin)])
def reseller_dns_permissions(name:str):
 with db() as c:
  r=c.execute("SELECT can_add_dns FROM admins WHERE name=? AND role='reseller'",(name,)).fetchone();check(r,'Revendedor no encontrado',404)
  return {'can_add_dns':bool(r['can_add_dns']),'dns_ids':[x[0] for x in c.execute('SELECT dns_id FROM reseller_dns WHERE reseller=?',(name,))]}
@app.put('/api/admin/resellers/{name}/dns',dependencies=[Depends(admin)])
async def set_reseller_dns(name:str,req:Request):
 b=await req.json();ids=b.get('dns_ids');permission=b.get('can_add_dns')
 check(isinstance(ids,list) and len(ids)<=500 and all(isinstance(i,str) for i in ids) and len(ids)==len(set(ids)) and isinstance(permission,bool),'Permisos inválidos')
 with db() as c:
  check(c.execute("SELECT 1 FROM admins WHERE name=? AND role='reseller'",(name,)).fetchone(),'Revendedor no encontrado',404)
  for i in ids:
   r=c.execute('SELECT owner_id FROM dns WHERE id=?',(i,)).fetchone();check(r and r['owner_id'] in (None,name),'DNS no disponible para este revendedor')
  c.execute('DELETE FROM reseller_dns WHERE reseller=?',(name,))
  c.executemany('INSERT INTO reseller_dns VALUES (?,?)',[(name,i) for i in ids])
  c.execute('UPDATE admins SET can_add_dns=? WHERE name=?',(int(permission),name))
 return {'ok':True}
@app.get('/permisos-listas',include_in_schema=False)
def dns_permissions_page(actor=Depends(operator)):
 return FileResponse(Path(__file__).with_name('permisos_listas.html'))

# OrionTV playlists extension v56
from playlist_extension import install_playlists
install_playlists(globals())

from mateo_panel import install_mateo_panel
install_mateo_panel(globals())

# Agente MATEO por WhatsApp (conservado del repositorio actual)
from mateo_whatsapp import install as install_mateo_whatsapp
install_mateo_whatsapp(globals())
