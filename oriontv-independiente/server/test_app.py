import os,tempfile,time
os.environ['ORION_DATA']=tempfile.mkdtemp(prefix='orion-tests-');os.environ['PUBLIC_URL']='https://orion.test'
from fastapi.testclient import TestClient
import app
client=TestClient(app.app,base_url='https://orion.test');origin={'Origin':'https://orion.test'}
with app.db() as c:c.execute('INSERT INTO admins(name,password) VALUES (?,?)',('admin',app.pw_hash('test-admin-only-123!')))
def register():
 import uuid
 r=client.post('/api/register',json={'installation_id':str(uuid.uuid4())});assert r.status_code==200;d=r.json();return d,{'Authorization':'Bearer '+d['device_token']}
def setup():
 assert client.post('/api/admin/login',json={'username':'admin','password':'test-admin-only-123!'},headers=origin).status_code==200
 if not client.get('/api/admin/data').json()['dns']:
  assert client.post('/api/admin/dns',json={'name':'Pruebas','url':'https://example.invalid','is_default':True},headers=origin).status_code==200
 dns=client.get('/api/admin/data').json()['dns'][0]['id']
 assert client.post('/api/admin/demo',json={'enabled':True,'dns_id':dns,'service_user':'demo','service_password':'demo-test'},headers=origin).status_code==200
 return dns

def test_isolation_and_csrf():
 anon=TestClient(app.app,base_url='https://orion.test');assert anon.get('/api/admin/data').status_code==401
 assert anon.post('/api/admin/login',json={},headers={'Origin':'https://other.invalid'}).status_code==403
 assert client.get('/health').json()['application']=='oriontv-independent'

def test_demo_no_restart_expiry_and_conversion():
 dns=setup();d,auth=register();r=client.post('/api/demo/start',json={},headers=auth);assert r.status_code==200;first=r.json();assert 7198<=first['expires_at']-first['server_time']<=7200
 assert client.post('/api/demo/start',json={},headers=auth).json()['expires_at']==first['expires_at']
 with app.db() as c:c.execute('UPDATE devices SET demo_expires=? WHERE mac=?',(int(time.time())-1,d['mac']))
 assert client.get('/api/access',headers=auth).status_code==403
 assert client.post('/api/demo/start',json={},headers=auth).status_code==403
 b={'name':'Cliente convertido','mode':'mac','mac':d['mac'],'dns_id':dns,'service_user':'paid-user','service_password':'paid-pass','months':1,'enabled':True}
 assert client.post('/api/admin/license',json=b,headers=origin).status_code==200
 access=client.get('/api/access',headers=auth).json();assert access['status']=='active';assert access['username']=='paid-user'
 info=client.get('/api/admin/data').json();assert 'service_password' not in info['demo'];assert 'service_password' not in info['licenses'][0]
 with app.db() as c:assert 'paid-pass' not in c.execute('SELECT service_password FROM licenses WHERE mac=?',(d['mac'],)).fetchone()[0]

def test_credentials_bind_one_device():
 dns=setup()
 b={'name':'Cuenta','mode':'credentials','username':'cliente1','password':'password-test-only','dns_id':dns,'service_user':'stream-user','service_password':'stream-pass','months':12,'enabled':True}
 assert client.post('/api/admin/license',json=b,headers=origin).status_code==200
 d,a=register();d2,a2=register();assert client.post('/api/activate',json={'username':'cliente1','password':'bad'},headers=a).status_code==401
 assert client.post('/api/activate',json={'username':'cliente1','password':'password-test-only'},headers=a).status_code==200
 assert client.post('/api/activate',json={'username':'cliente1','password':'password-test-only'},headers=a2).status_code==409

def test_calendar_months():
 from datetime import datetime,timezone
 stamp=int(datetime(2028,1,31,tzinfo=timezone.utc).timestamp());assert datetime.fromtimestamp(app.months_after(stamp,1),timezone.utc).day==29

def test_offline_id_registration_retry_and_pre_activation():
 import uuid,secrets,hashlib
 dns=setup();installation=str(uuid.uuid4());secret=secrets.token_urlsafe(32)
 raw=bytearray(hashlib.sha256(installation.encode()).digest()[:6]);raw[0]=(raw[0]|2)&254
 offline=':'.join(f'{x:02X}' for x in raw)
 license={'name':'ID generado sin internet','mode':'mac','mac':offline,'dns_id':dns,'service_user':'offline-user','service_password':'offline-pass','months':1,'enabled':True}
 assert client.post('/api/admin/license',json=license,headers=origin).status_code==200
 payload={'installation_id':installation,'registration_secret':secret}
 first=client.post('/api/register',json=payload);assert first.status_code==200;assert first.json()['mac']==offline
 repeat=client.post('/api/register',json=payload);assert repeat.json()==first.json()
 rejected=client.post('/api/register',json={**payload,'registration_secret':secrets.token_urlsafe(32)})
 assert rejected.status_code==409
 access=client.get('/api/access',headers={'Authorization':'Bearer '+secret});assert access.status_code==200;assert access.json()['username']=='offline-user'

def test_numeric_code_eight_digits_and_leading_zeros():
 import uuid,secrets,hashlib
 dns=setup()
 # Find a deterministic code with a leading zero to verify string storage.
 for _ in range(10000):
  installation=str(uuid.uuid4());code=f'{int.from_bytes(hashlib.sha256(installation.encode()).digest()[:4],"big")%100000000:08d}'
  if code.startswith('0'):break
 assert len(code)==8 and code.isascii() and code.isdigit() and code[0]=='0'
 secret=secrets.token_urlsafe(32);payload={'installation_id':installation,'registration_secret':secret,'id_format':'numeric8'}
 license={'name':'Código numérico','mode':'mac','mac':code,'dns_id':dns,'service_user':'numeric-user','service_password':'numeric-pass','months':1,'enabled':True}
 assert client.post('/api/admin/license',json=license,headers=origin).status_code==200
 r=client.post('/api/register',json=payload);assert r.status_code==200;assert r.json()['mac']==code
 assert client.post('/api/register',json=payload).json()['mac']==code
 assert client.get('/api/access',headers={'Authorization':'Bearer '+secret}).json()['username']=='numeric-user'

def test_alphanumeric_eight_and_migration_without_reset():
 import uuid,secrets,hashlib,re
 dns=setup();installation=str(uuid.uuid4());secret=secrets.token_urlsafe(32);hashed=hashlib.sha256(installation.encode()).digest()
 code=''.join(chr((65 if j in (0,1,4,5) else 48)+hashed[j]%(26 if j in (0,1,4,5) else 10)) for j in range(8))
 assert re.fullmatch(r'[A-Z]{2}[0-9]{2}[A-Z]{2}[0-9]{2}',code)
 original=client.post('/api/register',json={'installation_id':installation,'registration_secret':secret,'id_format':'numeric8'}).json();old=original['mac']
 assert client.post('/api/demo/start',json={},headers={'Authorization':'Bearer '+secret}).status_code==200
 with app.db() as c:before=c.execute('SELECT demo_expires FROM devices WHERE installation=?',(installation,)).fetchone()[0]
 license={'name':'Migración alfanumérica','mode':'mac','mac':old,'dns_id':dns,'service_user':'alpha-user','service_password':'alpha-pass','months':1,'enabled':True}
 assert client.post('/api/admin/license',json=license,headers=origin).status_code==200
 payload={'installation_id':installation,'registration_secret':secret,'id_format':'alphanumeric8'}
 r=client.post('/api/register',json=payload);assert r.status_code==200;assert r.json()['mac']==code
 assert client.post('/api/register',json=payload).json()['mac']==code
 with app.db() as c:
  assert c.execute('SELECT demo_expires FROM devices WHERE installation=?',(installation,)).fetchone()[0]==before
  assert c.execute('SELECT service_user FROM licenses WHERE mac=?',(code,)).fetchone()[0]=='alpha-user'

def test_limit_four_devices():
 dns=setup();body={'name':'Cuenta cuatro equipos','mode':'credentials','username':'cuatroequipos','password':'test-only-pass','dns_id':dns,'service_user':'four-user','service_password':'four-pass','months':1,'enabled':True,'device_limit':4}
 assert client.post('/api/admin/license',json=body,headers=origin).status_code==200
 auths=[]
 for _ in range(5):
  d,a=register();auths.append(a)
 for a in auths[:4]:
  assert client.post('/api/activate',json={'username':'cuatroequipos','password':'test-only-pass'},headers=a).status_code==200
  assert client.get('/api/access',headers=a).status_code==200
 assert client.post('/api/activate',json={'username':'cuatroequipos','password':'test-only-pass'},headers=auths[4]).status_code==409
 assert client.get('/api/access',headers=auths[4]).status_code==403
 # Reusing an authorized installation does not consume a second slot.
 assert client.post('/api/activate',json={'username':'cuatroequipos','password':'test-only-pass'},headers=auths[0]).status_code==200

def test_channel_rules_separate_per_client():
 dns=setup();auths=[];ids=[]
 for i in range(2):
  d,a=register();auths.append(a)
  b={'name':'Canales cliente '+str(i),'mode':'mac','mac':d['mac'],'dns_id':dns,'service_user':'channels-'+str(i),'service_password':'test-pass','months':1,'enabled':True}
  assert client.post('/api/admin/license',json=b,headers=origin).status_code==200
  ids.append(next(l['id'] for l in client.get('/api/admin/data').json()['licenses'] if l['mac']==d['mac']))
 policy={'hidden_ids':['20'],'hidden_categories':['9'],'order':['30','10']}
 catalog=[{'id':'10','name':'Uno','category':'1','categoryName':'Noticias'},{'id':'20','name':'Dos','category':'9','categoryName':'Ocultos'},{'id':'30','name':'Tres','category':'1','categoryName':'Noticias'}]
 assert client.post('/api/admin/channels',json={'id':ids[0],'channels':catalog,'policy':policy},headers=origin).status_code==200
 assert client.get('/api/access',headers=auths[0]).json()['channel_policy']==policy
 assert client.get('/api/access',headers=auths[1]).json()['channel_policy']=={'hidden_ids':[],'hidden_categories':[],'order':[]}
 assert client.get('/api/admin/channels?id='+ids[0]).json()['channels']==catalog


def test_reseller_isolation_and_updates():
 app.limits.clear();dns=setup()
 def create(name):
  assert client.post('/api/admin/resellers',headers=origin,json={'username':name,'display_name':name,'password':'test-only-123','enabled':True}).status_code==200
 create('seller1');create('seller2')
 a=TestClient(app.app,base_url='https://orion.test');b=TestClient(app.app,base_url='https://orion.test')
 for c,n in [(a,'seller1'),(b,'seller2')]:assert c.post('/api/admin/login',headers=origin,json={'username':n,'password':'test-only-123'}).status_code==200
 assert a.get('/api/admin/data').json()['role']=='reseller'
 for path in ['dns','demo','resellers']:assert a.post('/api/admin/'+path,headers=origin,json={}).status_code==403
 body={'name':'Seller client','mode':'credentials','username':'sellerclient','password':'test-only-123','dns_id':dns,'service_user':'service','service_password':'secret','months':1,'owner_id':'seller2'}
 assert a.post('/api/admin/license',headers=origin,json=body).status_code==200
 rows=a.get('/api/admin/data').json()['licenses'];assert len(rows)==1 and rows[0]['owner_id']=='seller1'
 assert b.get('/api/admin/data').json()['licenses']==[]
 id=rows[0]['id'];assert b.post('/api/admin/license',headers=origin,json={**body,'id':id}).status_code==403
 assert b.get('/api/admin/channels',params={'id':id}).status_code==403
 assert b.post('/api/admin/channels',headers=origin,json={'id':id}).status_code==403
 assert client.post('/api/admin/resellers',headers=origin,json={'username':'seller1','enabled':False}).status_code==200
 assert a.get('/api/admin/data').status_code==401
 r=client.get('/api/panel-version');assert r.status_code==200 and len(r.json()['version'])==16 and r.headers['cache-control']=='no-store'

def test_alternative_service_endpoints():
 app.limits.clear();dns=setup()
 body={'id':dns,'name':'Servicio con respaldo','url':'https://example.invalid','is_default':True,'alternatives':['https://backup.invalid:8443','https://other.invalid']}
 assert client.post('/api/admin/dns',headers=origin,json=body).status_code==200
 d,auth=register();r=client.post('/api/demo/start',json={},headers=auth);assert r.status_code==200
 assert r.json()['dns_alternatives']==body['alternatives']
 for alternatives in [['https://evil.invalid@else.invalid'],['https://backup.invalid:99999'],['https://backup.invalid?password=secret'],['http://downgrade.invalid'],['https://a.invalid']*4]:
  assert client.post('/api/admin/dns',headers=origin,json={**body,'alternatives':alternatives}).status_code==400
 saved=next(x for x in client.get('/api/admin/data').json()['dns'] if x['id']==dns)
 import json
 assert json.loads(saved['alternatives'])==body['alternatives']

def test_unified_demo_reseller_activation_and_channel_policy():
 import uuid,secrets
 app.limits.clear();dns=setup()
 assert client.post('/api/admin/dns',headers=origin,json={'id':dns,'name':'Servicio integrado','url':'https://example.invalid','is_default':True,'alternatives':['https://backup.invalid:8443','https://other.invalid']}).status_code==200
 assert client.post('/api/admin/resellers',headers=origin,json={'username':'unifiedseller','display_name':'Revendedor integrado','password':'TestAB12','enabled':True}).status_code==200
 seller=TestClient(app.app,base_url='https://orion.test')
 assert seller.post('/api/admin/login',headers=origin,json={'username':'unifiedseller','password':'TestAB12'}).status_code==200
 secret=secrets.token_urlsafe(32)
 registered=client.post('/api/register',json={'installation_id':str(uuid.uuid4()),'registration_secret':secret,'id_format':'alphanumeric8'}).json()
 auth={'Authorization':'Bearer '+registered['device_token']}
 trial=client.post('/api/demo/start',json={},headers=auth).json();assert trial['status']=='demo' and 7198<=trial['expires_at']-trial['server_time']<=7200
 body={'name':'Cliente integrado','mode':'mac','mac':registered['mac'],'dns_id':dns,'service_user':'unified-provider','service_password':'unified-secret','months':1,'enabled':True}
 assert seller.post('/api/admin/license',json=body,headers=origin).status_code==200
 account=seller.get('/api/admin/data').json()['licenses'][0];assert account['owner_id']=='unifiedseller'
 policy={'hidden_ids':['10'],'hidden_categories':[],'order':['30','20']}
 assert seller.post('/api/admin/channels',json={'id':account['id'],'channels':[],'policy':policy},headers=origin).status_code==200
 response=client.get('/api/access',headers=auth).json();assert response['status']=='active' and response['channel_policy']==policy and response['username']=='unified-provider'
 assert response['dns_alternatives']==['https://backup.invalid:8443','https://other.invalid']
 # Conversion does not restart the original trial or create a new installation.
 with app.db() as c:assert c.execute('SELECT demo_expires FROM devices WHERE id=?',(registered['device_id'],)).fetchone()[0]==trial['expires_at']
 # Only the corresponding license is suspended, using the same panel and API.
 assert seller.post('/api/admin/license',json={**body,'id':account['id'],'months':0,'enabled':False},headers=origin).status_code==200
 assert client.get('/api/access',headers=auth).status_code==403
