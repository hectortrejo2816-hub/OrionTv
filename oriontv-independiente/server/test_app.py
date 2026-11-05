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
  assert c.execute('SELECT demo_expires FROM devices WHERE installation=?',(installation,)).fetchone()[0]<=int(time.time())
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
 assert client.put('/api/admin/resellers/seller1/dns',headers=origin,json={'can_add_dns':False,'dns_ids':[dns]}).status_code==200
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
 assert client.put('/api/admin/resellers/unifiedseller/dns',headers=origin,json={'can_add_dns':False,'dns_ids':[dns]}).status_code==200
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
 with app.db() as c:assert c.execute('SELECT demo_expires FROM devices WHERE id=?',(registered['device_id'],)).fetchone()[0]<=int(time.time())
 # Only the corresponding license is suspended, using the same panel and API.
 assert seller.post('/api/admin/license',json={**body,'id':account['id'],'months':0,'enabled':False},headers=origin).status_code==200
 assert client.get('/api/access',headers=auth).status_code==403

def test_remote_app_themes_admin_only_and_access():
 setup()
 anon=TestClient(app.app,base_url='https://orion.test')
 assert anon.post('/api/admin/app-theme',json={'theme':'ibo'},headers=origin).status_code==401
 assert client.post('/api/admin/app-theme',json={'theme':'ibo'},headers={'Origin':'https://wrong.invalid'}).status_code==403
 original=client.get('/api/admin/data').json()['app_theme']
 for theme in ['unknown',['ibo'],None]:
  assert client.post('/api/admin/app-theme',json={'theme':theme},headers=origin).status_code==400
 assert client.get('/api/admin/data').json()['app_theme']==original
 assert client.post('/api/admin/resellers',headers=origin,json={'username':'themeseller','password':'test-only-theme-123','enabled':True}).status_code==200
 reseller=TestClient(app.app,base_url='https://orion.test')
 assert reseller.post('/api/admin/login',headers=origin,json={'username':'themeseller','password':'test-only-theme-123'}).status_code==200
 assert reseller.post('/api/admin/app-theme',json={'theme':'ibo'},headers=origin).status_code==403
 r=client.post('/api/admin/app-theme',json={'theme':'ibo'},headers=origin)
 assert r.status_code==200;selected=r.json();assert selected['theme']=='ibo'
 assert client.post('/api/admin/app-theme',json={'theme':'ibo'},headers=origin).json()==selected
 d,auth=register();access=client.post('/api/demo/start',json={},headers=auth).json()
 assert access['app_theme']==selected
 dns=client.get('/api/admin/data').json()['dns'][0]['id']
 assert client.post('/api/admin/license',headers=origin,json={'name':'Tema activo','mode':'mac','mac':d['mac'],'dns_id':dns,'service_user':'theme-user','service_password':'theme-pass','months':1,'enabled':True}).status_code==200
 licensed=client.get('/api/access',headers=auth).json();assert licensed['status']=='active';assert licensed['app_theme']==selected
 r=client.post('/api/admin/app-theme',json={'theme':'midnight'},headers=origin).json()
 assert r['revision']==selected['revision']+1
 refreshed=client.get('/api/access',headers=auth).json();assert refreshed['app_theme']==r
 assert refreshed['expires_at']==licensed['expires_at'];assert refreshed['username']=='theme-user'
 with app.db() as c:assert app.app_appearance(c)==r
 client.post('/api/admin/app-theme',json={'theme':'orion'},headers=origin)


def test_lists_permissions_and_no_dns_leaks():
 app.limits.clear();dns=setup()
 for name in ['listseller','otherseller']:
  assert client.post('/api/admin/resellers',headers=origin,json={'username':name,'password':'test-only-123','enabled':True}).status_code==200
 a=TestClient(app.app,base_url='https://orion.test');b=TestClient(app.app,base_url='https://orion.test')
 for session,name in [(a,'listseller'),(b,'otherseller')]:
  assert session.post('/api/admin/login',headers=origin,json={'username':name,'password':'test-only-123'}).status_code==200
 assert a.get('/api/admin/data').json()['dns']==[]
 assert a.post('/api/admin/dns',headers=origin,json={'name':'Propia','url':'https://private.invalid'}).status_code==403
 assert client.put('/api/admin/resellers/listseller/dns',headers=origin,json={'can_add_dns':True,'dns_ids':[dns]}).status_code==200
 visible=a.get('/api/admin/data').json()['dns'];assert len(visible)==1 and 'url' not in visible[0] and 'alternatives' not in visible[0]
 assert a.post('/api/admin/dns',headers=origin,json={'name':'Propia','url':'https://private.invalid'}).status_code==200
 own=next(d['id'] for d in a.get('/api/admin/data').json()['dns'] if d['name']=='Propia')
 assert own not in [d['id'] for d in b.get('/api/admin/data').json()['dns']]
 assert b.put('/api/admin/resellers/listseller/dns',headers=origin,json={'can_add_dns':True,'dns_ids':[dns]}).status_code==403
 assert a.post('/api/admin/dns',headers=origin,json={'id':dns,'name':'Hack','url':'https://changed.invalid'}).status_code==403
 d,auth=register();body={'name':'Cliente listas','mode':'mac','mac':d['mac'],'dns_id':dns,'service_user':'first','service_password':'secret','months':12}
 assert a.post('/api/admin/license',headers=origin,json=body).status_code==200
 lic=a.get('/api/admin/data').json()['licenses'][0]['id']
 path='/api/admin/licenses/'+lic+'/playlists'
 row={'dns_id':own,'name':'Mi lista','service_user':'second','service_password':'other-secret'}
 assert a.put(path,headers=origin,json={'playlists':[row]}).status_code==200
 assert b.get(path).status_code==403
 access=client.get('/api/access',headers=auth).json();assert len(access['playlists'])==2 and access['playlists'][1]['username']=='second'
 assert 'other-secret' not in a.get(path).text
 assert a.put(path,headers=origin,json={'playlists':[row]*5}).status_code==400
 assert len(client.get('/api/access',headers=auth).json()['playlists'])==2
 assert client.put('/api/admin/resellers/listseller/dns',headers=origin,json={'can_add_dns':False,'dns_ids':[dns]}).status_code==200
 assert a.post('/api/admin/dns',headers=origin,json={'name':'Otra','url':'https://new.invalid'}).status_code==403
 assert len(a.get('/api/admin/data').json()['dns'])==2
 assert client.put('/api/admin/resellers/listseller/dns',headers=origin,json={'can_add_dns':False,'dns_ids':[]}).status_code==200
 assert a.post('/api/admin/license',headers=origin,json={**body,'id':lic,'months':0}).status_code==403
 assert client.get('/listas').status_code==200 and client.get('/permisos-listas').status_code==200
 assert TestClient(app.app).get('/listas').status_code==401

def test_five_lists_atomic_limit():
 app.limits.clear();dns=setup();ids=[]
 for n in range(5):
  name='Limit '+str(n)
  assert client.post('/api/admin/dns',headers=origin,json={'name':name,'url':'https://limit'+str(n)+'.invalid'}).status_code==200
  ids.append(next(d['id'] for d in client.get('/api/admin/data').json()['dns'] if d['name']==name))
 d,auth=register()
 assert client.post('/api/demo/start',headers=auth,json={}).status_code==200
 body={'name':'Five lists','mode':'mac','mac':d['mac'],'dns_id':dns,'service_user':'primary','service_password':'primary-secret','months':12}
 assert client.post('/api/admin/license',headers=origin,json=body).status_code==200
 lic=next(l['id'] for l in client.get('/api/admin/data').json()['licenses'] if l['mac']==d['mac'])
 path='/api/admin/licenses/'+lic+'/playlists'
 rows=[{'dns_id':value,'name':'List '+str(i),'service_user':'user'+str(i),'service_password':'secret'+str(i)} for i,value in enumerate(ids)]
 assert client.put(path,headers=origin,json={'playlists':rows[:4]}).status_code==200
 access=client.get('/api/access',headers=auth).json();assert len(access['playlists'])==5 and access['playlists'][4]['password']=='secret3';expiry=access['expires_at']
 for bad in [rows,[rows[0],rows[0]],[{**rows[0],'dns_id':'nonexistent'}]]:
  assert client.put(path,headers=origin,json={'playlists':bad}).status_code==400
  assert len(client.get('/api/access',headers=auth).json()['playlists'])==5
 saved=client.get(path).json()['playlists']
 assert client.put(path,headers=origin,json={'playlists':saved}).status_code==200
 assert client.get('/api/access',headers=auth).json()['playlists'][4]['password']=='secret3'
 with app.db() as c:
  assert all(not r[0].startswith('secret') for r in c.execute('SELECT service_password FROM license_playlists WHERE license_id=?',(lic,)))
  trial=c.execute('SELECT demo_expires,demo_used FROM devices WHERE mac=?',(d['mac'],)).fetchone();assert trial['demo_used']==1 and trial['demo_expires']<=int(time.time())
 assert client.put(path,headers=origin,json={'playlists':[]}).status_code==200
 access=client.get('/api/access',headers=auth).json();assert len(access['playlists'])==1 and access['expires_at']==expiry

def test_mateo_panel_authorization_and_queries():
 app.limits.clear();dns=setup()
 anon=TestClient(app.app,base_url='https://orion.test')
 assert anon.post('/api/admin/mateo/query',headers=origin,json={'command':'summary'}).status_code==401
 assert client.post('/api/admin/resellers',headers=origin,json={'username':'mateoseller','password':'test-only-123'}).status_code==200
 seller=TestClient(app.app,base_url='https://orion.test')
 assert seller.post('/api/admin/login',headers=origin,json={'username':'mateoseller','password':'test-only-123'}).status_code==200
 response=seller.post('/api/admin/mateo/query',headers=origin,json={'command':'summary'});assert response.status_code==200 and '0 clientes' in response.json()['reply']
 assert seller.post('/api/admin/mateo/query',headers=origin,json={'command':'client','text':'Cliente'}).json()['clients']==[]
 assert client.post('/api/admin/mateo/query',headers=origin,json={'command':'delete'}).status_code==400
 assert client.post('/api/admin/mateo/query',headers=origin,json={'command':'client','text':''}).status_code==400
 r=client.post('/api/admin/mateo/query',headers=origin,json={'command':'client','text':'Five lists'});assert r.status_code==200
 assert r.json()['clients'] and 'lists' in r.json()['clients'][0]
 assert 'primary-secret' not in r.text and 'https://' not in r.text
 assert client.post('/api/admin/mateo/query',headers=origin,json={'command':'expiring'}).status_code==200

def test_preserved_whatsapp_routes_and_owner_isolation(monkeypatch):
 app.limits.clear();setup()
 anon=TestClient(app.app,base_url='https://orion.test')
 assert anon.get('/mateo').status_code==401
 assert client.get('/mateo').status_code==200
 result=client.get('/api/admin/mateo-whatsapp');assert result.status_code==200
 seller=TestClient(app.app,base_url='https://orion.test')
 assert seller.post('/api/admin/login',headers=origin,json={'username':'mateoseller','password':'test-only-123'}).status_code==200
 assert seller.get('/mateo').status_code==403
 assert seller.get('/api/admin/mateo-whatsapp').status_code==403
 monkeypatch.setenv('MATEO_WA_VERIFY_TOKEN','fixture-token-no-secrets')
 params={'hub.mode':'subscribe','hub.verify_token':'fixture-token-no-secrets','hub.challenge':'test-challenge'}
 assert anon.get('/api/mateo/whatsapp',params=params).text=='test-challenge'
 assert anon.get('/api/mateo/whatsapp',params={**params,'hub.verify_token':'wrong'}).status_code==403
 monkeypatch.setenv('MATEO_WA_ENABLED','0')
 assert anon.post('/api/mateo/whatsapp',json={}).status_code==503
 with app.db() as c:
  for name in ['mateo_owner','mateo_messages','mateo_aliases','license_playlists','reseller_dns']:
   assert c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone()

def test_apk_publication_admin_atomic_and_persistence(monkeypatch):
 import json
 from pathlib import Path
 import app_updates
 setup()
 anon=TestClient(app.app,base_url='https://orion.test')
 assert anon.get('/api/admin/apk-updates').status_code==401
 assert anon.post('/api/admin/apk-updates/publish',headers=origin).status_code==401
 assert client.post('/api/admin/apk-updates/publish',headers={'Origin':'https://wrong.invalid'}).status_code==403
 # Patch only manifest I/O, never a real APK or the published database.
 candidate={'enabled':True,'package_name':'com.oriontv.independent','version_code':57,'version_name':'2.9.7','min_sdk':23,'size_bytes':100,'sha256':'a'*64,'signer_sha256':'b'*64,'apk_url':'https://example.invalid/orion-57.apk','notes':'Mejoras'}
 original=Path.read_text
 monkeypatch.setattr(Path,'read_text',lambda self,*a,**kw:json.dumps(candidate) if self.name=='android-stable.json' else original(self,*a,**kw))
 assert anon.get('/api/app-updates/android/stable').json()=={'enabled':False}
 assert client.post('/api/admin/apk-updates/publish',headers=origin).status_code==200
 assert anon.get('/api/app-updates/android/stable').json()['version_code']==57
 assert client.post('/api/admin/apk-updates/publish',headers=origin).status_code==409
 candidate['version_code']=56
 assert client.post('/api/admin/apk-updates/publish',headers=origin).status_code==409
 candidate['version_code']=58;candidate['apk_url']='http://example.invalid/a.apk'
 assert client.post('/api/admin/apk-updates/publish',headers=origin).status_code==400
 assert anon.get('/api/app-updates/android/stable').json()['version_code']==57
 assert anon.get('/api/app-updates/android/stable').headers['cache-control']=='no-store'
 # A reseller cannot publish or load the admin publication page.
 with app.db() as c:
  c.execute("INSERT INTO admins(name,password,role,enabled) VALUES(?,?,?,1)",('updates-reseller',app.pw_hash('reseller-test-only'),'reseller'))
 reseller=TestClient(app.app,base_url='https://orion.test')
 assert reseller.post('/api/admin/login',json={'username':'updates-reseller','password':'reseller-test-only'},headers=origin).status_code==200
 assert reseller.post('/api/admin/apk-updates/publish',headers=origin).status_code==403
 assert reseller.get('/actualizaciones').status_code==403
 assert client.get('/actualizaciones').status_code==200

# Business management regression: no external providers or AI calls are made here.
def business_fixture():
 import uuid
 app.limits.clear();dns=setup();name='r'+uuid.uuid4().hex[:10]
 assert client.post('/api/admin/resellers',headers=origin,json={'username':name,'password':'test-only-reseller','enabled':True}).status_code==200
 assert client.put('/api/admin/resellers/'+name+'/dns',headers=origin,json={'can_add_dns':False,'dns_ids':[dns]}).status_code==200
 seller=TestClient(app.app,base_url='https://orion.test')
 assert seller.post('/api/admin/login',headers=origin,json={'username':name,'password':'test-only-reseller'}).status_code==200
 username='u'+uuid.uuid4().hex[:10]
 body={'name':'Business '+username,'mode':'credentials','username':username,'password':'activation-test','dns_id':dns,'service_user':'provider-secret-user','service_password':'provider-secret-password','months':1,'enabled':True,'owner_id':name}
 assert client.post('/api/admin/license',headers=origin,json=body).status_code==200
 lic=next(l for l in client.get('/api/admin/data').json()['licenses'] if l['username']==username)
 return dns,name,seller,lic,body

def test_business_payments_scope_validation_and_history():
 dns,name,seller,l,b=business_fixture();path='/api/admin/business/payment'
 pay={'license_id':l['id'],'amount':'150.00','currency':'MXN','method':'Efectivo','reference':'Prueba'}
 assert seller.post(path,json=pay,headers=origin).status_code==200
 assert seller.post(path,json={**pay,'amount':'0.001'},headers=origin).status_code==400
 assert seller.post(path,json={**pay,'amount':'NaN'},headers=origin).status_code==400
 assert seller.post(path,json={**pay,'currency':'OTHER'},headers=origin).status_code==400
 d=seller.get('/api/admin/business').json();assert d['payments'][0]['amount_cents']==15000
 assert any(h['action']=='Pago registrado' for h in d['history'])
 assert 'provider-secret-password' not in str(d)
 anon=TestClient(app.app,base_url='https://orion.test');assert anon.get('/api/admin/business').status_code==401
 other=next(x for x in client.get('/api/admin/data').json()['licenses'] if x['id']!=l['id'])
 assert seller.post(path,json={**pay,'license_id':other['id']},headers=origin).status_code==404
 with app.db() as c:assert c.execute('SELECT expires FROM licenses WHERE id=?',(l['id'],)).fetchone()[0]==l['expires']

def test_business_batch_trash_restore_and_atomicity():
 dns,name,seller,l,b=business_fixture();path='/api/admin/business/batch'
 assert seller.post(path,json={'ids':[l['id']],'action':'trash'},headers=origin).status_code==403
 assert client.put('/api/admin/business/reseller/'+name,json={'permissions':{'delete':True}},headers=origin).status_code==200
 assert seller.post(path,json={'ids':[l['id'],'unknown'],'action':'renew','months':1},headers=origin).status_code==404
 with app.db() as c:assert c.execute('SELECT expires FROM licenses WHERE id=?',(l['id'],)).fetchone()[0]==l['expires']
 assert seller.post(path,json={'ids':[l['id']],'action':'trash'},headers=origin).status_code==200
 assert l['id'] not in [x['id'] for x in seller.get('/api/admin/data').json()['licenses']]
 assert next(x for x in seller.get('/api/admin/business').json()['clients'] if x['id']==l['id'])['deleted_at']
 assert seller.post('/api/admin/license',json={**b,'id':l['id'],'months':0},headers=origin).status_code==409
 assert seller.post(path,json={'ids':[l['id']],'action':'restore'},headers=origin).status_code==200
 with app.db() as c:
  restored=c.execute('SELECT * FROM licenses WHERE id=?',(l['id'],)).fetchone();assert restored['enabled']==1 and restored['expires']==l['expires'] and restored['deleted_at'] is None

def test_business_permissions_enforced_on_old_routes_and_playlists():
 dns,name,seller,l,b=business_fixture()
 assert client.put('/api/admin/business/reseller/'+name,json={'permissions':{'edit':False,'renew':False,'create':False}},headers=origin).status_code==200
 assert seller.post('/api/admin/license',json={**b,'id':l['id'],'months':1},headers=origin).status_code==403
 assert seller.put('/api/admin/licenses/'+l['id']+'/playlists',json={'playlists':[]},headers=origin).status_code==403
 assert seller.post('/api/admin/business/batch',json={'ids':[l['id']],'action':'renew','months':1},headers=origin).status_code==403
 assert seller.post('/api/admin/license',json={**b,'username':'fresh-business'},headers=origin).status_code==403
 assert seller.put('/api/admin/business/reseller/'+name,json={'permissions':{'edit':True}},headers=origin).status_code==403

def test_business_telemetry_brand_notices_and_owner_isolation():
 dns,name,seller,l,b=business_fixture();d,auth=register()
 assert client.put('/api/admin/business/reseller/'+name,json={'permissions':{'announce':True},'brand':'Mi marca','whatsapp':'+521234567890'},headers=origin).status_code==200
 assert client.post('/api/activate',json={'username':l['username'],'password':'activation-test'},headers=auth).status_code==200
 assert seller.post('/api/admin/business/notice',json={'title':'Mantenimiento','body':'Prueba controlada','ids':[l['id']],'days':1},headers=origin).status_code==200
 payload={'version_code':58,'version_name':'v58','sdk':35,'model':'Test device','engine':'VLC','error_code':'playback'}
 result=client.post('/api/device/report',json=payload,headers=auth);assert result.status_code==200
 assert result.json()['support']['brand']=='Mi marca';assert result.json()['notices'][0]['title']=='Mantenimiento'
 assert client.post('/api/device/report',json={**payload,'error_code':'http://secret/url'},headers=auth).status_code==400
 rows=seller.get('/api/admin/business').json()['clients'];dev=next(x for x in rows if x['id']==l['id'])['devices'][0]
 assert dev['version_code']==58 and dev['error_code']=='playback'
 unrelated,unrelated_auth=register();assert client.post('/api/device/report',json=payload,headers=unrelated_auth).json()['notices']==[]
 assert client.post('/api/device/report',json=payload).status_code==401

def test_business_reset_device_keeps_expiry_and_rotates_password():
 dns,name,seller,l,b=business_fixture();d,auth=register()
 assert client.post('/api/activate',json={'username':l['username'],'password':'activation-test'},headers=auth).status_code==200
 assert seller.post('/api/admin/business/reset-device/'+l['id'],json={'password':'replacement-test'},headers=origin).status_code==403
 assert client.put('/api/admin/business/reseller/'+name,json={'permissions':{'reset':True}},headers=origin).status_code==200
 assert seller.post('/api/admin/business/reset-device/'+l['id'],json={'password':'replacement-test'},headers=origin).status_code==200
 assert client.get('/api/access',headers=auth).status_code==403
 assert client.post('/api/activate',json={'username':l['username'],'password':'activation-test'},headers=auth).status_code==401
 assert client.post('/api/activate',json={'username':l['username'],'password':'replacement-test'},headers=auth).status_code==200
 with app.db() as c:assert c.execute('SELECT expires FROM licenses WHERE id=?',(l['id'],)).fetchone()[0]==l['expires']

def test_business_mateo_confirmation_stale_and_single_use():
 dns,name,seller,l,b=business_fixture()
 path='/api/admin/business/mateo/'
 p=seller.post(path+'prepare',json={'ids':[l['id']],'action':'renew','months':1},headers=origin);assert p.status_code==200
 proposal=p.json()['proposal_id']
 with app.db() as c:assert c.execute('SELECT expires FROM licenses WHERE id=?',(l['id'],)).fetchone()[0]==l['expires']
 assert seller.post(path+'confirm',json={'proposal_id':proposal},headers=origin).status_code==200
 assert seller.post(path+'confirm',json={'proposal_id':proposal},headers=origin).status_code==409
 p=seller.post(path+'prepare',json={'ids':[l['id']],'action':'renew','months':1},headers=origin).json()
 with app.db() as c:c.execute('UPDATE licenses SET enabled=0 WHERE id=?',(l['id'],))
 assert seller.post(path+'confirm',json={'proposal_id':p['proposal_id']},headers=origin).status_code==409

def test_business_backup_encrypted_and_recovery_offline(tmp_path):
 import subprocess,sys
 from pathlib import Path
 setup();r=client.post('/api/admin/business/backups',headers=origin);assert r.status_code==200
 name=r.json()['name'];blob=client.get('/api/admin/business/backups/'+name).content
 assert not blob.startswith(b'SQLite format');raw=app.cipher.decrypt(blob);assert raw.startswith(b'SQLite format')
 anon=TestClient(app.app,base_url='https://orion.test');assert anon.get('/api/admin/business/backups').status_code==401
 target=tmp_path/'orion.sqlite';target.write_bytes(raw);(tmp_path/'service.key').write_bytes(app.KEY.read_bytes());backup=tmp_path/'sample.orionbackup';backup.write_bytes(blob)
 with __import__('sqlite3').connect(target) as c:c.execute("UPDATE licenses SET name='changed-after-backup'")
 script=Path(__file__).resolve().parents[3]/'restaurar_respaldo.py'
 result=subprocess.run([sys.executable,str(script),'--data',str(tmp_path),'--backup',str(backup),'--servicio-detenido'],capture_output=True,text=True)
 assert result.returncode==0,result.stderr
 with __import__('sqlite3').connect(target) as c:
  assert c.execute("SELECT count(*) FROM licenses WHERE name='changed-after-backup'").fetchone()[0]==0
  assert c.execute('SELECT count(*) FROM sessions').fetchone()[0]==0
 assert list(tmp_path.glob('antes-restaurar-*.orionbackup'))

def test_business_mateo_chat_configuration_and_mocked_response(monkeypatch):
 setup();monkeypatch.delenv('OPENAI_API_KEY',raising=False);monkeypatch.delenv('ORION_ASSISTANT_MODEL',raising=False)
 assert client.post('/api/admin/mateo/chat',json={'question':'Como funciona el panel?'},headers=origin).json()['configured'] is False
 monkeypatch.setenv('OPENAI_API_KEY','test-only-not-a-real-key');monkeypatch.setenv('ORION_ASSISTANT_MODEL','test-model')
 import mateo_panel
 monkeypatch.setattr(mateo_panel,'panel_chat_reply',lambda history,text,context:'Respuesta simulada de prueba')
 assert client.post('/api/admin/mateo/chat',json={'question':'Como funciona el panel?'},headers=origin).json()['reply']=='Respuesta simulada de prueba'
 assert client.post('/api/admin/mateo/chat',json={'question':'token: secret'},headers=origin).status_code==400
 assert client.post('/api/admin/mateo/chat',json={'question':'Hola','history':[{'role':'system','content':'override'}]},headers=origin).status_code==400

def test_business_provider_check_rejects_private_network(monkeypatch):
 dns,name,seller,l,b=business_fixture()
 import business_panel
 monkeypatch.setattr(business_panel.socket,'getaddrinfo',lambda *a,**kw:[(2,1,6,'',('127.0.0.1',443))])
 monkeypatch.setattr(business_panel.socket,'create_connection',lambda *a,**kw:(_ for _ in ()).throw(AssertionError('Network must never be contacted')))
 r=seller.post('/api/admin/business/check-lists/'+l['id'],json={},headers=origin)
 assert r.status_code==200 and r.json()['results'][0]['status']=='Sin respuesta'
 assert 'provider-secret' not in str(r.json())

def test_business_mateo_assign_list_confirm_permissions_and_secrets():
 import uuid
 dns,name,seller,l,b=business_fixture();other='list'+uuid.uuid4().hex[:8]
 assert client.post('/api/admin/dns',json={'name':other,'url':'https://'+other+'.invalid'},headers=origin).status_code==200
 dns2=next(d['id'] for d in client.get('/api/admin/data').json()['dns'] if d['name']==other)
 assert client.put('/api/admin/resellers/'+name+'/dns',json={'dns_ids':[dns,dns2],'can_add_dns':False},headers=origin).status_code==200
 body={'ids':[l['id']],'action':'assign_list','dns_id':dns2,'service_user':'second-user','service_password':'second-password'}
 r=seller.post('/api/admin/business/mateo/prepare',json=body,headers=origin);assert r.status_code==200
 assert 'second-password' not in str(r.json());pid=r.json()['proposal_id']
 assert seller.post('/api/admin/business/mateo/confirm',json={'proposal_id':pid},headers=origin).status_code==200
 with app.db() as c:
  saved=c.execute('SELECT service_password FROM license_playlists WHERE license_id=?',(l['id'],)).fetchone()[0]
  assert saved!='second-password' and app.unseal(saved)=='second-password'
 assert client.put('/api/admin/business/reseller/'+name,json={'permissions':{'mateo':False}},headers=origin).status_code==200
 assert seller.post('/api/admin/mateo/query',json={'command':'summary'},headers=origin).status_code==403
 assert seller.post('/api/admin/mateo/chat',json={'question':'Hola'},headers=origin).status_code==403

def test_business_chat_context_excludes_other_resellers_and_credentials(monkeypatch):
 dns,name,seller,l,b=business_fixture();monkeypatch.setenv('OPENAI_API_KEY','test-key');monkeypatch.setenv('ORION_ASSISTANT_MODEL','test-model')
 import mateo_panel
 observed=[]
 def fake(history,question,context):observed.append(context);return 'Datos consultados en prueba'
 monkeypatch.setattr(mateo_panel,'panel_chat_reply',fake)
 r=seller.post('/api/admin/mateo/chat',json={'question':'Revisa '+l['name']},headers=origin);assert r.status_code==200
 assert observed[0]['total_clients']==1 and observed[0]['clients'][0]['name']==l['name']
 assert 'provider-secret' not in str(observed[0]) and 'password' not in str(observed[0])
