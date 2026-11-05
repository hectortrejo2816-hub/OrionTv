"""MATEO panel assistant: local, read-only account queries; no external AI or WhatsApp."""
import time
from fastapi import Depends,Request

def install_mateo_panel(ns):
 app,db,check,operator=ns['app'],ns['db'],ns['check'],ns['operator']
 @app.post('/api/admin/mateo/query')
 async def query(req:Request,actor=Depends(operator)):
  body=await req.json();check(isinstance(body,dict),'Solicitud inválida')
  command=body.get('command','summary');check(command in ('summary','expiring','client'),'Selecciona una consulta disponible')
  with db() as c:
   scope='' if actor['role']=='admin' else ' WHERE owner_id=?'
   params=() if actor['role']=='admin' else (actor['name'],)
   rows=[dict(r) for r in c.execute('SELECT id,name,mac,username,enabled,expires FROM licenses'+scope,params)]
   now=int(time.time())
   if command=='summary':
    active=sum(bool(r['enabled']) and r['expires']>now for r in rows)
    expiring=sum(bool(r['enabled']) and now<r['expires']<=now+7*86400 for r in rows)
    return {'reply':f'Tienes {len(rows)} clientes: {active} activos y {expiring} por vencer en los próximos 7 días.','clients':[]}
   if command=='expiring':
    selected=sorted((r for r in rows if r['enabled'] and now<r['expires']<=now+7*86400),key=lambda r:r['expires'])
    return {'reply':f'{len(selected)} clientes por vencer en los próximos 7 días.','clients':selected[:100]}
   text=body.get('text','');check(isinstance(text,str) and 0<len(text.strip())<=100,'Escribe un nombre o código de hasta 100 caracteres')
   text=text.strip().casefold()
   selected=[r for r in rows if any(text in str(r.get(k) or '').casefold() for k in ('name','mac','username'))]
   clients=[]
   for r in selected[:20]:
    primary=c.execute('SELECT n.name FROM licenses l JOIN dns n ON n.id=l.dns_id WHERE l.id=?',(r['id'],)).fetchone()
    r['lists']=([primary[0]] if primary else [])+[x[0] for x in c.execute('SELECT name FROM license_playlists WHERE license_id=? ORDER BY rowid',(r['id'],))]
    r['status']='Suspendido' if not r['enabled'] else 'Activo' if r['expires']>now else 'Vencido'
    clients.append(r)
   return {'reply':f'Encontré {len(selected)} coincidencias entre tus clientes.','clients':clients}
