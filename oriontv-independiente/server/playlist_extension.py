"""Additive extension: explicit per-license list assignments, at most five including primary."""
import json
import secrets
import time
from pathlib import Path
from fastapi import Depends, Request
from fastapi.responses import FileResponse


def install_playlists(ns):
    if ns.get('_orion_playlists_installed_v56'):
        return
    app, db, check = ns['app'], ns['db'], ns['check']
    operator, own_license = ns['operator'], ns['own_license']
    seal, unseal = ns['seal'], ns['unseal']
    with db() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS license_playlists (
          id TEXT PRIMARY KEY, license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
          dns_id TEXT NOT NULL REFERENCES dns(id), name TEXT NOT NULL,
          service_user TEXT NOT NULL, service_password TEXT NOT NULL,
          UNIQUE(license_id,dns_id))''')

    # A paid activation ends the trial, without clearing the one-trial history.
    stop_demo_sql = """UPDATE devices SET demo_expires=CAST(strftime('%s','now') AS INTEGER)
      WHERE demo_used=1 AND demo_expires>CAST(strftime('%s','now') AS INTEGER)
      AND EXISTS (SELECT 1 FROM licenses l WHERE l.enabled=1
        AND l.expires>CAST(strftime('%s','now') AS INTEGER)
        AND (l.mac=devices.mac OR l.device_id=devices.id OR EXISTS
          (SELECT 1 FROM license_devices ld WHERE ld.license_id=l.id AND ld.device_id=devices.id)))"""
    with db() as c:
        for trigger, event, table in [('orion_trial_paid_insert_v56','INSERT','licenses'),
                                      ('orion_trial_paid_update_v56','UPDATE','licenses'),
                                      ('orion_trial_paid_bound_v56','INSERT','license_devices')]:
            c.execute('CREATE TRIGGER IF NOT EXISTS '+trigger+' AFTER '+event+' ON '+table+' BEGIN '+stop_demo_sql+'; END')
        c.execute(stop_demo_sql)

    previous_data = ns['data']
    def data_with_trial_state(actor):
        result = previous_data(actor)
        now = int(time.time())
        with db() as c:
            for item in result.get('devices', []):
                license = c.execute('SELECT l.enabled,l.expires FROM licenses l WHERE l.mac=? OR l.device_id=? OR EXISTS\n                  (SELECT 1 FROM license_devices ld WHERE ld.license_id=l.id AND ld.device_id=?)\n                  ORDER BY l.expires DESC LIMIT 1', (item['mac'], item['id'], item['id'])).fetchone()
                if license:
                    item['access_status'] = 'suspended' if not license['enabled'] else 'active' if license['expires']>now else 'expired'
                    item['access_expires_at'] = license['expires']
        return result
    ns['data'] = data_with_trial_state
    for route in app.routes:
        if getattr(route, 'path', '') == '/api/admin/data' and 'GET' in getattr(route, 'methods', set()):
            route.endpoint = data_with_trial_state
            route.dependant.call = data_with_trial_state

    @app.get('/api/admin/licenses/{license_id}/playlists')
    def get_playlists(license_id: str, actor=Depends(operator)):
        own_license(actor, license_id)
        with db() as c:
            row = c.execute('SELECT l.dns_id,l.service_user,n.name FROM licenses l JOIN dns n ON n.id=l.dns_id WHERE l.id=?', (license_id,)).fetchone()
            check(row, 'Cliente no encontrado', 404)
            extra = [dict(r) for r in c.execute('SELECT id,dns_id,name,service_user FROM license_playlists WHERE license_id=? ORDER BY rowid', (license_id,))]
        return {'maximum': 5, 'primary': dict(row), 'playlists': extra}

    @app.put('/api/admin/licenses/{license_id}/playlists')
    async def save_playlists(license_id: str, req: Request, actor=Depends(operator)):
        own_license(actor, license_id)
        body = await req.json()
        rows = body.get('playlists') if isinstance(body, dict) else None
        check(isinstance(rows, list) and len(rows) <= 4, 'Máximo 5 DNS contando la lista principal')
        with db() as c:
            primary = c.execute('SELECT dns_id FROM licenses WHERE id=?', (license_id,)).fetchone()
            check(primary, 'Cliente no encontrado', 404)
            old = {r['id']: dict(r) for r in c.execute('SELECT * FROM license_playlists WHERE license_id=?', (license_id,))}
            seen, seen_ids, cleaned = {primary['dns_id']}, set(), []
            for row in rows:
                check(isinstance(row, dict), 'Lista inválida')
                dns_id, name = str(row.get('dns_id', '')).strip(), str(row.get('name', '')).strip()
                username, password = str(row.get('service_user', '')).strip(), row.get('service_password', '')
                item_id = str(row.get('id', '')).strip()
                check(not item_id or item_id in old, 'La lista no pertenece a este cliente', 403)
                check(not item_id or item_id not in seen_ids, 'Lista duplicada')
                seen_ids.add(item_id)
                check(dns_id not in seen, 'No repitas el mismo DNS para este cliente')
                seen.add(dns_id)
                dns = c.execute('SELECT id,name FROM dns WHERE id=?', (dns_id,)).fetchone()
                check(dns, 'Selecciona un DNS guardado')
                check(ns['allowed_dns'](c,actor,dns_id),'Lista no autorizada para este revendedor',403)
                owner=c.execute('SELECT owner_id FROM licenses WHERE id=?',(license_id,)).fetchone()[0]
                if owner:check(ns['allowed_dns'](c,{'role':'reseller','name':owner},dns_id),'Lista no autorizada para el propietario del cliente',403)
                name = name or dns['name']
                check(0 < len(name) <= 80 and '://' not in name and '\n' not in name, 'Nombre de lista inválido')
                check(0 < len(username) <= 128, 'Completa el usuario del servicio')
                check(isinstance(password, str) and len(password) <= 256, 'Contraseña inválida')
                encrypted = seal(password) if password else old.get(item_id, {}).get('service_password', '')
                check(encrypted, 'Completa la contraseña para la nueva lista')
                cleaned.append((item_id or secrets.token_hex(16), license_id, dns_id, name, username, encrypted))
            # Validation finishes before any deletion; failed edits leave the prior assignment intact.
            c.execute('DELETE FROM license_playlists WHERE license_id=?', (license_id,))
            c.executemany('INSERT INTO license_playlists VALUES (?,?,?,?,?,?)', cleaned)
        return {'ok': True, 'total': 1 + len(cleaned)}

    previous_access = ns['access']

    def access_with_playlists(device):
        result = previous_access(device)  # Existing expiry, suspension, demo and access checks remain authoritative.
        if result.get('status') != 'active':
            return result
        with db() as c:
            primary = c.execute('''SELECT l.id,l.dns_id,n.name FROM licenses l JOIN dns n ON n.id=l.dns_id
              WHERE l.mac=? OR l.device_id=? OR EXISTS
              (SELECT 1 FROM license_devices ld WHERE ld.license_id=l.id AND ld.device_id=?)
              ORDER BY l.expires DESC LIMIT 1''', (device['mac'], device['id'], device['id'])).fetchone()
            check(primary, 'Cliente no encontrado', 404)
            profiles = [{'id': 'primary', 'name': primary['name'], 'dns': result['dns'],
                         'dns_alternatives': result.get('dns_alternatives', []), 'username': result['username'],
                         'password': result['password'], 'channel_policy': result.get('channel_policy', {})}]
            extra = c.execute('''SELECT p.*,n.url,n.alternatives FROM license_playlists p JOIN dns n ON n.id=p.dns_id
              WHERE p.license_id=? AND p.dns_id!=? ORDER BY p.rowid LIMIT 4''', (primary['id'], primary['dns_id']))
            for row in extra:
                profiles.append({'id': row['id'], 'name': row['name'], 'dns': row['url'],
                                 'dns_alternatives': json.loads(row['alternatives']), 'username': row['service_user'],
                                 'password': unseal(row['service_password']),
                                 'channel_policy': result.get('channel_policy', {})})
        result['playlists'], result['default_playlist_id'] = profiles, 'primary'
        return result

    ns['access'] = access_with_playlists

    @app.get('/listas', include_in_schema=False)
    def playlists_page(actor=Depends(operator)):
        return FileResponse(Path(__file__).with_name('listas.html'))

    ns['_orion_playlists_installed_v56'] = True
