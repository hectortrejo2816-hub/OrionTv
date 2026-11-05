"""Public update contract. No account data; publication is an administrator Git change."""
import json
import re
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import Depends, HTTPException
from fastapi.responses import JSONResponse, FileResponse

PACKAGE = 'com.oriontv.independent'
MAX_BYTES = 300 * 1024 * 1024

def validate_release(data):
    if not isinstance(data, dict) or data.get('enabled') is not True:
        return {'enabled': False}
    for key, low, high in [('version_code', 1, 2147483647), ('min_sdk', 23, 10000), ('size_bytes', 1, MAX_BYTES)]:
        value = data.get(key)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(key)
    if data.get('package_name') != PACKAGE:
        raise ValueError('package')
    for key in ('sha256', 'signer_sha256'):
        if not isinstance(data.get(key), str) or not re.fullmatch(r'[0-9a-fA-F]{64}', data[key]):
            raise ValueError(key)
    u = urlsplit(data.get('apk_url', ''))
    if u.scheme != 'https' or not u.hostname or u.username is not None or u.password is not None or u.fragment:
        raise ValueError('url')
    if not isinstance(data.get('version_name'), str) or not 1 <= len(data['version_name']) <= 100:
        raise ValueError('name')
    if not isinstance(data.get('notes', ''), str) or len(data.get('notes', '')) > 2000:
        raise ValueError('notes')
    return {k: data[k] for k in ('enabled', 'package_name', 'version_code', 'version_name', 'min_sdk', 'size_bytes', 'sha256', 'signer_sha256', 'apk_url')} | {'notes': data.get('notes', '')}

def install_app_updates(ns):
    app, db, admin = ns['app'], ns['db'], ns['admin']
    manifest = Path(__file__).with_name('android-stable.json')
    with db() as c:
        c.execute('CREATE TABLE IF NOT EXISTS apk_publication(id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL)')
    def candidate():
        try:
            if manifest.stat().st_size > 65536:
                raise ValueError('size')
            return validate_release(json.loads(manifest.read_text(encoding='utf-8')))
        except (OSError, ValueError, TypeError):
            return {'enabled': False}
    def published():
        with db() as c:
            row = c.execute('SELECT payload FROM apk_publication WHERE id=1').fetchone()
        try:
            return validate_release(json.loads(row['payload'])) if row else {'enabled': False}
        except (ValueError, TypeError):
            return {'enabled': False}
    @app.get('/api/app-updates/android/stable')
    def android_stable():
        return JSONResponse(published(), headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})
    @app.get('/actualizaciones', include_in_schema=False)
    def update_page(actor=Depends(admin)):
        return FileResponse(Path(__file__).with_name('actualizaciones.html'))
    @app.get('/api/admin/apk-updates')
    def update_status(actor=Depends(admin)):
        return {'candidate': candidate(), 'published': published()}
    @app.post('/api/admin/apk-updates/publish')
    def publish(actor=Depends(admin)):
        data = candidate()
        if not data.get('enabled'):
            raise HTTPException(400, 'Primero prepara una APK firmada y sus metadatos verificados.')
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            row = c.execute('SELECT payload FROM apk_publication WHERE id=1').fetchone()
            previous = json.loads(row['payload']) if row else {}
            if data['version_code'] <= previous.get('version_code', 0):
                raise HTTPException(409, 'Esta version ya se publico o es anterior.')
            c.execute('INSERT OR REPLACE INTO apk_publication VALUES(1,?)', (json.dumps(data),))
        return {'ok': True, 'version_code': data['version_code']}
