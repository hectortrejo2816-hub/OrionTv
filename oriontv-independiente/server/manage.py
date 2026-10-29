import getpass,sys
from app import db,pw_hash
if len(sys.argv)!=2 or sys.argv[1]!='setup':raise SystemExit('Uso: python manage.py setup')
name=input('Nombre de administrador: ').strip();password=getpass.getpass('Contraseña (mínimo 12 caracteres): ')
if not name or len(password)<12:raise SystemExit('Datos incompletos o contraseña demasiado corta.')
with db() as c:c.execute('INSERT INTO admins(name,password) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET password=excluded.password',(name,pw_hash(password)));c.execute('DELETE FROM sessions')
print('Administrador guardado. Las sesiones anteriores fueron cerradas.')
