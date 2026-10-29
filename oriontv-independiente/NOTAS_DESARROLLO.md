# Estado técnico y límites

El código original de este paquete se creó para OrionTV. Dependencias de terceros: AndroidX Media3, Android SDK/Gradle, FastAPI, Uvicorn y cryptography, sujetas a sus respectivas licencias. No es una clonación de código de otra aplicación.

API de app:
- POST /api/register: identificador de instalación aleatorio. Responde código numérico de 8 dígitos y token propio de dispositivo.
- POST /api/demo/start: token de dispositivo; inicia una prueba solo si nunca fue utilizada.
- POST /api/activate: token + credenciales de activación de OrionTV.
- GET /api/access: token; devuelve acceso vigente y credenciales de reproducción, o deniega.

No se incluye ninguna contraseña de administrador o proveedor. El administrador se crea mediante manage.py. La base de datos y la clave se generan al iniciar por primera vez, fuera del código.

Las rutas /api/admin se autentican mediante sesión. Las operaciones de escritura requieren un Origin idéntico a PUBLIC_URL. El proxy debe preservar Host, sin reescribir el Origin del visitante.

La app de prueba permite tráfico HTTP para proveedores que todavía lo requieren, pero exige HTTPS para la activación. No realiza conversión de audio. La primera interfaz es funcional con controles nativos y foco para mando, y requiere QA en equipos reales.

La variante debug incluye los recursos y el logo propios y no se actualiza sobre Technored. Para producción hay que crear una firma propia y mantenerla para todas las futuras actualizaciones de OrionTV.

Verificar actualizaciones y vulnerabilidades de dependencias antes de exponer el servicio en internet. Añadir respaldos y controles de abuso acordes al volumen. El límite básico de intentos en memoria no sustituye controles distribuidos en instalaciones de múltiples procesos.


Revendedores: autenticación de sesiones vinculada a admins.name, con role y enabled. Licencias separadas por owner_id, validación de propiedad en lectura, edición y canales. Los revendedores nuevos asignan siempre sus clientes a sí mismos. DNS compartidos de solo lectura; cambios de DNS, demos y revendedores solo para admin. Sesiones previas a la migración deben iniciar sesión de nuevo. GET /api/panel-version calcula una huella del código y los recursos estáticos. Las actualizaciones no se descargan de terceros: el administrador publica el código una sola vez.
