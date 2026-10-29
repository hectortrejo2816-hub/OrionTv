# OrionTV: proyecto reunido

La aplicación Android, la API y el panel del VPS están reunidos en este proyecto. El panel del VPS y la app comparten el protocolo de activación: registro del ID, demo, validación del acceso, credenciales y reglas de canales. Para que funcionen en internet todavía hay que instalar este proyecto en tu propio servidor y compilar la app con su dominio real.

## Qué contiene

| Parte | Ubicación | Para qué sirve |
| --- | --- | --- |
| App OrionTV | android/ | Android, Android TV y Fire TV con Android compatible |
| Servidor y panel OrionTV | server/ | Clientes, licencias, demos, DNS y revendedores |
| Configuración del servicio | compose.yaml | Ejecutar únicamente el servicio propio de OrionTV |
| Instalación | INSTALACION_VPS.md | Preparar tu dominio HTTPS y despliegue sin sustituir servicios existentes |
| Comprobaciones | VERIFICACION.json | Qué se probó y qué sigue pendiente |

## Funciones reunidas

- Identidad y logo OrionTV, aplicación con identificador propio com.oriontv.independent.
- ID local de 8 caracteres, letras y números. Se conserva al actualizar sobre la misma instalación; borrar datos o reinstalar puede cambiarlo.
- Acceso por ID o usuario y contraseña; generador de credenciales de 8 caracteres y ficha para copiar al cliente. La contraseña solo se muestra al crearla o cambiarla.
- Duración de 1 a 12 meses y límite de 1 a 4 instalaciones en cuentas de usuario/contraseña.
- DNS guardados y hasta tres direcciones alternativas de reproducción por servicio.
- Demo de dos horas por instalación registrada y conversión al acceso mensual sin reiniciar la prueba.
- Orden y bloqueo de canales/categorías por cliente, administrados desde el panel.
- Revendedores con sesión propia, clientes separados y sin permisos de administración global.
- Una versión del panel para todos; comprobación de nuevas versiones cada minuto y aviso si se está llenando un formulario.
- Respaldo de conexión de la app con dominios y puertos configurados por el administrador. No garantiza evitar bloqueos de todas las redes o países.

## Separación respecto de la app de tu amigo

Este paquete usa código nuevo de OrionTV. No contiene la APK original de tu amigo, sus cuentas administrativas, su base de datos ni sus direcciones de activación. El identificador Android es propio; los archivos, las sesiones, las claves y la base del VPS son propios. No se ha ejecutado ninguna instalación en un servidor ajeno.

Al instalarlo usa un directorio, un dominio y un volumen de datos propios de OrionTV. Si compartes una máquina con otros servicios, primero hay que comprobar los puertos libres y añadir solo la configuración de OrionTV. Conservar el servicio existente y sus datos es parte de la instalación, no algo que la app pueda garantizar por sí sola.

## Un solo panel operativo para la app

El panel que se incluye en server/static y el servidor de server/app.py forman el sistema que utilizará la APK. Administrador y revendedores entrarán al mismo dominio, cada uno con sus permisos. Todos los dominios alternativos de activación deben llegar a esta misma base y clave persistente.

El panel privado alojado en ChatGPT continúa siendo un proyecto separado. No se ha creado una sincronización ni una migración automática de sus cuentas, clientes o contraseñas al VPS. No hay que administrar el mismo cliente en ambos suponiendo que se sincronizan. Al preparar el VPS hay que trasladar expresamente los registros necesarios y restablecer contraseñas cuando solo exista su hash. El código del panel alojado conserva su historial por separado.

## Lo siguiente

1. Identificar tu VPS de Hostinger y qué servicios utiliza, sin compartir contraseñas por el chat.
2. Elegir un dominio propio para OrionTV y revisar los puertos disponibles.
3. Instalar este servidor, crear tu administrador y cargar tus DNS y datos del proveedor.
4. Compilar la app con el dominio HTTPS real y, si existen, sus respaldos autorizados.
5. Probar en un teléfono y un televisor: reproducción, demo, vencimiento, revendedores y fallos de conexión.

La versión de código Android es 1.6. La APK de pruebas anterior es 1.5 y no incorpora estos últimos cambios. La compilación de 1.6 sigue pendiente porque no se pudo descargar Gradle en este entorno. No se ha puesto este sistema en funcionamiento en tu VPS.

## Cómo entregar el acceso a un revendedor

Una vez instalado el VPS, entra como administrador en tu dominio OrionTV. Abre Revendedores > Agregar revendedor; escribe su nombre, usuario y contraseña y guarda con Habilitado marcado. Entrega al revendedor únicamente la dirección de ese panel y sus propias credenciales. No entregues tu usuario administrador, datos de Hostinger o contraseñas del servidor.

El revendedor abre esa misma dirección e inicia sesión. El servidor reconoce su rol: puede crear y administrar sus propios clientes y sus reglas de canales, usando los DNS que el administrador ya guardó. No puede crear otros revendedores, modificar los DNS o demos globales ni consultar clientes de otras cuentas.

Para pasar un cliente existente a su cartera, edita el acceso como administrador y elige Asignar a revendedor. Si suspendes al revendedor desde Revendedores, sus sesiones dejan de funcionar; las licencias de sus clientes conservan su estado hasta que las cambies expresamente.

Este procedimiento es para el panel del VPS. El enlace privado del panel de ChatGPT no funciona como acceso por usuario y contraseña de revendedores y no se ha compartido con nadie.
