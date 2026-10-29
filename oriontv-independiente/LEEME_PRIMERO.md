# OrionTV Independiente — proyecto reunido para pruebas

Empieza por **EMPIEZA_AQUI.md** para ver qué partes están conectadas y qué queda pendiente.

Este proyecto contiene código nuevo de Android y de activación. No incluye el código de Technored, no accede a su panel y no usa sus direcciones de servidor. El logo es el que proporcionaste.

## Qué queda separado

- Aplicación Android: `com.oriontv.independent`.
- Nombre visible: **OrionTV Independiente**; puede instalarse junto a una app con identificador diferente.
- Datos del teléfono, registros, tokens, base de datos y clave de cifrado propios.
- Servidor y panel propios en la carpeta `server/`.
- El panel privado creado anteriormente en ChatGPT sigue separado. Este paquete contiene un panel para alojar en tu VPS; no migra ni sincroniza automáticamente los datos del panel anterior.
- No se modificó la APK que aportaste ni se instaló nada en Hostinger.

## Funciones incluidas

1. Registro de la nueva app con un código generado de 8 caracteres, letras y números. **No es la MAC física.**
2. Activación por ese ID o por usuario y contraseña de OrionTV. Las credenciales de activación se vinculan a un máximo configurable de 1 a 4 instalaciones.
3. DNS guardados, usuario y contraseña del proveedor por cliente, suspensión y renovaciones de 1 a 12 meses.
4. Cuenta demo compartida configurable. Al solicitarla, el servidor inicia exactamente 7,200 segundos. Consultas repetidas no cambian la hora de vencimiento.
5. Conversión del demo a acceso mensual asignando credenciales definitivas al mismo ID.
6. Catálogo Xtream de canales, películas y series, búsqueda por nombre y reproductor Media3 con HLS y DASH.
7. Validación del acceso cada 30 segundos y corte local al vencimiento según el plazo comunicado por el servidor. Si la validación falla, el acceso se detiene.
8. Panel con acceso de administrador, cookie de sesión, verificación de origen, contraseñas de activación mediante PBKDF2 y credenciales IPTV cifradas con Fernet.

## Qué falta para usarlo con clientes

- Revisar tu VPS de Hostinger y los servicios que ya usa. No ejecutar instrucciones de instalación sobre un servidor desconocido.
- Elegir un subdominio propio, configurar HTTPS y desplegar este servidor.
- Crear tu administrador y cargar tus DNS y cuentas del proveedor.
- Incorporar la URL HTTPS al compilar la app; el cliente no introduce el servidor.
- Probar instalación, mando a distancia, reproducción y vencimiento en un teléfono y TV reales. La compilación o las pruebas del servidor no sustituyen esas pruebas.
- Generar y guardar una clave de firma de producción antes de distribuir. Una APK de depuración es para pruebas, no una publicación final.

## Advertencias concretas sobre el demo

El control de 2 horas limita el acceso en esta app. **No desactiva la cuenta demo en tu proveedor**. Si todos usan una cuenta, comparten su límite de conexiones. Quien extraiga esas credenciales podría usarlas fuera de esta aplicación mientras sigan vigentes en el proveedor.

Una prueba por instalación no garantiza una prueba por dispositivo físico: borrar los datos o reinstalar genera otra instalación. Para limitar abuso de forma más estricta hacen falta controles adicionales. No se usa una MAC física ni se promete que sea imposible repetir una prueba.

La compatibilidad depende de los formatos y decodificadores del equipo. Esta versión no convierte automáticamente audio incompatible ni reproduce contenido con DRM sin una integración autorizada.

## Dispositivos

Android 6 o superior, Android TV y equipos Fire TV con Android/Fire OS. No es compatible por ser APK con Roku, televisores Samsung Tizen, LG webOS ni Fire TV con Vega OS.

## Abrir en Android Studio

Abre la carpeta `android`, selecciona JDK 17 y permite la sincronización de Gradle. Usa **Build > Generate App Bundles or APKs > Generate APKs** o el equivalente de tu versión. También puedes ejecutar `gradlew.bat assembleDebug` en Windows.

El proyecto fija AGP 8.9.2 y Gradle 8.11.1. No actualices una herramienta de forma aislada si aparece un aviso: revisaremos el mensaje concreto.

## Siguiente paso contigo

En Hostinger abre **VPS > Administrar** y revisa el sistema operativo y si ya hay otros servicios. Después se prepara la instalación para ese entorno. No necesitamos acceso al servidor ni al panel de tu amigo.

## Interfaz 1.1

La pantalla de acceso se adaptó a tu referencia: fondo negro con diagonales rojas, logo a la izquierda en pantallas anchas, formulario oscuro redondeado, usuario y contraseña, ID de activación, Entrar y demo de dos horas. En móvil se organiza verticalmente. Incluye mostrar/ocultar contraseña y foco visible para mando. La URL del servidor se configura al compilar y no se muestra un botón para cambiarla.

El campo de la llave muestra el ID que se registra en el panel; no es un código canjeable de un solo uso. Entrar usa usuario y contraseña si los completas, o consulta la activación del ID si los dejas vacíos. La conexión real sigue requiriendo tu servidor HTTPS.

## Versión 1.2 — ID automático, sin configuración visible

El código alfanumérico de 8 caracteres se crea localmente en el primer inicio, sin conexión. Puedes anotarlo y agregarlo al panel antes del registro en el servidor. Las actualizaciones conservan ese ID. Al borrar los datos o desinstalar y reinstalar, Android normalmente elimina sus preferencias y se crea otra instalación con otro ID. No es la MAC física del equipo.

Se eliminó el botón y el mensaje para configurar servidor. Para la versión conectada debes compilar con `gradlew.bat assembleDebug -PorionApiUrl=https://activar.tu-dominio.com` o definir esa propiedad en Gradle. El paquete entregado no contiene una dirección inventada: todavía necesitamos la URL real de tu servidor. El ID se muestra de inmediato, pero la activación y el demo requieren el servidor instalado y esa URL incorporada.

## Versión 1.4 — código de 8 caracteres con letras y números

Cada nueva instalación muestra un código como `AB12CD34`: cuatro letras mayúsculas y cuatro números, sin espacios ni separadores. Se genera sin internet y se conserva al cerrar y actualizar la app. Borrar sus datos o reinstalar puede generar otra instalación. Esta versión cambia el ID anterior al nuevo formato: registra en tu panel el código que muestra la APK actualizada. El servidor incluido puede migrar registros anteriores cuando la instalación conserva su secreto de registro, sin reiniciar el demo.

El servidor comprueba colisiones y no reutiliza silenciosamente el registro de otro dispositivo. El código identifica la instalación, pero sus peticiones también requieren un secreto de registro que no se muestra al usuario.

## Cantidad de dispositivos por cuenta

En modo usuario y contraseña puedes seleccionar de 1 a 4 instalaciones. El servidor vincula cada instalación al primer acceso y rechaza las que exceden el límite. Volver a entrar desde una instalación ya vinculada no consume otro lugar. El modo por código sigue siendo individual: cada instalación tiene su código. No se aumentan automáticamente las conexiones permitidas por el proveedor IPTV. La instalación del servidor en tu VPS sigue pendiente.

## Canales por cliente — versión 1.5

Todo se controla desde el panel: en Accesos pulsa Canales, importa una lista M3U o JSON Xtream y modifica orden y visibilidad. El catálogo se guarda por cliente, sin URLs de reproducción. El panel privado de ChatGPT también incorpora un editor por cliente, pero no sincroniza todavía con el VPS. La conexión y migración de sus reglas siguen pendientes.

La app recibe `channel_policy` al validar su acceso y filtra canales en vivo por ID o categoría, conservando el orden asignado. Una cuenta sin reglas sigue viendo el catálogo normal. Si se oculta un canal que se estaba viendo, la app lo detiene al recibir la siguiente validación. Esto controla la app OrionTV, no elimina los permisos de la cuenta en el proveedor. Tras importar una M3U con categorías por nombre, deben reimportarse nuevos canales para asignarles las reglas de categoría; los IDs de categoría nativos de Xtream permiten filtrar también nuevos canales de esa categoría.

El servidor incluye cuentas de administrador y revendedor. En Revendedores crea un usuario con contraseña propia; asígnale clientes al editar sus accesos. El revendedor entra en la misma dirección y solo puede administrar sus clientes. No puede cambiar DNS ni demos globales ni crear otros revendedores. Suspenderlo cierra sus sesiones; no suspende automáticamente a sus clientes. La instalación en VPS sigue pendiente.


## Actualizaciones compartidas
Todos los revendedores usan el mismo servidor y los mismos archivos del panel. Al publicar una nueva versión, sus páginas consultan la versión cada 60 segundos y recargan cuando no hay formularios pendientes. Si están editando, aparece un aviso para guardar antes de actualizar. Las actualizaciones de la APK se distribuyen aparte.

Para actualizar el VPS, respalda la base y service.key, conserva el directorio de datos persistente y reemplaza solo código/imagen del servicio OrionTV. Reinicia únicamente ese servicio. Las migraciones de esta versión agregan columnas sin borrar clientes existentes. No se ha realizado esta operación en tu servidor.


## Versión de código 1.6: respaldo de conexión
Esta entrega modifica el código fuente, no incluye una nueva APK compilada. La APK 1.5 anterior no incorpora esta función. La compilación Gradle 1.6 se intentó, pero no se pudo descargar Gradle por falta de acceso de red. Se comprobaron la política Java de direcciones/reintentos y 11 pruebas del servidor.

La activación admite un servidor principal y hasta tres URLs de respaldo HTTPS, configurados al compilar. Todos deben llegar al MISMO backend OrionTV y a la misma base de datos y clave persistente; no deben ser instalaciones con bases separadas. En Android Studio, agrega las propiedades orionApiUrl y orionApiFallbackUrls a la configuración privada de compilación, con URLs completas separadas por comas. No contiene dominios reales ni abre puertos automáticamente.

En DNS guardados del panel incluido para VPS, agrega hasta tres URLs alternativas por servicio, una por línea. Deben ofrecer el mismo catálogo, identificadores y credenciales del proveedor. Por ejemplo, el mismo servidor publicado por el proveedor en otro puerto y otro dominio. Las direcciones alternativas se entregan a los clientes autorizados, incluidas las demos. Los DNS guardados del panel web de ChatGPT todavía no se sincronizan con este servidor.

La app prueba solamente estas direcciones autorizadas ante fallos de red o HTTP 408/502/503/504. No prueba puertos al azar. Los errores de cuenta 401/403, los límites 429 y los errores de formato no provocan cambio de dirección. La validación TLS se conserva; un servicio HTTPS no cambia a HTTP como respaldo. Para una reproducción con fallo de red, intenta cada respaldo como máximo una vez y conserva la posición de películas y episodios cuando el reproductor puede recuperarla.

No es posible garantizar funcionamiento en todos los países o redes. Cambiar de puerto no arregla un bloqueo del nombre DNS o de la IP; para respaldo de dominio hace falta otro dominio operativo. Los puertos deben estar habilitados por el proveedor y el servidor, y contar con certificados válidos si son HTTPS. Aún faltan pruebas en teléfonos, TV y redes reales, así como preparar tu dominio y puertos en Hostinger. Las restricciones del proveedor de contenido y las cuentas siguen aplicando.
