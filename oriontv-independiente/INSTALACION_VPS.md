# Instalación en VPS — guía para el momento del despliegue

**No ejecutar todavía en tu servidor actual.** Primero hay que revisar sistema operativo, puertos en uso, paneles existentes y copias de seguridad. Este proyecto no contiene un instalador que cambie el servidor de forma automática.

## Requisitos

Linux con Docker y Docker Compose ya instalados, un subdominio propio y un proxy HTTPS que enrute hacia `127.0.0.1:8099`. Esta guía no instala ni reemplaza Nginx, Apache, Caddy, XUI ni servicios existentes.

## Despliegue después de la revisión

1. Copiar este proyecto a un directorio nuevo, por ejemplo `/opt/oriontv-independent`.
2. Copiar `.env.example` a `.env` y establecer `PUBLIC_URL=https://activar.tu-dominio.com` con la dirección real, sin barra final.
3. Comprobar que el puerto local 8099 esté libre. Si no lo está, elegir otro puerto y ajustar el destino del proxy. No detener el proceso que ya lo utilice.
4. Desde el nuevo directorio, ejecutar `docker compose build` y después `docker compose up -d`.
5. Crear el administrador: `docker compose exec oriontv python manage.py setup`. La contraseña se introduce de forma interactiva, no se comparte en el chat ni se escribe en comandos de ejemplo.
6. Configurar el proxy existente para el nuevo subdominio y HTTPS. Solo añadir una ruta propia; no reemplazar la configuración de otro servicio.
7. Abrir la URL HTTPS, iniciar sesión y guardar un DNS y la cuenta demo. La casilla habilita las solicitudes automáticas del botón de la app.
8. Compilar la app con la URL HTTPS fija mediante `-PorionApiUrl=https://activar.tu-dominio.com`. Instalar esa APK actualizada. No habrá campo ni botón para configurar servidor. El ID se genera en el primer inicio, incluso sin internet, y se conserva cuando se registra con el servidor.
9. Solicitar un demo y comprobar que aparece en Demos con el mismo ID. Para convertirlo, pulsar Activar mensualidad, asignar los datos definitivos y elegir duración.

## Ejemplo de un bloque nuevo para Caddy ya instalado

```
activar.tu-dominio.com {
    reverse_proxy 127.0.0.1:8099
}
```

No pegar este bloque reemplazando todo el archivo existente. No iniciar un segundo proxy en 80/443 si esos puertos ya se utilizan.

## Respaldo

El volumen `oriontv_data` contiene la base de datos `orion.sqlite` y `service.key`. Ambos son necesarios para recuperar las credenciales del proveedor. Respaldar el volumen mediante una copia consistente de SQLite o deteniendo únicamente el contenedor propio de OrionTV durante la copia. No borrar `service.key` ni regenerarla con datos existentes.

## Pruebas de aceptación

- La app de tu amigo continúa instalada y funcionando sin cambios.
- La nueva app tiene identificador `com.oriontv.independent`.
- Ninguna petición de activación apunta al servidor de tu amigo.
- El demo mantiene su vencimiento tras cerrar y abrir la app.
- El demo vencido deja de obtener credenciales de `/api/access`.
- Un acceso mensual válido vuelve a funcionar al consultar acceso.
- Suspender una licencia corta las siguientes validaciones.
- Las credenciales respetan el límite elegido de 1 a 4 instalaciones; la siguiente instalación se rechaza.

La cuenta compartida del proveedor debe tener conexiones suficientes. Para un corte independiente del reproductor se necesitan cuentas demo individuales con vencimiento en el proveedor.


### Respaldos de dominio y puerto
Publica cada dominio/puerto de activación hacia la misma API de OrionTV; conserva su base y clave. Configura TLS válido para todos los nombres. El proxy del panel administrativo debe respetar PUBLIC_URL y Origin. El puerto alternativo no sirve hasta que el firewall y el proxy lo habiliten expresamente. Antes de tocar puertos, verifica qué servicios existentes los usan. Los puertos de reproducción los define tu proveedor: agregar una URL al panel no crea ese servicio.
