# PrivTrace

[Read in English](README.md)

PrivTrace es un analizador de solo lectura para rutas de escalada de privilegios en Windows. Correlaciona el token actual, privilegios, grupos, servicios, tareas programadas, rutas de ejecutables y permisos efectivos para identificar condiciones de seguridad accionables.

Un resultado `CONFIRMADO` significa que se observaron las condiciones requeridas por la regla. **No** significa que se haya realizado una explotacion o ejecucion privilegiada.

## Como funciona

PrivTrace recopila evidencia de solo lectura mediante APIs de Windows, incluyendo el token actual, servicios, tareas programadas, procesos, rutas de ejecutables y permisos efectivos.

Correlaciona esa evidencia con su catalogo de reglas para identificar condiciones de escalada de privilegios. La salida predeterminada muestra hallazgos accionables, mientras que `--verbose` y JSON conservan el contexto de diagnostico completo.

PrivTrace no intenta explotar los hallazgos ni modifica el sistema analizado.

## Descarga

Descargue el ejecutable x64 o x86 mas reciente desde [GitHub Releases](https://github.com/y0naldez/PrivTrace/releases/latest).

- Use **x64** en la mayoria de sistemas Windows modernos.
- Use **x86** solamente cuando necesite un ejecutable de 32 bits.
- Compare el archivo descargado con `PrivTrace-v1.1.0-SHA256.txt` incluido en el mismo Release.

PrivTrace se distribuye como un unico ejecutable. No necesita instalacion ni paquetes de terceros.

Verifique un ejecutable descargado desde el directorio que contiene los archivos del lanzamiento:

```powershell
Get-FileHash .\PrivTrace-v1.1.0-win-x64.exe -Algorithm SHA256
Get-Content .\PrivTrace-v1.1.0-SHA256.txt
```

El hash calculado debe coincidir exactamente con la linea de la arquitectura elegida.

## Inicio rapido

Ejecute el analisis resumido predeterminado:

```powershell
.\PrivTrace.exe
```

Ejecute la salida de consola en espanol:

```powershell
.\PrivTrace.exe -es
```

Exporte un informe JSON estructurado:

```powershell
.\PrivTrace.exe --json informe.json
```

## Opciones principales

| Opcion | Uso |
| --- | --- |
| `-es`, `--es` | Mostrar la salida natural en espanol. |
| `--verbose` | Incluir estados desconocidos, descartados y diagnosticos. |
| `--processes` | Mostrar procesos observados y servicios asociados. |
| `--binaries` | Mostrar rutas de ejecucion y permisos efectivos. |
| `--json <archivo>` | Exportar el informe estructurado completo. |
| `--rule <PT-xxx>` | Evaluar una regla. |
| `--rule-info <PT-xxx>` | Mostrar informacion sobre una regla. |
| `--category <nombre>` | Filtrar reglas por categoria. |
| `--list-rules` | Mostrar todas las reglas disponibles. |
| `--help` | Mostrar la ayuda de linea de comandos. |

Puede combinar opciones:

```powershell
.\PrivTrace.exe -es --verbose --json informe.json
```

## Software de terceros y contexto de versiones

PrivTrace tambien inventaria software de terceros seleccionado que puede ser relevante durante una evaluacion de escalada local de privilegios. Correlaciona procesos en ejecucion, rutas de instalacion, metadatos PE, servicios de Windows y el catalogo embebido de perfiles de software. Cuando existe una fuente local autorizada, muestra la version observada del producto y su procedencia.

Las fuentes de version pueden incluir:

- Metadatos de version de producto o archivo PE del ejecutable observado.
- El registro de desinstalacion de Windows para una instalacion corroborada.
- Metadatos locales especificos del producto, como `properties.ini` de XAMPP.

Un resultado resumido representativo puede verse asi:

```text
SOFTWARE DE INTERES

[1] Apache HTTP Server / XAMPP
    Proceso    : C:\xampp\apache\bin\httpd.exe
    Servicio   : Apache2.4
    Version    : 8.3.4-0
    Fuente     : XAMPP_PROPERTIES_INI
    Escalada   : PT-013, PT-016
```

Esta informacion ayuda a priorizar la investigacion. Por ejemplo, PrivTrace puede mostrar que una aplicacion de terceros esta activa, identificar el servicio y ejecutable relacionados, informar una version observada localmente y correlacionar rutas escribibles o permisos debiles del servicio con reglas PT existentes.

Ejemplos de interpretacion:

- `TeamViewer 15.x` con `Escalada: NO VERIFICADA` es solamente contexto de inventario; la version no implica una vulnerabilidad.
- `XAMPP 8.x` con `PT-013` significa que PrivTrace correlaciono el ejecutable del servicio con acceso efectivo de escritura y una identidad privilegiada. No significa que el ejecutable fuera modificado o ejecutado.
- Un producto con `Version: DESCONOCIDA` todavia puede producir un hallazgo de permisos, porque la evidencia de ACL y servicios es independiente del descubrimiento de version.

El nombre o la version del software por si solos nunca generan un hallazgo de escalada. PrivTrace no supone que una version antigua sea vulnerable, no relaciona versiones con CVE y no consulta bases de vulnerabilidades en linea. Si no puede verificar la identidad del producto o la procedencia de su version, muestra `DESCONOCIDA` en lugar de adivinar. Use `--verbose` o JSON para revisar la confianza de identificacion, fuente de version, firma, rutas, PID, servicios y condiciones pendientes.

## Salida en espanol

La proyeccion `-es` utiliza solamente texto ASCII para conservar la legibilidad en consolas antiguas de Windows y en salidas redirigidas.

```text
[ALTA] Servicio: KiteService
    Cuenta de ejecucion       : LocalSystem
    Puede iniciar el servicio? : SI (confirmado)
    Puede detener el servicio? : SI (confirmado)
    Puede escribir el binario? : SI (confirmado)
    Puede reemplazarlo?        : SI (confirmado)
    Se probo la ejecucion?     : NO; la ejecucion privilegiada sigue siendo condicional
    Proteccion en ejecucion    : REVISAR MANUALMENTE (no evaluada)
```

La bandera de idioma modifica solamente la presentacion de consola. Los identificadores de reglas, la logica de deteccion, las propiedades JSON y los valores destinados a procesamiento automatico permanecen estables.

## Interpretacion de resultados

| Estado | Significado |
| --- | --- |
| `CONFIRMADO` | Se observaron todas las condiciones requeridas por la regla. |
| `POTENCIAL` | Existe evidencia positiva, pero faltan condiciones por verificar. |
| `INFORMATIVO` | Contexto relevante sin afirmar una ruta accionable. |
| `DESCARTADO` | Se demostro que una condicion requerida es falsa. |
| `DESCONOCIDO` | La evidencia no estaba disponible, fue denegada o quedo incompleta. |

La severidad representa el impacto posible. La confianza representa la calidad de la evidencia. `EJECUCION CONDICIONAL` significa que PrivTrace detecto una ruta de permisos o configuracion, pero no modifico, reinicio ni ejecuto el objetivo.

Para hallazgos de servicios:

- `FILE_WRITE_DATA` significa que el usuario actual puede modificar el contenido del ejecutable existente.
- `FILE_REPLACEMENT` significa que los permisos observados permiten reemplazar el ejecutable.
- `Puede iniciar el servicio?: SI` confirma que el usuario actual puede iniciarlo.
- La proteccion en ejecucion permanece desconocida si no fue evaluada de forma independiente.

## Seguridad y limitaciones

PrivTrace no detiene ni inicia servicios, no ejecuta tareas, no reemplaza archivos, no cambia ACL o valores del registro, no extrae secretos, no descarga reglas y no envia telemetria.

No necesita privilegios administrativos. Si Windows niega acceso a evidencia, PrivTrace conserva el resultado como `DESCONOCIDO` en lugar de asumir que la condicion es segura o vulnerable.

Use PrivTrace solamente en sistemas propios o para los que tenga autorizacion de evaluacion.

## Requisitos

- Windows.
- .NET Framework 4.0 o un runtime instalado compatible.
- No se requiere conexion de red ni privilegios administrativos para iniciar PrivTrace.
