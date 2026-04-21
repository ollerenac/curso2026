# Conclusiones de la Sesión 1

**Duración**: 15 minutos

## Lo que hemos recorrido

En las últimas 5 horas hemos seguido un proceso sistemático de exploración de datos, desde la extracción hasta la validación estructural de ambos dominios de telemetría. Este recorrido no fue un ejercicio académico — cada hallazgo tiene consecuencias directas para las decisiones de diseño que tomaremos en las sesiones siguientes.

```
Sesión 1: Recorrido completo

  Extracción         Exploración              Consistencia
  ──────────    ─────────────────────    ──────────────────────
  Script 1      Sysmon: XML incrustado   Sysmon: 19 patrones
  Elasticsearch   en JSON, namespaces,     = 19 EventIDs (1:1)
  → JSONL         21 EventIDs              ALTAMENTE CONSISTENTE

                NetFlow: JSON anidado    NetFlow: 15 patrones
                  puro, 96 rutas,          sin discriminador
                  process opcional         MODERADAMENTE CONSISTENTE
```

## Lo que sabemos ahora

| Decisión de diseño | Sysmon | NetFlow | Sección |
|---------------------|--------|---------|---------|
| Formato de entrada | XML incrustado en JSON | JSON anidado puro | 3, 5 |
| Discriminador de tipo | EventID (19 tipos) | No existe | 4, 6 |
| Consistencia | ALTAMENTE CONSISTENTE (1:1) | MODERADAMENTE CONSISTENTE (15 patrones) | 4, 6 |
| Estrategia del conversor | Esquema fijo por EventID | Esquema unificado con manejo de nulos | 4, 6 |
| Campos universales | 2 (`UtcTime`, `RuleName`) | 62 de 89 rutas | 4, 6 |
| Columna temporal | `UtcTime` → epoch ms → `timestamp` | `@timestamp` directo | 3 |
| Campos opcionales | Ninguno dentro de cada EventID | `process` (49.2%), `source.process` (41.2%), `destination.process` (8.0%) | 5, 6 |

## Cómo alimenta el resto del curso

Cada sesión siguiente se apoya en lo que descubrimos aquí:

**Sesión 2 — Preprocesamiento**: Los Scripts 2 y 3 implementan exactamente las dos estrategias de conversión que la exploración reveló: esquema fijo por EventID para Sysmon, esquema unificado con `get_nested_value()` para NetFlow. El Script 4 corrige violaciones de `ProcessGuid` — un campo que identificamos como presente en el 71.3% de los registros Sysmon.

**Sesión 3 — Correlación cruzada**: Los Scripts 5-6 correlacionan temporalmente Sysmon y NetFlow. Esta correlación es posible porque ahora entendemos las columnas temporales de ambos dominios (`UtcTime` → `timestamp` en Sysmon, `@timestamp` en NetFlow) y sabemos que el campo `process` de NetFlow permite vincular flujos de red con procesos del sistema operativo.

**Sesión 4 — Etiquetado**: El Script 7 extrae eventos semilla de EventIDs específicos (1, 11, 23) — tres de los 19 tipos que catalogamos en la sección 4. El Script 8 traza cadenas de ataque usando `ProcessGuid` como enlace entre eventos, aprovechando la consistencia perfecta de este campo dentro de cada EventID.

**Sesión 5 — Datasets finales**: Los Scripts 9-10 generan los datasets etiquetados finales. La estructura de estos datasets refleja directamente las decisiones de diseño que emergen de esta sesión: columnas fijas por EventID en Sysmon, esquema unificado con nulos en NetFlow.

## El principio: explorar antes de codificar

La Sesión 1 demuestra un principio fundamental del trabajo con datos: **nunca escribir código de transformación sin haber explorado y validado primero la estructura de los datos**. Un conversor diseñado sin esta exploración habría fallado silenciosamente al encontrar XML con namespaces en Sysmon, o habría ignorado la variación del campo `process` en NetFlow — produciendo datasets incompletos o incorrectos sin que el desarrollador lo supiera.

---

En la **Sesión 2** comenzamos a aplicar estas decisiones: la conversión de archivos JSONL a CSV estructurados, utilizando las estrategias de extracción que la exploración nos ha revelado.
