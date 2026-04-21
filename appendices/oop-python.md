# Programación Orientada a Objetos en Python

Este apéndice introduce los conceptos básicos de **Programación Orientada a Objetos (OOP)** usando como referencia los scripts que ya conoces del curso. No es un tratado completo sobre OOP — es lo mínimo necesario para leer y entender el código con fluidez.

---

## ¿Qué es OOP?

OOP es un estilo de programación que organiza el código en torno a **objetos**. Un objeto combina dos cosas:

- **Datos** (lo que el objeto *sabe*): llamados atributos
- **Funciones** (lo que el objeto *puede hacer*): llamadas métodos

La idea central es que, en lugar de tener datos sueltos y funciones sueltas, los agrupamos en entidades coherentes. Un cliente de base de datos sabe a qué servidor conectarse y puede ejecutar consultas. Un analizador de argumentos sabe qué argumentos acepta y puede interpretarlos.

---

## Clase vs Objeto — la distinción fundamental

Una **clase** es el molde. Un **objeto** es lo que se fabrica con ese molde.

```
Clase           →    Objeto
─────────────────────────────
Plano de edificio →  Edificio construido
Receta           →   Plato preparado
Elasticsearch    →   Conexión concreta a un clúster
ArgumentParser   →   Analizador configurado para este script
datetime         →   Un instante de tiempo específico
```

En Python, las clases se identifican fácilmente porque empiezan con mayúscula: `Elasticsearch`, `ArgumentParser`, `datetime`, `Path`.

---

## Instanciación: crear un objeto a partir de una clase

**Instanciar** significa crear un objeto concreto usando una clase como plantilla. La sintaxis es `NombreClase(argumentos)`.

En `1_elastic_index_downloader.py`:

```python
# Elasticsearch es la clase (importada de la librería elasticsearch-py)
# es es el objeto — una conexión concreta configurada para nuestro clúster
es = Elasticsearch(
    hosts=["https://10.2.0.20:9200"],
    basic_auth=("elastic", "password"),
    verify_certs=False
)
```

Y más adelante en la función `main_cli()`:

```python
# ArgumentParser es la clase
# parser es el objeto — un analizador configurado para este script concreto
parser = argparse.ArgumentParser(
    description="Elasticsearch Index Downloader for Cybersecurity Data"
)
```

En ambos casos, el objeto creado (`es`, `parser`) recuerda su configuración y la usa cada vez que se le llama.

---

## Métodos: lo que un objeto puede hacer

Un **método** es una función que pertenece a un objeto. Se llama con la sintaxis `objeto.metodo(argumentos)`.

```python
# es es el objeto; ping() es un método que prueba si el servidor responde
es.ping()

# cat es un atributo de es que a su vez es un objeto;
# indices() es un método que lista los índices del clúster
es.cat.indices(format="json", h="index,store.size,creation.date")

# parser es el objeto; add_argument() registra un nuevo argumento CLI
parser.add_argument('--output-dir', help='Directorio de salida')
```

La notación punto (`.`) es la forma de acceder a lo que pertenece a un objeto: sus métodos y sus atributos.

---

## Métodos de clase vs métodos de instancia

Hay métodos que se llaman sobre un **objeto** (instancia) y métodos que se llaman directamente sobre la **clase**, sin necesidad de crear un objeto primero.

**Métodos de instancia** — requieren un objeto creado previamente:

```python
es = Elasticsearch(...)   # primero creas el objeto
es.ping()                 # luego llamas el método sobre ese objeto
```

**Métodos de clase** — se llaman directamente sobre la clase:

```python
# No necesitas crear un objeto datetime primero
dt = datetime.fromtimestamp(1706499894, tz=timezone.utc)
dt = datetime.strptime("Jan 29, 2025 @ 04:24:54.863", TIMESTAMP_FORMAT)
```

`fromtimestamp()` y `strptime()` son constructores alternativos: crean y devuelven un objeto `datetime` a partir de distintos formatos de entrada. Son la forma que tiene `datetime` de decir "dame estos datos y te devuelvo un instante de tiempo".

---

## Encadenamiento de métodos

Un método puede devolver un objeto sobre el que inmediatamente llamas otro método. Esto se llama **encadenamiento**:

```python
# strptime() devuelve un objeto datetime
# .replace() es un método de ese objeto datetime que devuelve otro datetime
return datetime.strptime(time_str, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
```

Equivale a:

```python
dt = datetime.strptime(time_str, TIMESTAMP_FORMAT)   # objeto datetime sin timezone
dt_utc = dt.replace(tzinfo=timezone.utc)             # nuevo objeto datetime con UTC
return dt_utc
```

---

## Resumen visual

```
                    ┌─────────────────────────────────────┐
                    │           Clase: Elasticsearch       │
                    │  (definida en la librería externa)   │
                    │                                     │
                    │  sabe cómo conectarse a cualquier   │
                    │  clúster de Elasticsearch           │
                    └───────────────┬─────────────────────┘
                                    │
                          instanciación: Elasticsearch(...)
                                    │
                                    ▼
                    ┌─────────────────────────────────────┐
                    │        Objeto: es                   │
                    │  (instancia concreta)               │
                    │                                     │
                    │  host: https://10.2.0.20:9200       │
                    │  user: elastic                      │
                    │                                     │
                    │  métodos:                           │
                    │    es.ping()                        │
                    │    es.cat.indices(...)              │
                    └─────────────────────────────────────┘
```

---

## Lo que necesitas recordar para este curso

| Concepto | Qué es | Ejemplo del curso |
|---|---|---|
| **Clase** | El molde / la plantilla | `Elasticsearch`, `datetime`, `ArgumentParser` |
| **Objeto** | Una instancia concreta | `es`, `parser`, un timestamp específico |
| **Instanciación** | Crear un objeto desde una clase | `es = Elasticsearch(...)` |
| **Método** | Función que pertenece a un objeto | `es.ping()`, `parser.add_argument()` |
| **Método de clase** | Función que pertenece a la clase | `datetime.fromtimestamp()` |
| **Encadenamiento** | Llamar un método sobre el resultado de otro | `.strptime(...).replace(...)` |

No necesitas saber cómo *definir* clases para seguir este curso — los scripts las usan pero no las crean desde cero. Entender cómo *usarlas* (instanciar, llamar métodos, encadenar) es suficiente para leer el código con fluidez.
