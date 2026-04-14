# Introducción

**Duración**: 45 minutos

## Motivaciones de la investigación

### Casos reales de ataques APT (Advanced Persistent Threat) en sistemas ciberfísicos.

- Aproximadamente, desde 2010, con el ataque denominado `Stuxnet`, los ataques denominados como APT y la Cyber-warfare sobre sistemas ciber-físicos son tópico de interés en Ciberseguridad.

- Existen varios otros ataques investigados y documentados, además de muchos más que se mantienen en discreción.

| Año   | Ataque                       | Objetivo o Sistema afectado                                       |
|-------|------------------------------|-------------------------------------------------------------------|
| 2010  | [Stuxnet Worm](https://ieeexplore.ieee.org/document/6120048)                 | Sistema nuclear iraní (CPS)                                       |
| 2015  | [BlackEnergy Malware](https://attack.mitre.org/software/S0089/)          | Red eléctrica de Ucrania                                          |
| 2016  | [CrashOverride Malware](https://www.cisa.gov/news-events/alerts/2017/06/12/crashoverride-malware)        | Red eléctrica de Ucrania                                          |
| 2017  | [Triton Malware](https://www.cyberark.com/resources/threat-research-blog/anatomy-of-the-triton-malware-attack)               | Planta petroquímica en Arabia Saudita                             |
| 2017  | [NotPetya Ransomware](https://gvnshtn.com/posts/maersk-me-notpetya/)          | Sistemas ciber-físicos de Maersk y Merck                          |
| 2021  | [Oldsmar APT](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-042a)                  | Niveles químicos en planta de suministro de agua (EE.UU.)         |
| 2021  | [Colonial Pipeline Ransomware](https://www.cisa.gov/news-events/news/attack-colonial-pipeline-what-weve-learned-what-weve-done-over-past-two-years) | Oleoductos de combustible en EE.UU.                               |
| 2021  | Water Sector Attacks         | Niveles químicos en plantas de tratamiento de agua (EE.UU.)       |
| 2021  | [Iranian Railway System Attack](https://www.youtube.com/watch?v=MsuCC50UMlc)| Sistema ferroviario de Irán                                       |

**Puntos clave:**
- Los ataques APT reales a sistemas ciberfísicos demuestran que las amenazas son **multi-etapa** y **multi-dominio**: afectan tanto la red como los procesos del sistema operativo simultáneamente.
- La mayoría de estos ataques fueron detectados *después* de causar daño, lo que subraya la necesidad de sistemas IDS más avanzados.
- Para entrenar IDS efectivos, necesitamos datasets que capturen esta complejidad dual (host + red), no solo un tipo de telemetría.

### Actual enfoque de investigación sobre Sistemas de Detección de Intrusiones basados en IA

- Los IDS son sistemas diseñados para detectar ciber-ataques, incluidos los ataques APT.
- El estado del arte en sistemas IDS está basado en IA y Big Data.
- La siguiente figura describe las etapas más relevantes respecto al actual enfoque de investigación sobre nuevas propuestas o mejoras tecnológicas para sistemas IDS.

![alt text](/images/research-trends-ids-1.png)
_**Paper**: "Learn-IDS: Bridging Gaps between Datasets and Learning-Based Network Intrusion Detection"
[https://doi.org/10.3390/electronics13061072](https://doi.org/10.3390/electronics13061072)_

- Básicamente, los investigadores utilizan datasets disponibles que contienen algún tipo de datos basados en telemetría de red, de la red bajo ataque.

- Los investigadores emplean datasets públicos que contienen alguna forma de información de red donde ocurren los ataques. Luego, existe una etapa de preprocesamiento de raw data en la cual los diferentes datasets son acondicionados y formateados de manera uniforme para las siguientes etapas. La siguiente etapa es la Personalización de Datos, en la cual se extraen características siguiendo formatos tabulares, series temporales, arreglos o grafos. Estas características posteriormente son ingresadas al modelo de IA del IDS, donde el modelo es entrenado y evaluado.

- Continuando con la siguiente figura, como es fácil deducir, los esfuerzos de los investigadores se enfocan en nuevas tecnologías y algoritmos para la etapa de Preprocesamiento y las etapas relacionadas con el Modelo.
- Se están proponiendo técnicas novedosas de pipeline de datos en la etapa de preprocesamiento.
- Se están proponiendo métodos novedosos de selección de características, modelos novedosos de deep-learning y/o deep-reinforcement-learning, y técnicas novedosas de optimización para la etapa de modelado.

![alt text](/images/research-trends-ids-2.png)
_**Paper**: "Learn-IDS: Bridging Gaps between Datasets and Learning-Based Network Intrusion Detection"
[https://doi.org/10.3390/electronics13061072](https://doi.org/10.3390/electronics13061072)_

## Planteamiento del Problema

- Sin embargo, a pesar de los avances en sistemas de detección de intrusiones, los investigadores continúan enfrentando desafíos significativos debido a las limitaciones de los datasets utilizados:

    - **La mayoría de los datasets existentes se enfocan en un solo tipo de datos**, como tráfico de red o archivos PCAP, lo que limita la exhaustividad del análisis.
    - **Los ataques dentro de estos datasets frecuentemente están aislados**, careciendo de las correlaciones complejas y multi-etapa encontradas en los ataques de Amenazas Persistentes Avanzadas (APT). En los APTs, cada acción a través de la red o sistema tiene una significancia estratégica, a diferencia de los escenarios de ataques aislados.
    - **El etiquetado de datasets sigue siendo un proceso que consume mucho tiempo y requiere trabajo intensivo**, necesitando un esfuerzo manual extenso para asegurar la precisión.
    - **Los datasets de APT del mundo real generalmente no están disponibles debido a políticas de no divulgación** aplicadas por las organizaciones afectadas, dificultando el desarrollo de soluciones basadas en incidentes reales de alto impacto.

![alt text](/images/research-trends-ids-3.png)
_**Paper**: "Learn-IDS: Bridging Gaps between Datasets and Learning-Based Network Intrusion Detection"
[https://doi.org/10.3390/electronics13061072](https://doi.org/10.3390/electronics13061072)_

## ¿Cuál es nuestra solución propuesta?

- **Crear nuestro propio dataset** mediante la **ejecución de nuestros propios ataques APT complejos** sobre **nuestra propia red virtual**, primero, sobre una mini-red y, posteriormente, sobre una red más compleja y de mayor escala.

### Implementación de la red virtual

![alt text](/images/infrastructure.png)

**Descripción**

| Rol | Elemento de Red | Dirección IP | RAM (GB) | CPU | Disco (GB) | Sistema Operativo |
|-----|----------------|-------------|----------|-----|------------|-------------------|
| **Atacante** | Workstation | 192.168.0.5 | 2 | 2 | 30 | Kali Linux 2025 |
| | C2 Server | 192.168.0.4 | 2 | 2 | 30 | Ubuntu 22.04 |
| **Red Objetivo** | DC (Domain Controller) | 10.1.0.4 | 4 | 2 | 50 | Windows Server Datacenter 2019 (v17763) |
| | DDBB (Base de Datos) | 10.1.0.7 | 4 | 2 | 80 | Windows Server Datacenter 2019 (v17763) |
| | EWS (Email & Web Server) | 10.1.0.6 | 8 | 4 | 80 | Windows Server Datacenter 2019 (v17763) |
| | Workstation 1 | 10.1.0.5 | 6 | 4 | 100 | Windows 10 Pro (v17763) |
| | Workstation 2 | 10.1.0.8 | 6 | 4 | 100 | Windows 10 Pro (v17763) |
| **Event Collector** | Elasticsearch Server | 10.2.0.20 | 8 | 4 | 125 | Ubuntu 22.04 |
| **Router** | Firewall/Router | 192.168.0.1 / 10.1.0.1 / 10.2.0.1 | 1 | 1 | 20 | OPNSense v12 |

**Puntos clave:**
- La solución propuesta aborda las 4 limitaciones identificadas: (1) datos dual-domain (Sysmon + NetFlow), (2) ataques APT multi-etapa reales, (3) un pipeline de etiquetado estructurado, y (4) un dataset propio sin restricciones de divulgación.
- La infraestructura virtual permite repetir experimentos con diferentes campañas APT de forma controlada y reproducible.
- Los sensores Sysmon capturan actividad a nivel de proceso (creación, acceso a archivos, registro), mientras que NetFlow captura flujos de tráfico de red — juntos proporcionan visibilidad completa.

### Dominios de telemetría: Sysmon y NetFlow

Nuestra infraestructura recolecta datos desde dos **dominios de telemetría** complementarios. Cada dominio observa la actividad del sistema desde una perspectiva diferente:

| Dominio | Fuente | Qué observa | Ejemplos de eventos |
|---------|--------|-------------|---------------------|
| **Host** | Sysmon (System Monitor) | Actividad interna de cada máquina: procesos, archivos, registro, conexiones | Creación de proceso (`cmd.exe`), acceso a archivo, modificación de registro, conexión de red saliente |
| **Red** | NetFlow | Tráfico de red entre máquinas: flujos de comunicación | Flujo TCP de 10.1.0.5 → 192.168.0.4 (puerto 443), volumen de datos transferido, duración de la conexión |

- **Sysmon** es un servicio de Windows (parte de Sysinternals) que se instala en cada host de la red objetivo. Registra eventos detallados del sistema operativo: qué procesos se crean, qué archivos se modifican, qué conexiones de red inicia cada proceso. Cada evento se identifica con un **EventID** (por ejemplo, EventID 1 = creación de proceso, EventID 3 = conexión de red).

- **NetFlow** es un protocolo de monitoreo de red que registra los **flujos de tráfico** que pasan por el router. Un flujo es un resumen de una comunicación entre dos endpoints: IPs de origen y destino, puertos, protocolo, bytes transferidos y duración. A diferencia de una captura de paquetes (PCAP), NetFlow no registra el contenido de los paquetes, sino los metadatos del flujo.

La combinación de ambos dominios es lo que hace a este dataset **dual-domain**: Sysmon nos dice *qué ocurre dentro de cada máquina*, y NetFlow nos dice *cómo se comunican las máquinas entre sí*. Un ataque APT deja huellas en ambos dominios simultáneamente.

## Actividad Práctica

### Ejercicio: Reflexión sobre el Diseño del Dataset

Responde las siguientes preguntas basándote en el contexto presentado:

1. **De las 4 limitaciones identificadas en los datasets existentes**, ¿cuál consideras la más crítica para la investigación en IDS y por qué? Piensa en cómo cada limitación afecta la capacidad de entrenar modelos de detección.

2. **Observando la tabla de infraestructura virtual**, identifica al menos 3 superficies de ataque que un adversario podría explotar. Considera: servicios expuestos, comunicación entre subredes, y puntos de recolección de datos.

3. **Si un atacante ejecuta un script malicioso en un cliente Windows 10 (ITM4) que se conecta a un servidor C2 externo**, ¿qué información capturaría un sensor Sysmon vs un sensor NetFlow? ¿Qué información solo estaría disponible combinando ambos dominios?

### Resultado esperado

Al finalizar esta sección, deberías comprender:
- La motivación detrás de la creación de un dataset dual-domain propio.
- Las limitaciones de los datasets existentes que este proyecto busca superar.
- La arquitectura de red virtual donde se ejecutan las campañas APT.
- Por qué la combinación de Sysmon y NetFlow proporciona una visión más completa que cualquier dominio por separado.

En la siguiente sección, veremos cómo **extraer los raw data** desde el clúster Elasticsearch donde se almacenan las dos fuentes de telemetría.
