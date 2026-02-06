# Introducción

**Duración**: 45 minutos

## Motivaciones de la investigación

### Casos reales de ataques APT (Advanced Persistent Threat) en sistemas ciberfísicos.

- Aproximadamente, desde 2010, con el ataque denominado `Stuxnet`, los ataques denominados como APT y la Cyber-warfare sobre sistemas ciber-físicos son tópico de interés en Ciberseguridad.

- Existen varios otros ataques investigados y documentados, además de muchos más que se mantienen en discreción.

| Año   | Ataque                       | Objetivo o Sistema afectado                                       |
|-------|------------------------------|-------------------------------------------------------------------|
| 2010  | Stuxnet Worm                 | Sistema nuclear iraní (CPS)                                       |
| 2015  | BlackEnergy Malware          | Red eléctrica de Ucrania                                          |
| 2016  | CrashOverride Malware        | Red eléctrica de Ucrania                                          |
| 2017  | Triton Malware               | Planta petroquímica en Arabia Saudita                             |
| 2017  | NotPetya Ransomware          | Sistemas ciber-físicos de Maersk y Merck                          |
| 2021  | Oldsmar APT                  | Niveles químicos en planta de suministro de agua (EE.UU.)         |
| 2021  | Colonial Pipeline Ransomware | Oleoductos de combustible en EE.UU.                               |
| 2021  | Water Sector Attacks         | Niveles químicos en plantas de tratamiento de agua (EE.UU.)       |
| 2021  | Iranian Railway System Attack| Sistema ferroviario de Irán                                       |

### Actual enfoque de investigación sobre Sistemas de Detección de Intrusiones basados en IA

- Los IDS son sistemas diseñados para detectar ciber-ataques, incluidos los ataques APT.
- El estado del arte en sistemas IDS está basado en IA y Big Data.
- La siguiente figura describe las etapas más relevantes respecto al actual enfoque de investigación sobre nuevas propuestas o mejoras tecnológicas para sistemas IDS.

![alt text](/images/research-trends-ids-1.png)
_**Paper**: "Learn-IDS: Bridging Gaps between Datasets and Learning-Based Network Intrusion Detection"
[https://doi.org/10.3390/electronics13061072](https://doi.org/10.3390/electronics13061072)_

- Básicamente, los investigadores utilizan datasets disponibles que contienen algún tipo de datos basados en telemetría de red, de la red bajo ataque.

- Los investigadores emplean datasets públicos que contienen alguna forma de información de red donde ocurren los ataques. Luego, existe una etapa de preprocesamiento de datos crudos en la cual los diferentes datasets son acondicionados y formateados de manera uniforme para las siguientes etapas. La siguiente etapa es la Personalización de Datos, en la cual se extraen características siguiendo formatos tabulares, series temporales, arreglos o grafos. Estas características posteriormente son ingresadas al modelo de IA del IDS, donde el modelo es entrenado y evaluado.

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

- Tres hosts basados en Linux que alojan diferentes elementos de nuestra implementación de red.

| Servidor | Dirección IP Externa | Elementos alojados                                    | Red           |
|----------|----------------------|-------------------------------------------------------|---------------|
| ITM2     | 114.71.51.40         | Servidor Ubuntu 22.04 y servidor Windows 2022         |192.168.1.0/24 |
| ITM4     | 114.71.51.42         | Clientes Windows 10 y Windows 11                      |192.168.2.0/24 |
| ITMX     | 114.71.51.XX         | Recolector de eventos basado en framework Elasticsearch|192.168.3.0/24 |

- Cada servidor alojará diferentes sub-redes compuestas por máquinas virtuales, switches virtuales y routers virtuales.
- Para comunicar estas sub-redes entre sí, y para proporcionar acceso a internet a estas sub-redes, la interfaz WAN de cada router virtual debe estar en modo 'Bridge'.
- Para que el modo 'Bridge' funcione correctamente, será necesario asignar una dirección IPv4 del mismo rango de red que las direcciones IPv4 de cada host, en el rango 114.71.51.0/24.
- Otra solución puede ser configurar la interfaz WAN del router en modo 'NAT'. Sin embargo, se requiere una configuración más compleja. El modo 'Bridge' es la estrategia más simple y garantizada para proporcionar acceso a red externa a las sub-redes.
