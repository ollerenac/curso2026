# Introducción

**Duración**: 45 minutos

## Research Motivations

### Real Cases of Advanced Persistent Threat (APT) Attacks on Cyber-Physical Systems. 

- Since 2010, with Stuxnet Worm, APTs and Cyber-warfare over Cyber-Physical Systems are a major concern on Cybersecurity.
- Plenty of number of known examples to describe a critical situation. And there are more that remain non-disclosed.

| Year  | Attack Name                | Target/System Affected                                    |
|-------|----------------------------|-----------------------------------------------------------|
| 2010  | Stuxnet Worm               | Iranian Nuclear CPS                                       |
| 2015  | BlackEnergy Malware        | Ukrainian Power Grid                                      |
| 2016  | CrashOverride Malware      | Ukrainian Power Grid                                      |
| 2017  | Triton Malware             | Petrochemical plant in Saudi Arabia                       |
| 2017  | NotPetya Ransomware        | Cyber-physical systems of Maersk and Merck                |
| 2021  | Oldsmar APT                | Chemical levels in the water plant supply (US)            |
| 2021  | Colonial Pipeline Ransomware | Fuel pipelines in the US                                |
| 2021  | Water Sector Attacks       | Chemical levels in water treatment facilities (US)        |
| 2021  | Iranian Railway System Attack | Iran's railway system                                  |

### So, how is the research towards Intrusion Detection Systems?

- Intrusion Detection Systems, or IDS in short, are systems design to detect cyber-attacks, **including APTs**.
- State-of-the-art IDS are, of course, AI & Big Data-driven.
- The following picture is modified from the original to describe the most relevant stages regarding how researchers propose or improve new technologies for IDS. We just added dotted-line-boxes and add some labels for a better depiction of the stages.

![alt text](/images/research-trends-ids-1.png)
_**Paper**: "Learn-IDS: Bridging Gaps between Datasets and Learning-Based Network Intrusion Detection"
[https://doi.org/10.3390/electronics13061072](https://doi.org/10.3390/electronics13061072)_

- Basically, researchers employ public datasets containing some form of network information where attacks happen. Then, there is a raw-data pre-processing stage in which the different datasets are conditioned and uniformly formatted for the next stages. Next stage is Data Customizing in which features are extracted following a tabular, time-series, array, or graph formats. These features subsequently are input into the IDS AI-model in which the model is trained and evaluated.

- So, continuing with the following picture, as easy to deduce, researchers efforts are targeting new technologies and algorithms for the Pre-processing stage and the Model-related stages.
    - Novel data-pipeline techniques are being proposed in the pre-processing stage.
    - Novel feature selection methods, novel deep-learning and/or deep-reinforcement-learning models, and novel optimization techniques are being proposed for the modelling stage.

![alt text](/images/research-trends-ids-2.png)
_**Paper**: "Learn-IDS: Bridging Gaps between Datasets and Learning-Based Network Intrusion Detection"
[https://doi.org/10.3390/electronics13061072](https://doi.org/10.3390/electronics13061072)_

<!-- - However, **researchers are still relying on datasets which:** 
    - Most of the time only considers **one type of data (network traffic, pcap)** 
    - Most of the attacks are **isolated attacks**, meaning that there is not strong correlation between them. Unlike ATP attacks, in which each action in the target system or network is meaningful.
    - These datasets need Labeling, which is time and effort consuming.
    - And most of the real APT attack datasets are Not available because of the non-disclose politics of the affected organization. -->

## Problem Statement

- However, despite advancements in intrusion detection systems, researchers continue to face significant challenges due to limitations in the datasets being used:

    - **Most existing datasets focus on a single data type**, such as network traffic or PCAP files, which limits the comprehensiveness of the analysis.
    - **Attacks within these datasets are often isolated**, lacking the complex, multi-stage correlations found in Advanced Persistent Threat (APT) attacks. In APTs, every action across the network or system carries a strategic significance, unlike in isolated attack scenarios.
    - **Dataset labeling remains a time-consuming and labor-intensive process**, requiring extensive manual effort to ensure accuracy.
    + **Real-world APT datasets are generally unavailable due to non-disclosure policies** enforced by affected organizations, making it difficult to develop solutions based on real, high-impact incidents.

![alt text](/images/research-trends-ids-3.png)
_**Paper**: "Learn-IDS: Bridging Gaps between Datasets and Learning-Based Network Intrusion Detection"
[https://doi.org/10.3390/electronics13061072](https://doi.org/10.3390/electronics13061072)_

## What is our proposed solution?

- **Create our own dataset** by **performing our own complex APT attacks** over **our own virtual network**, first, over an mini-network and, later, over a more complex and more scaled network.

### Virtual network implementation.


![alt text](/images/infrastructure.png)

**Description**

- Three Linux-based hosts hosting different elements of our network implementation.

| Server | External IP Address | Elements being hosted                                 | Network       |
|--------|---------------------|-------------------------------------------------------|---------------|
| ITM2   | 114.71.51.40        | Ubuntu 22.04 server & Windows 2022 server             |192.168.1.0/24 |
| ITM4   | 114.71.51.42        | Windows 10 & Windows 11 clients                       |192.168.2.0/24 |
| ITMX   | 114.71.51.XX        | Event-data collector based on Elasticsearch framework |192.168.3.0/24 |


- Each server will host different sub-networks composed by virtual machines, virtual switches, and virtual routers. 
- To communicate these sub-networks between each other, and to provide internet access to these sub-networks, each of the virtual routers' WAN interface should be in 'Bridge' mode. 
- For the 'Bridge' mode to work properly, it will be necessary to assign an IPv4 address from the same network range as the IPv4 addresses of each host, in the range 114.71.51.0/24.
- Another solution can be to set the router's WAN interface in 'NAT' mode. However, more complex configuration is needed. 'Bridge' mode is the simplest guaranteed strategy to provide external-network access to the sub-networks.