# Event Data Collection

- Elasticsearch server deploys elastic-agents into each of the servers or workstations in the Target Network
- The elastic-agents use the event-data collection capabilities from software artifacts such as sysmon for host telemetry collection and npcap for network flow (netflow) telemetry collection
- Elasticsearch server processes the sysmon and npcap datastreams from each server or workstation and create unique sysmon and netflow indexes
- Each sysmon and netflow index contains structured information of host events and netflow events, respectively
- Following, the tables and description of the information fields that we use for building the corresponding dataset:
  - [Sysmon Events](#sysmon-events-and-fields-per-event)
  - [Netflow Events](#netflow-event-fields)

## Sysmon Events and Fields per Event

| Event ID | Event Type | Event meaning | Key Fields Collected |
|----------|------------|-------------|--------|
| 1 | Process Creation | Logs when a new process is started, capturing command line, parent process, and execution details | [EventID](#eventid), [Computer](#computer), [ProcessGuid](#processguid), [ProcessId](#processid), [Image](#image), [User](#user), [CommandLine](#commandline), [CurrentDirectory](#currentdirectory), [ParentProcessGuid](#parentprocessguid), [ParentProcessId](#parentprocessid), [ParentImage](#parentimage), [ParentCommandLine](#parentcommandline), [Hashes](#hashes), [timestamp](#timestamp) |
| 2 | File Creation Time | Detects when a process modifies a file's creation timestamp, often used by attackers to hide malicious files | [EventID](#eventid), [Computer](#computer), [ProcessGuid](#processguid), [ProcessId](#processid), [Image](#image), [TargetFilename](#targetfilename), [CreationUtcTime](#creationutctime), [PreviousCreationUtcTime](#previouscreationutctime), [User](#user), [timestamp](#timestamp) |
| 3 | Network Connection | Records TCP/UDP connections initiated by a process, including source/destination IPs and ports | [EventID](#eventid), [Computer](#computer), [ProcessGuid](#processguid), [ProcessId](#processid), [Image](#image), [User](#user), [Protocol](#protocol), [SourceIsIpv6](#sourceisipv6), [SourceIp](#sourceip), [SourceHostname](#sourcehostname), [SourcePort](#sourceport), [SourcePortName](#sourceportname), [DestinationIsIpv6](#destinationisipv6), [DestinationIp](#destinationip), [DestinationHostname](#destinationhostname), [DestinationPort](#destinationport), [DestinationPortName](#destinationportname), [timestamp](#timestamp) |
| 4 | Sysmon State Changed | Indicates Sysmon service status changes (started, stopped, or configuration updated) | [EventID](#eventid), [Computer](#computer), [timestamp](#timestamp) |
| 5 | Process Terminated | Logs when a process ends, useful for tracking process lifecycle | [EventID](#eventid), [Computer](#computer), [ProcessGuid](#processguid), [ProcessId](#processid), [Image](#image), [User](#user), [timestamp](#timestamp) |
| 6 | Driver Loaded | Records kernel drivers loaded into the system, critical for detecting rootkits | [EventID](#eventid), [Computer](#computer), [ImageLoaded](#imageloaded), [Hashes](#hashes), [User](#user), [timestamp](#timestamp) |
| 7 | Image Loaded | Logs DLLs and modules loaded by processes, useful for detecting DLL injection/hijacking | [EventID](#eventid), [Computer](#computer), [ProcessGuid](#processguid), [ProcessId](#processid), [Image](#image), [ImageLoaded](#imageloaded), [OriginalFileName](#originalfilename), [Hashes](#hashes), [User](#user), [timestamp](#timestamp) |
| 8 | CreateRemoteThread | Detects when a process creates a thread in another process, common in code injection attacks | [EventID](#eventid), [Computer](#computer), [SourceProcessGUID](#sourceprocessguid), [SourceProcessId](#sourceprocessid), [SourceImage](#sourceimage), [TargetProcessGUID](#targetprocessguid), [TargetProcessId](#targetprocessid), [TargetImage](#targetimage), [NewThreadId](#newthreadid), [SourceUser](#sourceuser), [TargetUser](#targetuser), [timestamp](#timestamp) |
| 9 | RawAccessRead | Logs direct disk read operations bypassing the filesystem, used in credential dumping | [EventID](#eventid), [Computer](#computer), [ProcessGuid](#processguid), [ProcessId](#processid), [Image](#image), [Device](#device), [User](#user), [timestamp](#timestamp) |
| 10 | ProcessAccess | Records when a process opens another process, indicating potential memory reading or injection | [EventID](#eventid), [Computer](#computer), [SourceProcessGUID](#sourceprocessguid), [SourceProcessId](#sourceprocessid), [SourceImage](#sourceimage), [TargetProcessGUID](#targetprocessguid), [TargetProcessId](#targetprocessid), [TargetImage](#targetimage), [SourceThreadId](#sourcethreadid), [SourceUser](#sourceuser), [TargetUser](#targetuser), [timestamp](#timestamp) |
| 11 | FileCreate | Logs file creation events with path and creating process information | [EventID](#eventid), [Computer](#computer), [ProcessGuid](#processguid), [ProcessId](#processid), [Image](#image), [TargetFilename](#targetfilename), [CreationUtcTime](#creationutctime), [User](#user), [timestamp](#timestamp) |
| 12 | Registry Key/Value Created or Deleted | Records registry key and value creation or deletion operations | [EventID](#eventid), [Computer](#computer), [EventType](#eventtype), [ProcessGuid](#processguid), [ProcessId](#processid), [Image](#image), [TargetObject](#targetobject), [User](#user), [timestamp](#timestamp) |
| 13 | Registry Value Set | Logs when a registry value is modified, tracking persistence mechanisms | [EventID](#eventid), [Computer](#computer), [EventType](#eventtype), [ProcessGuid](#processguid), [ProcessId](#processid), [Image](#image), [TargetObject](#targetobject), [User](#user), [timestamp](#timestamp) |
| 14 | RegistryEvent (Key and Value Rename) |  |  |
| 15 | FileCreateStreamHash | Logs creation of alternate data streams (ADS), often used to hide malicious content | [EventID](#eventid), [Computer](#computer), [ProcessGuid](#processguid), [ProcessId](#processid), [Image](#image), [TargetFilename](#targetfilename), [Hash](#hash), [User](#user), [timestamp](#timestamp) |
| 17 | Named Pipe Created | Logs named pipe creation, used for inter-process communication and C2 channels | [EventID](#eventid), [Computer](#computer), [ProcessGuid](#processguid), [ProcessId](#processid), [PipeName](#pipename), [Image](#image), [User](#user), [timestamp](#timestamp) |
| 18 | Named Pipe Connected | Records when a process connects to a named pipe | [EventID](#eventid), [Computer](#computer), [ProcessGuid](#processguid), [ProcessId](#processid), [PipeName](#pipename), [Image](#image), [User](#user), [timestamp](#timestamp) |
| 23 | FileDelete | Logs file deletion with hash of deleted content for forensic analysis | [EventID](#eventid), [Computer](#computer), [ProcessGuid](#processguid), [ProcessId](#processid), [User](#user), [Image](#image), [TargetFilename](#targetfilename), [Hashes](#hashes), [timestamp](#timestamp) |
| 24 | ClipboardChange | Detects clipboard content changes, relevant for data theft detection | [EventID](#eventid), [Computer](#computer), [ProcessGuid](#processguid), [ProcessId](#processid), [Image](#image), [User](#user), [timestamp](#timestamp) |
| 25 | ProcessTampering | Detects process hollowing or process herpaderping evasion techniques | [EventID](#eventid), [Computer](#computer), [ProcessGuid](#processguid), [ProcessId](#processid), [Image](#image), [User](#user), [timestamp](#timestamp) |
| 255 | Error | Indicates Sysmon encountered an error during event generation | [EventID](#eventid), [Computer](#computer), [timestamp](#timestamp) |

Sysmon event definitions are reference to the [Microsoft documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)


### Sysmon Events Fields

This section provides detailed definitions for each field that appears in the Sysmon events table above. Fields are organized alphabetically for easy reference.

#### CommandLine
**Type:** String

**Description:** The full command-line arguments passed to a process when it was executed, including the executable path and all parameters.

**Populated in:** Event ID 1 (Process Creation)

**Technical Details:** This field captures the complete command line as it appears in the process creation call, making it essential for detecting malicious command patterns, obfuscation techniques, and suspicious script execution. Maximum length can vary by system but typically supports up to 32,767 characters in modern Windows systems.

#### Computer
**Type:** String

**Description:** The hostname or NetBIOS name of the computer where the event was generated.

**Populated in:** All Sysmon events

**Technical Details:** This field identifies the source system for the event. It's critical for multi-host analysis and correlation, helping to track lateral movement and identify which systems are affected during an incident. The value is typically the Windows computer name as configured in system properties.

#### CreationUtcTime
**Type:** Timestamp (UTC)

**Description:** The timestamp when a file was created or when a file creation operation occurred.

**Populated in:** Event ID 2 (File Creation Time), Event ID 11 (FileCreate)

**Technical Details:** Stored in ISO 8601 format (YYYY-MM-DD HH:MM:SS.mmm). For Event ID 2, this represents the new creation time after modification. For Event ID 11, it shows when the file was originally created. Useful for establishing file timeline and detecting timestamp manipulation.

#### CurrentDirectory
**Type:** String

**Description:** The working directory from which the process was launched.

**Populated in:** Event ID 1 (Process Creation)

**Technical Details:** Represents the current working directory (CWD) at the time of process creation. This can reveal execution context and help identify processes launched from unusual locations (e.g., temp directories, user profile paths). Important for detecting malware that executes from temporary or non-standard directories.

#### DestinationHostname
**Type:** String

**Description:** The DNS hostname of the remote system being connected to.

**Populated in:** Event ID 3 (Network Connection)

**Technical Details:** Resolved hostname of the destination IP address. May be empty if DNS resolution fails or is not available. Particularly useful for detecting connections to known malicious domains or suspicious DNS patterns. Can help identify C2 communications even when IP addresses change.

#### DestinationIp
**Type:** String (IP Address)

**Description:** The IP address of the remote endpoint in a network connection.

**Populated in:** Event ID 3 (Network Connection)

**Technical Details:** Can be either IPv4 (dotted decimal notation) or IPv6 (colon-hexadecimal notation) format. Represents the target of an outbound connection or the remote peer in a connection. Critical for network traffic analysis and threat intelligence correlation.

#### DestinationIsIpv6
**Type:** Boolean

**Description:** Indicates whether the destination IP address is IPv6 format.

**Populated in:** Event ID 3 (Network Connection)

**Technical Details:** Returns true if the destination address is IPv6, false for IPv4. Helps in properly parsing and categorizing network traffic, as IPv6 addresses require different processing and analysis techniques.

#### DestinationPort
**Type:** Integer

**Description:** The TCP or UDP port number on the remote system being connected to.

**Populated in:** Event ID 3 (Network Connection)

**Technical Details:** Valid port numbers range from 0 to 65535. Well-known ports (0-1023) typically indicate standard services, while high ports (49152-65535) are often used for ephemeral connections. Unusual port usage can indicate port-based evasion or non-standard service deployment.

#### DestinationPortName
**Type:** String

**Description:** The service name associated with the destination port number.

**Populated in:** Event ID 3 (Network Connection)

**Technical Details:** Mapped from the Windows services file or port-to-service database (e.g., "http" for port 80, "https" for port 443). May be empty for non-standard ports. Helps quickly identify the intended protocol or service being accessed.

#### Device
**Type:** String

**Description:** The physical or logical device path being accessed directly.

**Populated in:** Event ID 9 (RawAccessRead)

**Technical Details:** Typically shows device paths like "\Device\HarddiskVolume1" or "\Device\PhysicalMemory". Raw device access bypasses normal filesystem operations and is commonly associated with credential dumping tools (e.g., accessing raw disk to read NTDS.dit or SAM files).

#### EventID
**Type:** Integer

**Description:** The Sysmon event type identifier.

**Populated in:** All Sysmon events

**Technical Details:** Uniquely identifies the type of event being logged. Values range from 1-27 plus 255 for errors. Each EventID corresponds to a specific system activity type as defined in the Sysmon configuration. Essential for event filtering, parsing, and routing in SIEM systems.

#### EventType
**Type:** String

**Description:** The specific operation type within certain event categories.

**Populated in:** Event ID 12 (Registry Key/Value Created or Deleted), Event ID 13 (Registry Value Set)

**Technical Details:** For registry events, can be "CreateKey", "DeleteKey", "SetValue", "DeleteValue", etc. Provides granularity beyond the EventID to distinguish between creation, deletion, and modification operations within the same event category.

#### Hash
**Type:** String

**Description:** Cryptographic hash value of a file or stream.

**Populated in:** Event ID 15 (FileCreateStreamHash)

**Technical Details:** Hash algorithm and value are typically in format "SHA256=xxxxx" or "MD5=xxxxx". Used for file identification and malware detection. The hash is calculated when the alternate data stream is created, allowing for detection of hidden malicious content.

#### Hashes
**Type:** String (Multiple hash formats)

**Description:** One or more cryptographic hash values of a file or executable.

**Populated in:** Event ID 1 (Process Creation), Event ID 6 (Driver Loaded), Event ID 7 (Image Loaded), Event ID 23 (FileDelete)

**Technical Details:** Contains multiple hash algorithms separated by commas, typically "MD5=xxxxx,SHA256=xxxxx,IMPHASH=xxxxx". IMPHASH (Import Hash) is particularly useful for identifying malware variants. Hashes enable file reputation lookups, threat intelligence matching, and forensic analysis. Configuration determines which algorithms are calculated.

#### Image
**Type:** String (File Path)

**Description:** The full path to the executable file of the process performing the action.

**Populated in:** Most Sysmon events

**Technical Details:** Absolute path including drive letter (e.g., "C:\Windows\System32\cmd.exe"). Represents the process image that triggered the event. Critical for process-based detections and identifying legitimate vs. suspicious process locations. Can detect process masquerading when compared against expected paths.

#### ImageLoaded
**Type:** String (File Path)

**Description:** The full path to the DLL, driver, or module being loaded.

**Populated in:** Event ID 6 (Driver Loaded), Event ID 7 (Image Loaded)

**Technical Details:** Absolute path to the binary being loaded into memory. For Event ID 6, represents kernel drivers. For Event ID 7, represents DLLs and other modules. Useful for detecting malicious DLL injection, unusual driver loads, and library hijacking attacks.

#### NewThreadId
**Type:** Integer

**Description:** The thread identifier assigned to the newly created remote thread.

**Populated in:** Event ID 8 (CreateRemoteThread)

**Technical Details:** Unique identifier for the thread created in the target process. Combined with target process information, this helps track specific injection attempts and correlate with subsequent malicious activity in the injected process.

#### OriginalFileName
**Type:** String

**Description:** The original filename embedded in the file's version information resource.

**Populated in:** Event ID 7 (Image Loaded)

**Technical Details:** Extracted from the PE file's VERSIONINFO resource. Helps detect renamed executables and DLLs, as the original name remains embedded even if the file is renamed on disk. Useful for identifying legitimate binaries that have been copied and renamed for evasion.

#### ParentCommandLine
**Type:** String

**Description:** The complete command-line arguments of the parent process that spawned the current process.

**Populated in:** Event ID 1 (Process Creation)

**Technical Details:** Provides execution context by showing how the parent process was launched. Essential for understanding process chains and detecting suspicious parent-child relationships (e.g., Microsoft Office spawning cmd.exe or PowerShell with encoded commands).

#### ParentImage
**Type:** String (File Path)

**Description:** The full path to the executable of the parent process.

**Populated in:** Event ID 1 (Process Creation)

**Technical Details:** Absolute path to the parent process executable. Critical for process tree analysis and detecting abnormal parent-child relationships. For example, identifying when explorer.exe is not the parent of user-initiated applications can indicate process injection or hijacking.

#### ParentProcessGuid
**Type:** GUID String

**Description:** The globally unique identifier assigned to the parent process by Sysmon.

**Populated in:** Event ID 1 (Process Creation)

**Technical Details:** Format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}. Unique across the system and persistent for the lifetime of the process. Enables correlation with other events from the same parent process, even across process ID reuse scenarios.

#### ParentProcessId
**Type:** Integer

**Description:** The Process ID (PID) of the parent process.

**Populated in:** Event ID 1 (Process Creation)

**Technical Details:** Windows Process ID assigned by the operating system. Note that PIDs can be reused after a process terminates, so ParentProcessGuid is more reliable for long-term correlation. Useful for quick process tree construction and real-time monitoring.

#### PipeName
**Type:** String

**Description:** The name of the named pipe being created or connected to.

**Populated in:** Event ID 17 (Named Pipe Created), Event ID 18 (Named Pipe Connected)

**Technical Details:** Named pipes follow the format "\\.\pipe\pipename" or "\\computername\pipe\pipename". Named pipes are commonly used for inter-process communication (IPC) and are frequently leveraged by malware for C2 communications (e.g., Cobalt Strike uses specific pipe naming patterns).

#### PreviousCreationUtcTime
**Type:** Timestamp (UTC)

**Description:** The original file creation timestamp before it was modified.

**Populated in:** Event ID 2 (File Creation Time)

**Technical Details:** Stored in ISO 8601 format. Captures the file's creation time before timestomping. By comparing with CreationUtcTime, analysts can detect timestamp manipulation attempts - a common anti-forensics technique used by attackers to hide malicious files.

#### ProcessGuid
**Type:** GUID String

**Description:** The globally unique identifier assigned to a process by Sysmon.

**Populated in:** Most Sysmon events

**Technical Details:** Format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}. Generated when a process starts and remains constant throughout its lifetime. Solves the PID reuse problem and enables reliable correlation of all events from the same process across the entire event stream.

#### ProcessId
**Type:** Integer

**Description:** The Windows Process ID (PID) assigned by the operating system.

**Populated in:** Most Sysmon events

**Technical Details:** Numeric identifier ranging from 0 to 65535 (though typically lower values). Can be reused after process termination. Combined with ProcessGuid for accurate process tracking. System processes have low PIDs (e.g., System = 4, smss.exe typically < 100).

#### Protocol
**Type:** String

**Description:** The network protocol used for the connection.

**Populated in:** Event ID 3 (Network Connection)

**Technical Details:** Common values include "tcp" and "udp". Identifies the transport layer protocol being used. Important for understanding connection characteristics - TCP indicates established connections while UDP is connectionless and used for different types of network activities.

#### SourceHostname
**Type:** String

**Description:** The DNS hostname of the local system initiating the connection.

**Populated in:** Event ID 3 (Network Connection)

**Technical Details:** Typically matches the Computer field but represents the resolved hostname for the source IP. Can differ in scenarios involving DNS resolution or when the connection originates from a specific network interface with its own hostname.

#### SourceImage
**Type:** String (File Path)

**Description:** The full path to the executable of the process initiating an action on another process.

**Populated in:** Event ID 8 (CreateRemoteThread), Event ID 10 (ProcessAccess)

**Technical Details:** Absolute path to the source process in inter-process operations. Critical for identifying which process is performing injection, memory reading, or other cross-process activities. Legitimate system processes have expected source images; deviations can indicate malicious activity.

#### SourceIp
**Type:** String (IP Address)

**Description:** The local IP address from which a network connection originates.

**Populated in:** Event ID 3 (Network Connection)

**Technical Details:** Can be IPv4 or IPv6 format. Represents the local system's IP address for the outbound connection. In multi-homed systems, identifies which network interface was used. Important for network segmentation analysis and understanding connection routing.

#### SourceIsIpv6
**Type:** Boolean

**Description:** Indicates whether the source IP address is IPv6 format.

**Populated in:** Event ID 3 (Network Connection)

**Technical Details:** Returns true for IPv6, false for IPv4. Helps in protocol-specific analysis and ensures proper handling of different address formats in parsing and analysis tools.

#### SourcePort
**Type:** Integer

**Description:** The local TCP or UDP port number from which the connection originates.

**Populated in:** Event ID 3 (Network Connection)

**Technical Details:** Typically an ephemeral port (49152-65535) for client connections, or a well-known port (0-1023) for server applications. Can help identify the type of application (client vs. server) and detect port-based anomalies.

#### SourcePortName
**Type:** String

**Description:** The service name associated with the source port number.

**Populated in:** Event ID 3 (Network Connection)

**Technical Details:** Mapped from port-to-service databases. Often empty for ephemeral ports. When populated for well-known ports, indicates the service type initiating the connection.

#### SourceProcessGUID
**Type:** GUID String

**Description:** The globally unique identifier of the process initiating an action on another process.

**Populated in:** Event ID 8 (CreateRemoteThread), Event ID 10 (ProcessAccess)

**Technical Details:** Format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}. Enables correlation with other events from the attacking/accessing process. Essential for tracking the full activity chain of a process performing injection or memory access operations.

#### SourceProcessId
**Type:** Integer

**Description:** The Process ID of the process initiating an action on another process.

**Populated in:** Event ID 8 (CreateRemoteThread), Event ID 10 (ProcessAccess)

**Technical Details:** Windows PID of the source process in inter-process operations. Combined with SourceProcessGUID for reliable tracking. Useful for quick identification during incident response.

#### SourceThreadId
**Type:** Integer

**Description:** The identifier of the thread in the source process performing the action.

**Populated in:** Event ID 10 (ProcessAccess)

**Technical Details:** Unique identifier for the specific thread within the source process that opened the handle to the target process. Provides granular detail about which execution thread is performing potentially malicious operations.

#### SourceUser
**Type:** String

**Description:** The user account context under which the source process is running.

**Populated in:** Event ID 8 (CreateRemoteThread), Event ID 10 (ProcessAccess)

**Technical Details:** Format typically "DOMAIN\Username" or "COMPUTERNAME\Username". Identifies the security context of the process initiating cross-process operations. Essential for detecting privilege escalation and lateral movement, especially when source and target users differ.

#### TargetFilename
**Type:** String (File Path)

**Description:** The full path to the file being created, modified, or deleted.

**Populated in:** Event ID 2 (File Creation Time), Event ID 11 (FileCreate), Event ID 15 (FileCreateStreamHash), Event ID 23 (FileDelete)

**Technical Details:** Absolute path including drive letter and full directory structure. Critical for monitoring file operations in sensitive locations (e.g., startup folders, system directories). Used to detect suspicious file creation patterns, persistence mechanisms, and data exfiltration staging.

#### TargetImage
**Type:** String (File Path)

**Description:** The full path to the executable of the process being targeted by an action.

**Populated in:** Event ID 8 (CreateRemoteThread), Event ID 10 (ProcessAccess)

**Technical Details:** Absolute path to the target process in inter-process operations. Helps identify which processes are being injected into or accessed. Common attack patterns involve targeting high-value processes like lsass.exe (credential access) or explorer.exe (persistence).

#### TargetObject
**Type:** String

**Description:** The full registry path being created, modified, or deleted.

**Populated in:** Event ID 12 (Registry Key/Value Created or Deleted), Event ID 13 (Registry Value Set)

**Technical Details:** Complete registry path including hive and key path (e.g., "HKLM\Software\Microsoft\Windows\CurrentVersion\Run\MaliciousKey"). Essential for detecting persistence mechanisms, configuration changes, and registry-based attacks. Format follows standard Windows registry path conventions.

#### TargetProcessGUID
**Type:** GUID String

**Description:** The globally unique identifier of the process being targeted by an action.

**Populated in:** Event ID 8 (CreateRemoteThread), Event ID 10 (ProcessAccess)

**Technical Details:** Format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}. Enables correlation with other events involving the targeted process. Critical for tracking the lifecycle and all interactions with processes that are subject to injection or memory access.

#### TargetProcessId
**Type:** Integer

**Description:** The Process ID of the process being targeted by an action.

**Populated in:** Event ID 8 (CreateRemoteThread), Event ID 10 (ProcessAccess)

**Technical Details:** Windows PID of the target process. Combined with TargetProcessGUID for accurate tracking across PID reuse scenarios. Useful for quick identification of which process is being attacked or accessed.

#### TargetUser
**Type:** String

**Description:** The user account context under which the target process is running.

**Populated in:** Event ID 8 (CreateRemoteThread), Event ID 10 (ProcessAccess)

**Technical Details:** Format typically "DOMAIN\Username" or "COMPUTERNAME\Username". Shows the security context of the process being targeted. When SourceUser and TargetUser differ, it may indicate privilege escalation attempts or cross-user attacks.

#### timestamp
**Type:** Timestamp

**Description:** The date and time when the event was generated by Sysmon.

**Populated in:** All Sysmon events

**Technical Details:** Typically stored in ISO 8601 format with millisecond precision (YYYY-MM-DD HH:MM:SS.mmm). Represents the event creation time in UTC. Critical for timeline analysis, event correlation, and temporal pattern detection. Should be distinguished from CreationUtcTime which refers to file creation timestamps.

#### User
**Type:** String

**Description:** The user account under which the process generating the event is running.

**Populated in:** Most Sysmon events

**Technical Details:** Format typically "DOMAIN\Username" or "COMPUTERNAME\Username" or "NT AUTHORITY\SYSTEM". Represents the security context of the process. Essential for identifying anomalous user activity, privilege escalation, and lateral movement. System accounts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE) indicate processes running with elevated privileges.


## Netflow Event Fields

Network flow (netflow) data represents aggregated, summarized records of network communications between endpoints over a specific time period. Unlike packet capture (PCAP), which records every individual packet and its full payload, netflow captures metadata about conversations between systems - including who communicated with whom, when, how much data was transferred, and which protocols were used. This makes netflow significantly more scalable and privacy-preserving than full packet capture, as it doesn't store actual packet contents.

For security monitoring and threat detection, netflow data provides critical visibility into network behavior patterns without the storage and processing overhead of full packet capture. It enables detection of data exfiltration (unusual outbound data volumes), command-and-control communications (beaconing patterns, connections to suspicious IPs), lateral movement (internal host-to-host communications), port scanning, and protocol anomalies. When enriched with process-level context (as in this dataset), netflow becomes especially powerful for attributing network activity to specific applications and detecting process-based network threats like malware communications, unauthorized software, and compromised legitimate processes.

### Network Flow Dataset Schema and Field Collections

| Field Category | Field Group | Key Fields Collected |
|----------------|-------------|---------------------|
| **Temporal** | Event Timing | [timestamp](#timestamp), [event_start](#event_start), [event_end](#event_end), [event_duration](#event_duration) |
| **Temporal** | Flow Classification | [event_action](#event_action), [event_type](#event_type), [network_traffic_flow_final](#network_traffic_flow_final) |
| **Temporal** | Flow Identification | [network_community_id](#network_community_id), [network_traffic_flow_id](#network_traffic_flow_id) |
| **Network Layer** | Connection Details | [network_transport](#network_transport), [network_type](#network_type), [network_bytes](#network_bytes), [network_packets](#network_packets) |
| **Network Layer** | Source Endpoint | [source_ip](#source_ip), [source_mac](#source_mac), [source_port](#source_port), [source_bytes](#source_bytes), [source_packets](#source_packets) |
| **Network Layer** | Destination Endpoint | [destination_ip](#destination_ip), [destination_mac](#destination_mac), [destination_port](#destination_port), [destination_bytes](#destination_bytes), [destination_packets](#destination_packets) |
| **Network Layer** | Host Context | [host_hostname](#host_hostname), [host_ip](#host_ip), [host_mac](#host_mac), [host_os_platform](#host_os_platform) |
| **Process Context** | Source Process | [source_process_executable](#source_process_executable), [source_process_name](#source_process_name), [source_process_pid](#source_process_pid), [source_process_ppid](#source_process_ppid), [source_process_args](#source_process_args) |
| **Process Context** | Destination Process | [destination_process_executable](#destination_process_executable), [destination_process_pid](#destination_process_pid), [destination_process_ppid](#destination_process_ppid), [destination_process_args](#destination_process_args) |
| **Process Context** | General Process | [process_executable](#process_executable), [process_name](#process_name), [process_pid](#process_pid), [process_parent_pid](#process_parent_pid), [process_args](#process_args) |
| **Process Context** | Process Hierarchy | Parent-child relationships tracked via PID and PPID fields |

### Netflow Field Definitions

This section provides detailed definitions for each field that appears in the network flow events table above. Fields are organized alphabetically for easy reference.

#### destination_bytes

**Type:** Integer

**Description:** The total number of bytes sent from the source to the destination endpoint during this network flow.

**Field Group:** Destination Endpoint

**Technical Details:** Represents the volume of data transmitted to the destination. Combined with source_bytes, this enables calculation of total flow volume and directional data transfer ratios. Useful for detecting data exfiltration (unusually high outbound bytes), downloading of large files or malware payloads (high inbound bytes), and asymmetric communication patterns. Measured in bytes, can range from 0 to very large values depending on the duration and nature of the communication.

#### destination_ip

**Type:** String (IP Address)

**Description:** The IP address of the destination endpoint in the network communication.

**Field Group:** Destination Endpoint

**Technical Details:** Can be IPv4 (dotted decimal notation like 192.168.1.1) or IPv6 (colon-hexadecimal notation). Represents the target system receiving the network connection. Critical for identifying connections to external threat actors, command-and-control infrastructure, known malicious IPs, or unauthorized external services. Used extensively in threat intelligence correlation and network-based indicators of compromise (IOCs). Internal IPs may indicate lateral movement while external IPs often represent internet-bound traffic.

#### destination_mac

**Type:** String (MAC Address)

**Description:** The Media Access Control (MAC) address of the destination network interface.

**Field Group:** Destination Endpoint

**Technical Details:** 48-bit hardware address typically formatted as six groups of two hexadecimal digits (e.g., 00:1A:2B:3C:4D:5E). Identifies the physical network interface at the data link layer. Useful for tracking specific devices on local networks, detecting MAC address spoofing, and correlating network activity to specific hardware. For routed traffic beyond the local subnet, this typically shows the MAC of the gateway/router rather than the ultimate destination.

#### destination_packets

**Type:** Integer

**Description:** The total number of packets sent from the source to the destination during this network flow.

**Field Group:** Destination Endpoint

**Technical Details:** Count of individual network packets transmitted to the destination. When combined with destination_bytes, allows calculation of average packet size, which can reveal protocol characteristics and potential packet fragmentation or padding techniques used by malware. Small packet counts with large byte counts suggest bulk data transfer, while high packet counts with low byte counts may indicate chatty protocols or scanning activity.

#### destination_port

**Type:** Integer

**Description:** The TCP or UDP port number on the destination system.

**Field Group:** Destination Endpoint

**Technical Details:** Valid range is 0-65535. Well-known ports (0-1023) identify standard services like HTTP (80), HTTPS (443), DNS (53), SMB (445). Registered ports (1024-49151) are assigned to specific applications. Dynamic/ephemeral ports (49152-65535) are typically used for client-side connections. Unusual port usage can indicate port-based evasion, non-standard service deployment, or tunneling protocols. Critical for protocol identification and detecting services running on non-standard ports.

#### destination_process_args

**Type:** String

**Description:** The command-line arguments of the process on the destination system that received or handled the network connection.

**Field Group:** Destination Process

**Technical Details:** Captures the full command line including parameters for the destination process. In server scenarios, this might show web server startup parameters, database connection strings, or service configurations. Particularly valuable when analyzing lateral movement where an attacker's commands on the destination system can be observed. May be empty if the destination system isn't instrumented or if the connection is to an external system.

#### destination_process_executable

**Type:** String (File Path)

**Description:** The full path to the executable file of the process on the destination system that received the network connection.

**Field Group:** Destination Process

**Technical Details:** Absolute file path identifying which application on the destination handled the connection. For server-side connections, reveals the listening service (e.g., /usr/sbin/sshd for SSH, C:\Windows\System32\svchost.exe for Windows services). Critical for understanding what services are exposed and detecting unauthorized listeners. In lateral movement scenarios, can identify remote execution tools or malicious implants running on compromised systems.

#### destination_process_pid

**Type:** Integer

**Description:** The process identifier (PID) of the destination process that handled the network connection.

**Field Group:** Destination Process

**Technical Details:** Unique identifier assigned by the operating system to the destination process. Enables correlation of network activity with other process-based telemetry on the destination system. PIDs are typically 32-bit integers that may be reused after process termination. Combined with timestamps and hostname, provides unique process identification for investigative correlation.

#### destination_process_ppid

**Type:** Integer

**Description:** The parent process identifier (PPID) of the destination process.

**Field Group:** Destination Process

**Technical Details:** Identifies the parent process that spawned the destination process, enabling reconstruction of process hierarchy and execution chains on the destination system. Critical for understanding how a listening service or connection handler was launched. For example, legitimate services typically have expected parent processes (services.exe on Windows, systemd on Linux), while unusual parent-child relationships may indicate process injection or malicious execution.

#### event_action

**Type:** String

**Description:** The specific network action or flow state being recorded.

**Field Group:** Flow Classification

**Technical Details:** Describes the nature of the network event, such as "network_flow", "connection_attempted", "connection_accepted", "connection_closed", etc. Provides granularity beyond simple flow records to understand the lifecycle of connections. Values like "network_flow" typically indicate a completed or ongoing bidirectional communication session. Essential for distinguishing between successful communications, failed connection attempts, and connection terminations, each of which has different security implications.

#### event_duration

**Type:** Integer or Float

**Description:** The total time duration of the network flow from start to finish.

**Field Group:** Event Timing

**Technical Details:** Typically measured in milliseconds or seconds, calculated as event_end minus event_start. Long-duration connections may indicate persistent backdoors, tunneling, or legitimate long-running services. Very short connections could suggest scanning, failed connections, or quick data transfers. Beaconing malware often exhibits patterns of regular, short-duration connections. Duration analysis combined with bytes transferred reveals data transfer rates useful for identifying exfiltration or suspicious traffic patterns.

#### event_end

**Type:** Timestamp (UTC)

**Description:** The timestamp when the network flow ended or was last observed.

**Field Group:** Event Timing

**Technical Details:** Stored in ISO 8601 format (YYYY-MM-DD HH:MM:SS.mmm) or Unix epoch time. Marks the conclusion of the network session, either through graceful connection termination (TCP FIN), forceful termination (TCP RST), timeout, or end of the observation window. Together with event_start, defines the temporal boundaries of the flow for timeline analysis and correlation with other security events.

#### event_start

**Type:** Timestamp (UTC)

**Description:** The timestamp when the network flow began or was first observed.

**Field Group:** Event Timing

**Technical Details:** Stored in ISO 8601 format (YYYY-MM-DD HH:MM:SS.mmm) or Unix epoch time. Represents when the network communication initiated, typically corresponding to TCP SYN for TCP connections or first packet for UDP flows. Critical for establishing timelines, correlating network activity with other host-based events, and identifying the sequence of attacker actions during an incident.

#### event_type

**Type:** String

**Description:** The category or classification of the network event being logged.

**Field Group:** Flow Classification

**Technical Details:** Broad categorization such as "connection", "flow", "protocol_event", etc. Helps in filtering and routing network telemetry to appropriate analysis pipelines. Different event types may contain different field sets or require different analytical approaches. For example, "connection" events might focus on session establishment while "flow" events emphasize data transfer metrics.

#### host_hostname

**Type:** String

**Description:** The hostname or computer name of the system where the network flow was observed or originated.

**Field Group:** Host Context

**Technical Details:** Typically the DNS name or NetBIOS name of the host. Critical for multi-host analysis in enterprise environments, enabling tracking of which specific systems are involved in suspicious communications. Helps identify compromised hosts, map network architecture, and correlate with asset management databases. More stable than IP addresses in DHCP environments where IPs may change.

#### host_ip

**Type:** String (IP Address)

**Description:** The IP address of the host where the flow was observed, typically the source system in outbound flows.

**Field Group:** Host Context

**Technical Details:** Can be IPv4 or IPv6 format. Represents the network identifier of the monitoring point or flow originator. Essential for network-based correlation and identifying which subnet or network segment is involved. In environments with multiple network interfaces, helps determine which interface was used for the communication.

#### host_mac

**Type:** String (MAC Address)

**Description:** The MAC address of the host's network interface where the flow was observed.

**Field Group:** Host Context

**Technical Details:** Hardware address of the network interface card. Useful for tracking specific devices even when IP addresses change (DHCP environments), detecting MAC spoofing, and correlating with network access control (NAC) systems. Remains constant unless the hardware is changed or deliberately spoofed, making it valuable for long-term device tracking and forensic analysis.

#### host_os_platform

**Type:** String

**Description:** The operating system platform of the host where the flow was observed.

**Field Group:** Host Context

**Technical Details:** Identifies the OS family such as "windows", "linux", "macos", "unix", etc. Critical for understanding platform-specific threat behaviors and expected network patterns. Windows systems may show different process names and paths than Linux systems for similar services. Helps in filtering platform-specific detections and understanding the technical context of observed behaviors.

#### network_bytes

**Type:** Integer

**Description:** The total number of bytes transferred in both directions during the entire network flow.

**Field Group:** Connection Details

**Technical Details:** Sum of all bytes sent and received across the entire communication session, calculated as source_bytes + destination_bytes. Primary metric for understanding data volume and detecting data exfiltration or unusual transfers. Large values may indicate file transfers, data theft, or legitimate bulk operations. Very small values might suggest scanning, heartbeats, or failed connections. Essential for bandwidth analysis and anomaly detection based on historical baselines.

#### network_community_id

**Type:** String

**Description:** A standardized hash-based identifier for the network flow that is consistent across different network monitoring tools.

**Field Group:** Flow Identification

**Technical Details:** Generated using the Community ID flow hashing specification, which creates a stable hash from the 5-tuple (source IP, destination IP, source port, destination port, protocol) and ensures the same value is produced regardless of directionality. Format is typically "1:base64hash" where 1 is the version. Enables correlation of the same network flow across different data sources (e.g., correlating netflow with IDS alerts, packet captures, or endpoint telemetry). Critical for unified analysis in heterogeneous monitoring environments.

#### network_packets

**Type:** Integer

**Description:** The total number of packets transferred in both directions during the network flow.

**Field Group:** Connection Details

**Technical Details:** Combined count of all packets sent and received, equal to source_packets + destination_packets. When analyzed with network_bytes, reveals average packet size (bytes/packets), which can identify protocol characteristics, fragmentation, padding, or covert channels. High packet counts with low byte counts suggest chatty protocols or potential scanning. Low packet counts with high byte counts indicate bulk data transfer with large packets.

#### network_traffic_flow_final

**Type:** Boolean or String

**Description:** Indicates whether this record represents the final state of the network flow or if it's an interim update.

**Field Group:** Flow Classification

**Technical Details:** Some network monitoring systems export flow records periodically during long sessions (active flows) and then a final record when the session terminates. This field distinguishes between interim updates and the definitive final flow record containing complete statistics. "true" or "final" indicates the flow has ended; "false" or "interim" indicates an ongoing flow snapshot. Important for accurate metric calculations and avoiding double-counting in analytics.

#### network_traffic_flow_id

**Type:** String or Integer

**Description:** A unique identifier assigned to this specific network flow session by the monitoring system.

**Field Group:** Flow Identification

**Technical Details:** Locally generated identifier unique within the collecting system's context. Unlike community_id which is deterministic across systems, this is typically a UUID, sequence number, or hash assigned by the specific collection tool. Used for tracking flow records through processing pipelines, correlating interim and final flow records for the same session, and referencing specific flows in investigations. Not portable across different monitoring systems.

#### network_transport

**Type:** String

**Description:** The transport layer protocol used for the network communication.

**Field Group:** Connection Details

**Technical Details:** Typically "tcp", "udp", "icmp", or other IP protocol identifiers. TCP indicates connection-oriented, reliable communications (most application protocols). UDP indicates connectionless, faster transmissions (DNS, streaming, some malware C2). ICMP is used for network diagnostics and control (ping, traceroute, but also for covert channels). Critical for understanding the communication mechanism and applying protocol-specific analysis techniques.

#### network_type

**Type:** String

**Description:** The network layer protocol version or addressing type.

**Field Group:** Connection Details

**Technical Details:** Commonly "ipv4" or "ipv6", indicating which IP version is being used. IPv4 is still predominant but IPv6 adoption is increasing. Some malware uses IPv6 for evasion since it's less commonly monitored in many environments. Important for proper parsing of IP addresses and ensuring monitoring coverage across both protocol versions. May also indicate other network types like "icmp" in some implementations.

#### process_args

**Type:** String

**Description:** The command-line arguments of the process associated with the network flow, when process attribution is available but directionality is not specified.

**Field Group:** General Process

**Technical Details:** Full command line including the executable path and all parameters. Used when the monitoring system can attribute network activity to a process but doesn't distinguish between source and destination processes, or when the same field applies to both. Essential for detecting malicious command patterns, script-based attacks, encoded commands, and unusual process invocations. May contain sensitive information and is critical for behavioral analysis.

#### process_executable

**Type:** String (File Path)

**Description:** The full path to the executable file of the process responsible for the network activity.

**Field Group:** General Process

**Technical Details:** Absolute file path identifying the program that generated or received the network traffic. Enables application-level attribution of network activity. Expected paths vary by OS: Windows typically uses C:\Program Files\ or C:\Windows\, Linux uses /usr/bin/, /usr/sbin/, etc. Unexpected paths (user directories, temp folders, hidden directories) may indicate malware or unauthorized software. Critical for application allow/deny listing and detecting process masquerading.

#### process_name

**Type:** String

**Description:** The filename of the process executable without the full path.

**Field Group:** General Process

**Technical Details:** Extracted from the full executable path, representing just the filename (e.g., "chrome.exe", "sshd", "python"). Simpler to analyze than full paths but less precise since the same filename can exist in multiple locations. Useful for quick filtering and high-level categorization. Common legitimate process names are well-documented, making anomalies easier to spot, but beware of malware using legitimate-sounding names.

#### process_parent_pid

**Type:** Integer

**Description:** The process identifier of the parent process that spawned the process responsible for this network activity.

**Field Group:** General Process

**Technical Details:** Identifies the parent in the process execution chain, enabling reconstruction of process trees and understanding execution context. Expected parent-child relationships are documented for legitimate software (e.g., explorer.exe spawning user applications on Windows, systemd spawning daemons on Linux). Unusual relationships often indicate malicious injection, process hollowing, or attacker tool execution. Essential for detecting process-based evasion techniques.

#### process_pid

**Type:** Integer

**Description:** The process identifier of the process responsible for the network activity.

**Field Group:** General Process

**Technical Details:** Operating system-assigned unique identifier for the process instance. Typically a 32-bit integer that may be reused after process termination. Enables correlation of network flows with other process-based telemetry (file access, registry changes, additional network connections). Combined with timestamp and hostname, provides precise process instance identification for investigative linking across multiple data sources.

#### source_bytes

**Type:** Integer

**Description:** The total number of bytes sent from the source endpoint to the destination during this network flow.

**Field Group:** Source Endpoint

**Technical Details:** Measures outbound data volume from the source's perspective. Critical for detecting data exfiltration when source_bytes significantly exceeds destination_bytes (upload-heavy traffic to external IPs). Normal client-server patterns typically show higher destination_bytes (downloads) than source_bytes (requests). Malware C2 often shows characteristic byte patterns in beaconing behavior. Combined with temporal analysis, reveals sustained vs. bursty transmission patterns.

#### source_ip

**Type:** String (IP Address)

**Description:** The IP address of the source endpoint that initiated or participated in the network communication.

**Field Group:** Source Endpoint

**Technical Details:** IPv4 or IPv6 address of the originating system. In outbound connections, typically the internal host; in inbound connections, may be external attacker IP. Essential for identifying which internal systems are communicating externally, detecting compromised internal hosts, and building network maps. Used extensively in firewall rules, network segmentation enforcement, and identifying the origin of suspicious traffic.

#### source_mac

**Type:** String (MAC Address)

**Description:** The Media Access Control address of the source network interface.

**Field Group:** Source Endpoint

**Technical Details:** 48-bit hardware address of the originating network interface. More permanent than IP addresses, useful for tracking specific devices across IP changes. Critical for detecting MAC spoofing, identifying devices in DHCP environments, and correlating with network access control systems. Only meaningful within the local network segment; routed traffic will show intermediate device MACs rather than the true original source.

#### source_packets

**Type:** Integer

**Description:** The total number of packets sent from the source to the destination during this network flow.

**Field Group:** Source Endpoint

**Technical Details:** Count of individual packets transmitted from source to destination. Ratio of source_packets to source_bytes reveals average outbound packet size. Small packets (high count, low bytes) may indicate control traffic, keepalives, or scanning. Large packets (low count, high bytes) suggest bulk data transfer. Protocol-specific patterns emerge: HTTP uploads show different packet patterns than malware beaconing.

#### source_port

**Type:** Integer

**Description:** The TCP or UDP port number on the source system.

**Field Group:** Source Endpoint

**Technical Details:** For client-initiated connections, typically an ephemeral port (49152-65535 on modern systems, varies by OS). For server listening sockets, a well-known or registered port. Source port analysis helps distinguish client vs. server roles. Consistent source ports from a client may indicate port reuse by malware or specific application behavior. Unusual low-numbered source ports from clients can indicate crafted packets or port manipulation.

#### source_process_args

**Type:** String

**Description:** The command-line arguments of the process on the source system that initiated the network connection.

**Field Group:** Source Process

**Technical Details:** Complete command line for the source process, including executable path and parameters. Reveals how the network-generating process was invoked, which is critical for detecting malicious scripts, encoded PowerShell commands, suspicious browser invocations, or attacker tools. May contain URLs being accessed, file paths being transferred, or configuration parameters that reveal attack techniques. Maximum length varies by system but can be extensive.

#### source_process_executable

**Type:** String (File Path)

**Description:** The full path to the executable file of the process on the source system that initiated the network connection.

**Field Group:** Source Process

**Technical Details:** Absolute file path of the originating process. Most network security analysis focuses on this field since it attributes network activity to specific applications. Expected paths for common applications are well-documented; deviations suggest malware, unauthorized software, or LOLBins (living-off-the-land binaries). Critical for application-based network policies, detecting malicious executables, and understanding which software is generating what network traffic.

#### source_process_name

**Type:** String

**Description:** The filename of the source process executable without the full path.

**Field Group:** Source Process

**Technical Details:** Process name extracted from the full executable path (e.g., "chrome.exe", "curl", "powershell.exe"). Simpler for quick analysis and reporting than full paths. Commonly used in network filtering rules and baseline definitions. However, be cautious of malware using legitimate-sounding names in non-standard locations; always validate against the full source_process_executable path for accurate identification.

#### source_process_pid

**Type:** Integer

**Description:** The process identifier of the source process that initiated the network connection.

**Field Group:** Source Process

**Technical Details:** Operating system-assigned PID for the source process. Enables precise correlation with other host-based telemetry from the source system, such as process creation events, file operations, and registry modifications by the same process instance. Critical for building complete attack narratives by linking network IOCs with process behaviors. PIDs may be reused, so combine with timestamps for unique identification.

#### source_process_ppid

**Type:** Integer

**Description:** The parent process identifier of the source process.

**Field Group:** Source Process

**Technical Details:** Identifies which process spawned the network-generating process, enabling process tree reconstruction. Expected parent-child relationships are well-documented for legitimate applications (e.g., legitimate chrome.exe spawned by explorer.exe or systemd). Unusual relationships often indicate process injection, privilege escalation, or lateral movement techniques. Essential for detecting sophisticated malware that manipulates process hierarchies to evade detection.

#### timestamp

**Type:** Timestamp (UTC)

**Description:** The primary timestamp associated with the network flow event, typically representing when the event was recorded or processed.

**Field Group:** Event Timing

**Technical Details:** Stored in ISO 8601 format (YYYY-MM-DD HH:MM:SS.mmm) or Unix epoch time. May represent the flow start time, end time, or export time depending on implementation. Critical for temporal correlation, timeline reconstruction, and time-based analysis. When event_start and event_end are present, timestamp often represents when the flow record was generated or exported by the collection system. Essential for all time-series analysis and sequencing events in incident investigations.

