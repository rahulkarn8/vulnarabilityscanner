import re
from pathlib import Path
from typing import Any, Dict, List, Optional


class AutomotiveSecurityScanner:
    """Detects automotive-specific security vulnerabilities in embedded and AUTOSAR code."""

    def __init__(self) -> None:
        # CAN Bus Security Patterns
        self.can_bus_patterns = [
            {
                "rule_id": "CAN-001",
                "cwe_id": "CWE-20",
                "name": "CAN Message Parsing Without Validation",
                "pattern": r"CAN_\w+.*\([^)]*\)|can_\w+.*\([^)]*\)|CanIf_\w+.*\([^)]*\)",
                "severity": "high",
                "description": (
                    "CAN message parsing without proper validation can lead to injection attacks. "
                    "Always validate CAN message IDs, DLC (Data Length Code), and payload ranges."
                ),
            },
            {
                "rule_id": "CAN-002",
                "cwe_id": "CWE-547",
                "name": "Hardcoded CAN ID",
                "pattern": r"(?:CAN_ID|CANID|can_id)\s*[=:]\s*0x[0-9a-fA-F]+|#define\s+CAN.*ID\s+0x",
                "severity": "medium",
                "description": (
                    "Hardcoded CAN IDs reduce flexibility and may conflict with other ECUs. "
                    "Consider using configuration files or parameter management systems."
                ),
            },
            {
                "rule_id": "CAN-003",
                "cwe_id": "CWE-306",
                "name": "Missing CAN Message Authentication",
                "pattern": r"CAN.*Receive|CanIf_Receive|can_receive",
                "severity": "critical",
                "description": (
                    "CAN message reception without authentication/encryption is vulnerable to spoofing. "
                    "Implement CANsec or similar security protocols for critical messages."
                ),
            },
            {
                "rule_id": "CAN-004",
                "cwe_id": "CWE-20",
                "name": "Unvalidated DLC (Data Length Code)",
                "pattern": r"DLC\s*[=:]|\.dlc\s*=|DataLengthCode",
                "severity": "high",
                "description": (
                    "DLC validation is critical to prevent buffer overflows. Always validate DLC against "
                    "expected message length before processing CAN payloads."
                ),
            },
        ]

        # AUTOSAR Security Patterns
        self.autosar_patterns = [
            {
                "rule_id": "AUTOSAR-001",
                "cwe_id": "CWE-703",
                "name": "Insecure RTE (Runtime Environment) Usage",
                "pattern": r"Rte_Write|Rte_Read|Rte_Call",
                "severity": "medium",
                "description": (
                    "RTE calls without proper error handling can lead to undefined behavior. "
                    "Always check return values and implement proper error handling."
                ),
            },
            {
                "rule_id": "AUTOSAR-002",
                "cwe_id": "CWE-703",
                "name": "Missing BSW Error Handling",
                "pattern": r"EcuM_|BswM_|ComM_|CanIf_|CanNm_",
                "severity": "high",
                "description": (
                    "AUTOSAR BSW (Basic Software) calls should always check return values. "
                    "Missing error handling can lead to system failures."
                ),
            },
            {
                "rule_id": "AUTOSAR-003",
                "cwe_id": "CWE-20",
                "name": "Insecure COM Stack Usage",
                "pattern": r"Com_SendSignal|Com_ReceiveSignal|Com_TriggerIPDUSend",
                "severity": "high",
                "description": (
                    "COM stack signals should be validated before transmission. "
                    "Unvalidated signals can cause network congestion or security issues."
                ),
            },
            {
                "rule_id": "AUTOSAR-004",
                "cwe_id": "CWE-665",
                "name": "Missing Crypto Stack Initialization",
                "pattern": r"Csm_|Crypto_|CryIf_",
                "severity": "critical",
                "description": (
                    "Crypto stack usage without proper initialization is insecure. "
                    "Ensure Crypto Service Manager (CSM) is properly initialized before use."
                ),
            },
            {
                "rule_id": "AUTOSAR-005",
                "cwe_id": "CWE-321",
                "name": "Hardcoded Security Keys",
                "pattern": r"(?:SECRET|KEY|PASSWORD|PIN)\s*[=:]\s*['\"][^'\"]+['\"]|#define\s+(?:SECRET|KEY|PASSWORD)",
                "severity": "critical",
                "description": (
                    "Hardcoded cryptographic keys or secrets in source code are a critical security risk. "
                    "Use secure key storage (HSM, secure element) or secure boot mechanisms."
                ),
            },
            {
                "rule_id": "AUTOSAR-006",
                "cwe_id": "CWE-693",
                "name": "Missing Memory Protection Unit (MPU) Configuration",
                "pattern": r"Mpu_|MPU_|MemoryProtection",
                "severity": "high",
                "description": (
                    "AUTOSAR OS Memory Protection Unit should be properly configured to prevent unauthorized memory access. "
                    "Missing MPU configuration can allow code injection or data corruption attacks."
                ),
            },
            {
                "rule_id": "AUTOSAR-007",
                "cwe_id": "CWE-284",
                "name": "Insecure OS Task Configuration",
                "pattern": r"OsTask|OSTask|Task_|ActivateTask|TerminateTask",
                "severity": "high",
                "description": (
                    "AUTOSAR OS tasks should have proper priority, stack size, and access rights configured. "
                    "Insecure task configuration can lead to privilege escalation or resource exhaustion."
                ),
            },
            {
                "rule_id": "AUTOSAR-008",
                "cwe_id": "CWE-362",
                "name": "Missing Resource Protection",
                "pattern": r"GetResource|ReleaseResource|DisableAllInterrupts|EnableAllInterrupts",
                "severity": "high",
                "description": (
                    "AUTOSAR OS resource protection should be used to prevent race conditions. "
                    "Missing resource protection can cause data corruption or system instability."
                ),
            },
            {
                "rule_id": "AUTOSAR-009",
                "cwe_id": "CWE-306",
                "name": "Insecure SecOC (Secure Onboard Communication) Usage",
                "pattern": r"SecOC_|Secoc_|SecureOnboardCommunication",
                "severity": "critical",
                "description": (
                    "SecOC should be properly configured with fresh keys and proper authentication. "
                    "Missing or misconfigured SecOC allows message replay and injection attacks."
                ),
            },
            {
                "rule_id": "AUTOSAR-010",
                "cwe_id": "CWE-310",
                "name": "Insecure Key Management",
                "pattern": r"KeyM_|KeyManager|KeyStore|KeySlot",
                "severity": "critical",
                "description": (
                    "AUTOSAR Key Manager should use secure key storage and proper key lifecycle management. "
                    "Insecure key management can lead to key exposure or unauthorized access."
                ),
            },
            {
                "rule_id": "AUTOSAR-011",
                "cwe_id": "CWE-295",
                "name": "Missing Certificate Validation",
                "pattern": r"Cert_|Certificate_|X509|Pki_|PKI_",
                "severity": "critical",
                "description": (
                    "Certificate validation is critical for secure communication. "
                    "Missing certificate validation allows man-in-the-middle attacks."
                ),
            },
            {
                "rule_id": "AUTOSAR-012",
                "cwe_id": "CWE-494",
                "name": "Insecure Secure Boot Integration",
                "pattern": r"SecureBoot|Secure_Boot|BootManager|Bm_",
                "severity": "critical",
                "description": (
                    "AUTOSAR Secure Boot should verify firmware signatures before execution. "
                    "Missing secure boot allows malicious firmware injection."
                ),
            },
            {
                "rule_id": "AUTOSAR-013",
                "cwe_id": "CWE-20",
                "name": "Insecure PDU Router Usage",
                "pattern": r"PduR_|PduRouter_|PduR_Transmit|PduR_Receive",
                "severity": "high",
                "description": (
                    "PDU Router should validate PDU length and routing rules. "
                    "Unvalidated PDUs can cause buffer overflows or routing attacks."
                ),
            },
            {
                "rule_id": "AUTOSAR-014",
                "cwe_id": "CWE-306",
                "name": "Missing DoIP (Diagnostic over IP) Security",
                "pattern": r"DoIP_|Doip_|DiagnosticOverIP|TcpIp_",
                "severity": "high",
                "description": (
                    "DoIP communication should use TLS/DTLS for secure transport. "
                    "Unencrypted DoIP allows diagnostic session hijacking."
                ),
            },
            {
                "rule_id": "AUTOSAR-015",
                "cwe_id": "CWE-703",
                "name": "Missing DCM (Diagnostic Communication Manager) Security",
                "pattern": r"Dcm_|DCM_|DiagnosticCommunicationManager",
                "severity": "high",
                "description": (
                    "DCM should implement security access (0x27) for sensitive services. "
                    "Missing security access allows unauthorized diagnostic operations."
                ),
            },
            {
                "rule_id": "AUTOSAR-016",
                "cwe_id": "CWE-665",
                "name": "Insecure State Manager Usage",
                "pattern": r"StateM_|StateManager|BswM_StateRequest",
                "severity": "medium",
                "description": (
                    "State Manager transitions should be validated to prevent unauthorized state changes. "
                    "Unvalidated state transitions can bypass security controls."
                ),
            },
            {
                "rule_id": "AUTOSAR-017",
                "cwe_id": "CWE-693",
                "name": "Missing Watchdog Integration",
                "pattern": r"Wdg_|WdgM_|WatchdogManager",
                "severity": "high",
                "description": (
                    "AUTOSAR Watchdog Manager should be properly configured and serviced. "
                    "Missing watchdog can allow system hangs or denial of service."
                ),
            },
            {
                "rule_id": "AUTOSAR-018",
                "cwe_id": "CWE-20",
                "name": "Insecure NVM (Non-Volatile Memory) Access",
                "pattern": r"NvM_|Nvm_|NonVolatileMemory",
                "severity": "high",
                "description": (
                    "NVM access should be protected and validated. "
                    "Unprotected NVM access can allow tampering with critical configuration data."
                ),
            },
            {
                "rule_id": "AUTOSAR-019",
                "cwe_id": "CWE-362",
                "name": "Race Condition in Shared Resources",
                "pattern": r"SchM_|ScheduleManager|ActivateTask|ChainTask",
                "severity": "high",
                "description": (
                    "AUTOSAR scheduling should use proper resource protection. "
                    "Race conditions in shared resources can cause data corruption."
                ),
            },
            {
                "rule_id": "AUTOSAR-020",
                "cwe_id": "CWE-306",
                "name": "Missing Firewall Configuration",
                "pattern": r"Firewall_|FirewallManager|FwM_",
                "severity": "critical",
                "description": (
                    "AUTOSAR Firewall should be configured to restrict inter-ECU communication. "
                    "Missing firewall allows unauthorized network access."
                ),
            },
            {
                "rule_id": "AUTOSAR-021",
                "cwe_id": "CWE-367",
                "name": "Time-of-Check Time-of-Use (TOCTOU) in AUTOSAR",
                "pattern": r"(Rte_Read|NvM_Read|Com_ReceiveSignal).*?(Rte_Write|NvM_Write|Com_SendSignal)",
                "severity": "high",
                "description": (
                    "Time-of-check time-of-use vulnerabilities can occur when data is read and then written "
                    "without proper locking. Use atomic operations or resource protection."
                ),
            },
            {
                "rule_id": "AUTOSAR-022",
                "cwe_id": "CWE-665",
                "name": "Improper Initialization of AUTOSAR Services",
                "pattern": r"(EcuM_Init|BswM_Init|ComM_Init|CanIf_Init|Crypto_Init)\s*\([^)]*\)(?!.*(?:if|return|E_OK|E_NOT_OK))",
                "severity": "critical",
                "description": (
                    "AUTOSAR service initialization must be checked for errors. "
                    "Missing initialization error checking can lead to undefined behavior."
                ),
            },
            {
                "rule_id": "AUTOSAR-023",
                "cwe_id": "CWE-20",
                "name": "Unvalidated AUTOSAR Signal Values",
                "pattern": r"Rte_Write_.*?\(|Com_SendSignal.*?\(|PduR_Transmit.*?\([^)]*\)",
                "severity": "high",
                "description": (
                    "AUTOSAR signals should be validated for range, type, and constraints before transmission. "
                    "Unvalidated signals can cause system failures or security breaches."
                ),
            },
            {
                "rule_id": "AUTOSAR-024",
                "cwe_id": "CWE-754",
                "name": "Improper Check for Unusual or Exceptional Conditions in AUTOSAR",
                "pattern": r"(EcuM_|BswM_|Rte_|Com_|CanIf_|Dcm_)[^(]*\([^)]*\)(?!\s*(?:if|switch|==|!=))",
                "severity": "high",
                "description": (
                    "AUTOSAR API return values must always be checked. Missing return value checks can "
                    "mask errors and lead to system failures."
                ),
            },
            {
                "rule_id": "AUTOSAR-025",
                "cwe_id": "CWE-330",
                "name": "Use of Insufficiently Random Values in AUTOSAR",
                "pattern": r"(Crypto_GenerateRandom|Csm_GenerateRandom|Rng_|Random_)(?!.*(?:CryptoDrv|Certified|True|TRNG))",
                "severity": "critical",
                "description": (
                    "AUTOSAR cryptographic operations must use certified random number generators (TRNG). "
                    "Weak random number generation compromises cryptographic security."
                ),
            },
            {
                "rule_id": "AUTOSAR-026",
                "cwe_id": "CWE-311",
                "name": "Missing Encryption of Sensitive Data in AUTOSAR",
                "pattern": r"(NvM_Write|Rte_Write|Com_SendSignal).*?(?:KEY|PASSWORD|SECRET|PIN|CREDENTIAL)",
                "severity": "critical",
                "description": (
                    "Sensitive data (keys, passwords, secrets) must be encrypted before storage or transmission. "
                    "Unencrypted sensitive data can be intercepted or tampered with."
                ),
            },
            {
                "rule_id": "AUTOSAR-027",
                "cwe_id": "CWE-693",
                "name": "Protection Mechanism Failure in AUTOSAR OS",
                "pattern": r"(ActivateTask|TerminateTask|ChainTask|SetEvent|WaitEvent)(?!.*(?:Check|Verify|Protect))",
                "severity": "high",
                "description": (
                    "AUTOSAR OS task operations should include proper protection mechanisms. "
                    "Missing protection can allow unauthorized task manipulation."
                ),
            },
            {
                "rule_id": "AUTOSAR-028",
                "cwe_id": "CWE-400",
                "name": "Uncontrolled Resource Consumption in AUTOSAR",
                "pattern": r"(OsMemAlloc|malloc|new)\s*\([^)]*(?:user_input|received|buffer|size)",
                "severity": "high",
                "description": (
                    "Memory allocation based on unvalidated user input can lead to resource exhaustion. "
                    "Always validate and limit memory allocation sizes in AUTOSAR applications."
                ),
            },
            {
                "rule_id": "AUTOSAR-029",
                "cwe_id": "CWE-330",
                "name": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
                "pattern": r"(rand\(|random\(|srand\(|rand_r\(|rand48\(|drand48\(|erand48\()",
                "severity": "critical",
                "description": (
                    "Weak PRNGs must not be used for security-critical operations in AUTOSAR. "
                    "Use AUTOSAR Crypto Stack with certified TRNG for all cryptographic operations."
                ),
            },
            {
                "rule_id": "AUTOSAR-030",
                "cwe_id": "CWE-703",
                "name": "Improper Check or Handling of Exceptional Conditions in AUTOSAR State Machine",
                "pattern": r"(StateM_|BswM_StateRequest|SchM_).*?State.*?(?!.*(?:if|switch|Check|Verify))",
                "severity": "medium",
                "description": (
                    "AUTOSAR state machine transitions should validate state changes. "
                    "Unvalidated state transitions can bypass security controls."
                ),
            },
        ]

        # MISRA C/C++ Compliance Violations
        self.misra_patterns = [
            {
                "rule_id": "MISRA-STR-001",
                "cwe_id": "CWE-120",
                "name": "MISRA: Use of Unsafe String Functions",
                "pattern": r"\b(strcpy|strcat|sprintf|gets|scanf)\s*\(",
                "severity": "high",
                "description": (
                    "MISRA C:2012 Rule 21.6 - Use of unsafe string functions can cause buffer overflows. "
                    "Use strncpy, strncat, snprintf, or fgets instead."
                ),
            },
            {
                "rule_id": "MISRA-PTR-002",
                "cwe_id": "CWE-119",
                "name": "MISRA: Pointer Arithmetic",
                "pattern": r"(\w+)\s*\+\+\s*;|(\w+)\s*--\s*;|(\w+)\s*\+\s*\d+|(\w+)\s*-\s*\d+",
                "severity": "medium",
                "description": (
                    "MISRA C:2012 Rule 18.4 - Pointer arithmetic can lead to undefined behavior. "
                    "Use array indexing or structured access methods instead."
                ),
            },
            {
                "rule_id": "MISRA-CONV-003",
                "cwe_id": "CWE-681",
                "name": "MISRA: Potential Implicit Type Conversion",
                "pattern": r"\b(?:uint(?:8|16|32|64)_t|int(?:8|16|32|64)_t|float|double|char)\s+\w+\s*=\s*[^;]+;",
                "severity": "low",
                "description": (
                    "MISRA C:2012 Rule 10.3 - Implicit type conversions in declarations can cause data loss. "
                    "Use explicit casts and validate value ranges where necessary."
                ),
            },
            {
                "rule_id": "MISRA-GOTO-004",
                "cwe_id": "CWE-710",
                "name": "MISRA: Use of goto Statement",
                "pattern": r"\bgoto\s+\w+",
                "severity": "medium",
                "description": (
                    "MISRA C:2012 Rule 15.1 - Use of goto can make code difficult to maintain. "
                    "Refactor to use structured control flow."
                ),
            },
            {
                "rule_id": "MISRA-MEM-005",
                "cwe_id": "CWE-789",
                "name": "MISRA: Dynamic Memory Allocation",
                "pattern": r"\b(malloc|calloc|realloc|free)\s*\(",
                "severity": "high",
                "description": (
                    "MISRA C:2012 Rule 21.3 - Dynamic memory allocation in safety-critical systems "
                    "can lead to memory leaks or fragmentation. Use static allocation when possible."
                ),
            },
        ]

        # Diagnostic Protocol Security (UDS, OBD-II)
        self.diagnostic_patterns = [
            {
                "rule_id": "DIAG-001",
                "cwe_id": "CWE-306",
                "name": "UDS Service Without Authentication",
                "pattern": r"UDS_\w+|Service0x[0-9a-fA-F]+|DiagnosticService",
                "severity": "critical",
                "description": (
                    "UDS (Unified Diagnostic Services) without authentication allows unauthorized access. "
                    "Implement UDS Security Access (Service 0x27) for sensitive diagnostic services."
                ),
            },
            {
                "rule_id": "DIAG-002",
                "cwe_id": "CWE-284",
                "name": "OBD-II Access Without Security",
                "pattern": r"OBD|OBDII|OBD2|PIDs|Mode0[1-9]",
                "severity": "high",
                "description": (
                    "OBD-II diagnostic access without proper security controls can expose vehicle data. "
                    "Implement authentication and access control for diagnostic sessions."
                ),
            },
            {
                "rule_id": "DIAG-003",
                "cwe_id": "CWE-287",
                "name": "Diagnostic Session Control Without Validation",
                "pattern": r"TesterPresent|DiagnosticSessionControl|SessionType",
                "severity": "medium",
                "description": (
                    "Diagnostic session control should validate session transitions. "
                    "Unauthorized session changes can bypass security measures."
                ),
            },
            {
                "rule_id": "DIAG-004",
                "cwe_id": "CWE-306",
                "name": "ECU Reset Without Validation",
                "pattern": r"ECUReset|HardReset|SoftReset|ResetECU",
                "severity": "high",
                "description": (
                    "ECU reset commands should require authentication and proper authorization. "
                    "Unauthorized resets can cause safety-critical system failures."
                ),
            },
        ]

        # Embedded Automotive Security
        self.embedded_patterns = [
            {
                "rule_id": "EMB-001",
                "cwe_id": "CWE-693",
                "name": "Missing Watchdog Timer",
                "pattern": r"Watchdog|WDT|watchdog",
                "severity": "high",
                "description": (
                    "Watchdog timers are critical for safety. Ensure watchdog is properly initialized "
                    "and serviced in all execution paths."
                ),
            },
            {
                "rule_id": "EMB-002",
                "cwe_id": "CWE-494",
                "name": "Insecure Boot Sequence",
                "pattern": r"Boot|bootloader|BootLoader|SecureBoot",
                "severity": "critical",
                "description": (
                    "Boot sequence should implement secure boot with signature verification. "
                    "Unverified boot can allow malicious firmware injection."
                ),
            },
            {
                "rule_id": "EMB-003",
                "cwe_id": "CWE-457",
                "name": "Uninitialized Critical Variables",
                "pattern": r"(?:int|uint|float|double|char)\s+\w+\s*;",
                "severity": "medium",
                "description": (
                    "Uninitialized variables in safety-critical code can cause undefined behavior. "
                    "Always initialize variables before use, especially in embedded systems."
                ),
            },
            {
                "rule_id": "EMB-004",
                "cwe_id": "CWE-119",
                "name": "Missing Stack Overflow Protection",
                "pattern": r"Stack|stack_size|StackSize",
                "severity": "high",
                "description": (
                    "Stack overflow protection (canaries, MPU) should be enabled in embedded systems. "
                    "Stack overflows can lead to code injection or system crashes."
                ),
            },
            {
                "rule_id": "EMB-005",
                "cwe_id": "CWE-362",
                "name": "Race Condition in Interrupt Handlers",
                "pattern": r"__interrupt|ISR|interrupt\s+void|IRQHandler",
                "severity": "high",
                "description": (
                    "Shared data access between ISR and main code without synchronization can cause "
                    "race conditions. Use atomic operations or disable interrupts during critical sections."
                ),
            },
            {
                "rule_id": "EMB-006",
                "cwe_id": "CWE-20",
                "name": "Missing Input Range Validation",
                "pattern": r"(?:sensor|Sensor|ADC|adc|input|Input)\s*\(",
                "severity": "medium",
                "description": (
                    "Sensor inputs should be validated against expected ranges. "
                    "Invalid sensor data can cause incorrect control decisions."
                ),
            },
        ]

        # ISO 26262 Functional Safety Concerns
        self.iso26262_patterns = [
            {
                "rule_id": "ISO26262-001",
                "cwe_id": "CWE-617",
                "name": "Missing Error Detection",
                "pattern": r"assert\s*\(|ASSERT\s*\(",
                "severity": "medium",
                "description": (
                    "ISO 26262 requires comprehensive error detection. Assert statements should not be "
                    "the only error handling mechanism in production code."
                ),
            },
            {
                "rule_id": "ISO26262-002",
                "cwe_id": "CWE-693",
                "name": "Missing Safety State Machine",
                "pattern": r"StateMachine|state_machine|FSM",
                "severity": "medium",
                "description": (
                    "Safety-critical systems should implement proper state machines with error states. "
                    "Ensure all error conditions transition to safe states."
                ),
            },
            {
                "rule_id": "ISO26262-003",
                "cwe_id": "CWE-693",
                "name": "Insufficient Redundancy",
                "pattern": r"redundant|Redundant|backup|Backup",
                "severity": "high",
                "description": (
                    "ISO 26262 ASIL-D systems require redundancy for critical functions. "
                    "Verify that safety-critical paths have appropriate redundancy."
                ),
            },
        ]

        # ISO 21434 Cybersecurity Compliance Patterns
        self.iso21434_patterns = [
            {
                "rule_id": "ISO21434-COMM-001",
                "cwe_id": "CWE-319",
                "name": "ISO 21434: Missing Secure Communication",
                "pattern": (
                    r"(?:CAN|CanIf|CANIF|LIN|FlexRay|Ethernet|DoIP|SoAd|TcpIp)"
                    r".*(?:Send|Receive|Transmit|send|receive|transmit)"
                ),
                "severity": "critical",
                "description": (
                    "ISO 21434 Section 8.4.2 - Secure communication must implement authentication, "
                    "encryption, and integrity checks. Unprotected communication channels are vulnerable to "
                    "eavesdropping, tampering, and replay attacks."
                ),
            },
            {
                "rule_id": "ISO21434-STOR-002",
                "cwe_id": "CWE-312",
                "name": "ISO 21434: Missing Secure Storage",
                "pattern": r"(?:key|secret|credential|password|token).*storage|"
                           r"(?:EEPROM|Flash|NVM).*write|(?:secure|encrypted).*storage",
                "severity": "critical",
                "description": (
                    "ISO 21434 Section 8.4.3 - Cryptographic keys and sensitive data must be stored securely "
                    "using hardware security modules (HSM) or secure elements. Plaintext storage violates "
                    "ISO 21434 requirements."
                ),
            },
            {
                "rule_id": "ISO21434-UPDATE-003",
                "cwe_id": "CWE-345",
                "name": "ISO 21434: Missing Secure Update Mechanism",
                "pattern": r"(?:firmware|software|OTA|over.*air).*update|"
                           r"(?:flash|program).*firmware|(?:bootloader|boot).*update",
                "severity": "critical",
                "description": (
                    "ISO 21434 Section 8.4.4 - Software updates must be authenticated and verified before "
                    "installation. Missing signature verification allows malicious firmware injection."
                ),
            },
            {
                "rule_id": "ISO21434-DETECT-004",
                "cwe_id": "CWE-693",
                "name": "ISO 21434: Missing Attack Detection",
                "pattern": r"(?:intrusion|attack|anomaly|detection|monitoring).*system|(?:IDS|IPS|SIEM)",
                "severity": "high",
                "description": (
                    "ISO 21434 Section 8.4.5 - Attack detection mechanisms must be implemented to identify "
                    "security breaches. Missing detection capabilities violate ISO 21434 requirements."
                ),
            },
            {
                "rule_id": "ISO21434-IR-005",
                "cwe_id": "CWE-778",
                "name": "ISO 21434: Missing Incident Response",
                "pattern": r"(?:incident|response|logging|audit).*handler|(?:security|event).*log",
                "severity": "high",
                "description": (
                    "ISO 21434 Section 8.4.6 - Incident response and logging mechanisms must be implemented. "
                    "Security events must be logged for forensic analysis and compliance."
                ),
            },
            {
                "rule_id": "ISO21434-TARA-006",
                "cwe_id": "CWE-1053",
                "name": "ISO 21434: Missing Threat Analysis (TARA)",
                "pattern": r"(?:TARA|threat.*analysis|risk.*assessment|cybersecurity.*goal)",
                "severity": "medium",
                "description": (
                    "ISO 21434 Section 6 - Threat Analysis and Risk Assessment (TARA) must be performed. "
                    "Code should reference cybersecurity goals derived from TARA."
                ),
            },
            {
                "rule_id": "ISO21434-AC-007",
                "cwe_id": "CWE-284",
                "name": "ISO 21434: Missing Access Control",
                "pattern": r"(?:authentication|authorization|access.*control|permission|role).*check",
                "severity": "critical",
                "description": (
                    "ISO 21434 Section 8.4.1 - Access control mechanisms must be implemented for all "
                    "security-critical functions. Missing access control violates ISO 21434 requirements."
                ),
            },
            {
                "rule_id": "ISO21434-CRYPTO-008",
                "cwe_id": "CWE-327",
                "name": "ISO 21434: Insecure Cryptographic Implementation",
                "pattern": r"(?:MD5|SHA1|DES|RC4|weak.*crypto|insecure.*hash)",
                "severity": "critical",
                "description": (
                    "ISO 21434 Section 8.4.3 - Weak cryptographic algorithms (MD5, SHA1, DES, RC4) must not "
                    "be used. Use AES-256, SHA-256/384/512, or ECC for automotive cybersecurity."
                ),
            },
        ]

        # UN R155 Compliance Patterns
        self.unr155_patterns = [
            {
                "rule_id": "UNR155-CSMS-001",
                "cwe_id": "CWE-1053",
                "name": "UN R155: Missing CSMS Implementation",
                "pattern": r"(?:CSMS|cybersecurity.*management.*system|security.*policy)",
                "severity": "high",
                "description": (
                    "UN R155 Article 4 - Cybersecurity Management System (CSMS) must be implemented. "
                    "Code should demonstrate compliance with CSMS processes and procedures."
                ),
            },
            {
                "rule_id": "UNR155-SUMS-002",
                "cwe_id": "CWE-494",
                "name": "UN R155: Missing SUMS Implementation",
                "pattern": r"(?:SUMS|software.*update.*management|OTA.*management|update.*policy)",
                "severity": "critical",
                "description": (
                    "UN R155 Article 5 - Software Update Management System (SUMS) must be implemented. "
                    "All software updates must be managed through SUMS with proper authentication."
                ),
            },
            {
                "rule_id": "UNR155-V2X-003",
                "cwe_id": "CWE-319",
                "name": "UN R155: Missing Secure Communication (Vehicle-to-X)",
                "pattern": r"(?:V2X|V2V|V2I|vehicle.*to.*|V2G|V2N)",
                "severity": "critical",
                "description": (
                    "UN R155 Article 6.2 - Vehicle-to-X communication must be secured with authentication "
                    "and encryption. Unprotected V2X communication violates UN R155 requirements."
                ),
            },
            {
                "rule_id": "UNR155-PREV-004",
                "cwe_id": "CWE-693",
                "name": "UN R155: Missing Attack Prevention",
                "pattern": r"(?:firewall|IDS|IPS|intrusion.*prevention|attack.*prevention)",
                "severity": "high",
                "description": (
                    "UN R155 Article 6.3 - Attack prevention mechanisms must be implemented. "
                    "Missing prevention capabilities violate UN R155 requirements."
                ),
            },
            {
                "rule_id": "UNR155-BOOT-005",
                "cwe_id": "CWE-1326",
                "name": "UN R155: Missing Secure Boot",
                "pattern": r"(?:secure.*boot|boot.*verification|firmware.*signature|chain.*of.*trust)",
                "severity": "critical",
                "description": (
                    "UN R155 Article 6.4 - Secure boot with signature verification must be implemented. "
                    "Unverified boot allows malicious firmware injection."
                ),
            },
            {
                "rule_id": "UNR155-VULN-006",
                "cwe_id": "CWE-1104",
                "name": "UN R155: Missing Vulnerability Management",
                "pattern": r"(?:vulnerability.*management|CVE.*tracking|security.*patch|vuln.*database)",
                "severity": "high",
                "description": (
                    "UN R155 Article 7 - Vulnerability management process must be implemented. "
                    "Known vulnerabilities must be tracked and patched according to CSMS."
                ),
            },
            {
                "rule_id": "UNR155-IR-007",
                "cwe_id": "CWE-778",
                "name": "UN R155: Missing Incident Response Plan",
                "pattern": r"(?:incident.*response|security.*incident|breach.*handling|forensic.*analysis)",
                "severity": "high",
                "description": (
                    "UN R155 Article 8 - Incident response plan must be implemented. "
                    "Security incidents must be detected, logged, and responded to according to CSMS."
                ),
            },
        ]

    def scan_code(
        self,
        code: str,
        file_path: Optional[str] = None,
        language: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Scan automotive code for security vulnerabilities."""
        if not code:
            return []

        automotive_type = self._determine_automotive_type(code, file_path, language)
        if not automotive_type:
            return []

        pattern_sets = {
            "can_bus": self.can_bus_patterns,
            "autosar": self.autosar_patterns,
            "misra": self.misra_patterns,
            "diagnostic": self.diagnostic_patterns,
            "embedded": self.embedded_patterns,
            "iso26262": self.iso26262_patterns,
            "iso21434": self.iso21434_patterns,
            "unr155": self.unr155_patterns,
        }

        # use a set of active groups to avoid adding ISO/UNR patterns multiple times
        active_groups = set()

        if automotive_type in ["can_bus", "autosar", "embedded"]:
            active_groups.update(["can_bus", "autosar", "embedded", "iso26262", "iso21434", "unr155"])

        if automotive_type == "misra" or language in ["cpp", "c"]:
            active_groups.update(["misra", "iso21434", "unr155"])

        if automotive_type in ["diagnostic", "autosar"]:
            active_groups.update(["diagnostic", "iso21434", "unr155"])

        all_patterns: List[Dict[str, Any]] = []
        for group in active_groups:
            all_patterns.extend(pattern_sets.get(group, []))

        vulnerabilities: List[Dict[str, Any]] = []
        lines = code.splitlines()

        for pattern in all_patterns:
            regex = re.compile(pattern["pattern"], re.IGNORECASE)
            for match in regex.finditer(code):
                line_number = code[: match.start()].count("\n") + 1
                vulnerabilities.append(
                    {
                        "type": pattern["name"],
                        "rule_id": pattern["rule_id"],
                        "cwe_id": pattern["cwe_id"],
                        "severity": pattern["severity"],
                        "description": pattern["description"],
                        "line_number": line_number,
                        "code_snippet": self._get_code_snippet(lines, line_number),
                        "match": match.group(0),
                        "scanner": "automotive",
                        "file_path": file_path,
                    }
                )

        # de-duplicate findings (same rule, line, match, file)
        unique: Dict[tuple, Dict[str, Any]] = {}
        for v in vulnerabilities:
            key = (v["rule_id"], v["line_number"], v["match"], v.get("file_path"))
            if key not in unique:
                unique[key] = v

        return list(unique.values())

    def _determine_automotive_type(
        self, code: str, file_path: Optional[str], language: Optional[str]
    ) -> Optional[str]:
        """Determine if code is automotive-related and what type."""
        path = (file_path or "").lower()
        suffix = Path(path).suffix.lower() if path else ""
        code_lower = code.lower()

        # AUTOSAR - Enhanced detection
        autosar_indicators = [
            "rte_", "rte.", "bswm_", "bsm_", "ecum_", "comm_", 
            "com_", "canif_", "cannm_", "secoc_", "keym_", 
            "dcm_", "pdura_", "schm_", "statem_", "wdgm_",
            "nvm_", "nvram", "firewall_", "fwm_", "os_",
            "csm_", "crypto_", "cryif_", "doip_",
            "autosar", "arxml", "swc", "application_sw_component",
            "runtimeenvironment", "basicsoftware", "diagnosticcommunicationmanager"
        ]
        if any(indicator in code_lower or indicator in path for indicator in autosar_indicators):
            return "autosar"
        
        # Also check for AUTOSAR-specific function calls (case-insensitive)
        autosar_function_patterns = [
            r"rte_(write|read|call)\s*\(",
            r"(com_|canif_|ecum_|bswm_|secoc_|keym_|dcm_|pdura_|nvm_|wdgm_|schm_|statem_)\w+\s*\(",
        ]
        import re
        for pattern in autosar_function_patterns:
            if re.search(pattern, code_lower):
                return "autosar"

        # CAN bus
        can_indicators = [
            "can_", "canif_", "can_id", "canid", "can message", "canbus",
            "canopen", "canfd"
        ]
        if any(indicator in code_lower for indicator in can_indicators):
            return "can_bus"

        # Diagnostic protocols
        diagnostic_indicators = [
            "uds_", "obd", "diagnostic", "testerpresent", "ecureset",
            "service0x", "did_", "dtc_"
        ]
        if any(indicator in code_lower for indicator in diagnostic_indicators):
            return "diagnostic"

        # Embedded automotive
        embedded_indicators = [
            "ecu", "ecm", "tcm", "bcm", "watchdog", "bootloader",
            "isr", "interrupt", "sensor", "actuator"
        ]
        if any(indicator in code_lower for indicator in embedded_indicators):
            return "embedded"

        # File-based hints
        if suffix in [".c", ".cpp", ".h", ".hpp"]:
            if any(token in path for token in ["ecu", "autosar", "can", "diagnostic", "embedded", "vehicle"]):
                return "embedded"
            if language in ["cpp", "c"]:
                return "misra"

        if suffix == ".arxml" or "arxml" in path:
            return "autosar"

        if suffix in [".xml", ".yaml", ".yml"]:
            if any(token in path for token in ["ecu", "autosar", "can", "diagnostic", "vehicle"]):
                return "autosar"

        return None

    def _get_code_snippet(self, lines: List[str], line_number: int, context: int = 3) -> str:
        """Get code snippet around a line number."""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return "\n".join(lines[start:end])

    # generate_compliance_report stays the same, it will automatically carry rule_id/cwe_id inside vuln dicts
