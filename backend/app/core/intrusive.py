"""
Classification of scanner modules by intrusiveness.
Intrusive modules generate attack-like traffic (active injection payloads,
brute-force attempts, large wordlists) and can be flagged by a target's
WAF/IDS or trigger account lockouts. They require Target.intrusive_testing_confirmed
in addition to the regular Target.authorization_confirmed.
"""

PASSIVE_MODULES = {
    "headers", "tls", "cookies", "cors", "fingerprint",
    "subdomains", "owasp", "port_scan",
}

INTRUSIVE_MODULES = {
    "sqli_xss", "dirbuster", "auth_bruteforce", "port_scan_deep",
}

ALL_MODULES = PASSIVE_MODULES | INTRUSIVE_MODULES
