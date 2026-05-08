# PatzRecon
PatzRecon: Educational Reconnaissance Framework
PatzRecon is a Python-based, modular reconnaissance tool designed to assist security practitioners in identifying potential vulnerability classes within controlled, authorized environments. It is not an exploitation framework; it performs structured probing to reduce manual enumeration time during penetration testing engagements or CTF challenges.
Core Philosophy:
Authorization First: The tool requires explicit target definition (URL/IP) and assumes the user has legal authority to test the target.
No False Positives (Best Effort): Probes are designed to be deterministic where possible (e.g., checking for specific headers, status codes, or known file paths) rather than relying on heuristic guesses that often lead to false positives.
Modularity: Each of the 31 PortSwigger Web Security Academy topics is handled by an independent module, allowing for easy updates and maintenance.
