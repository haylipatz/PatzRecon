# PatzRecon
PatzRecon: Educational Reconnaissance Framework<br>
PatzRecon is a Python-based, modular reconnaissance tool designed to assist security practitioners in identifying potential vulnerability classes within controlled, authorized environments. It is not an exploitation framework; it performs structured probing to reduce manual enumeration time during penetration testing engagements or CTF challenges.

# Core Philosophy:
Authorization First: The tool requires explicit target definition (URL/IP) and assumes the user has legal authority to test the target.
<br>No False Positives (Best Effort): Probes are designed to be deterministic where possible (e.g., checking for specific headers, status codes, or known file paths) rather than relying on heuristic guesses that often lead to false positives.
<br>Modularity: Each of the 31 PortSwigger Web Security Academy topics is handled by an independent module, allowing for easy updates and maintenance.

# How It Works
PatzRecon operates as a "Lab-Scope Recon Aide." Instead of blindly attacking a target, it systematically fingerprints the application structure and behavior.
<br>1. Input: The user provides a target URL (e.g., https://example.net/) and optional credentials or session cookies.
<br>2. Orchestration: The main engine (PatzRecon.py) loads all 31 vulnerability modules.
<br>3. Probing: Each module executes a series of non-destructive checks:
<br>Passive Analysis: Inspects HTML source, HTTP headers, and JavaScript files for clues (e.g., X-Powered-By, CSRF tokens, CORS headers).
<br>Active Fingerprinting: Sends specific, safe requests to detect behaviors (e.g., sending a malformed JSON body to check for deserialization errors, or requesting /admin to check for access control responses).
<br>4. Reporting: Results are aggregated into a structured report indicating which vulnerability classes are likely present based on observed indicators.
<br><br>Example Scenario:
<br>Target: A PortSwigger Lab ID acme123.
<br>Action: PatzRecon sends a request to the homepage.
<br>Module: SQL Injection: Checks if input parameters reflect in error messages or if specific SQL keywords trigger database errors.
<br>Module: CORS: Checks if the Access-Control-Allow-Origin header is set to * or reflects the Origin header improperly.
<br>Output: "Potential SQL Injection detected in 'productId' parameter. CORS misconfiguration identified."
<br>
# Architecture: Modular Plugin System
The project is split into a main orchestrator and independent vulnerability modules. This follows the Strategy Pattern and Plugin Architecture.
Directory Structure
