# Kubernetes Security Scanner for Nuclear Facilities

**IAEA NSS-17 Compliance Scanner for Container Orchestration Environments**

An advanced security scanning and compliance assessment tool implementing IAEA Nuclear Security Series (NSS-17) guidelines for Kubernetes environments at nuclear facilities. The scanner enforces defense-in-depth security principles, performs automated risk assessment with nuclear facility-specific threat modeling, and generates compliance reports against multiple international frameworks.

## Compliance Frameworks

| Framework | Coverage |
|-----------|----------|
| IAEA Nuclear Security Series (NSS-17) | Computer security at nuclear facilities |
| ISO/IEC 27001:2022 | Information security management systems |
| CIS Kubernetes Benchmark | Container orchestration security |
| NIST Cybersecurity Framework | Critical infrastructure protection |

## Security Level Classification

The scanner classifies findings according to IAEA nuclear facility security levels:

- **Level 1** — Protection Systems (Highest Security): Reactor protection, safety shutdown systems
- **Level 2** — Safety Related Systems: Monitoring, emergency response
- **Level 3** — Process Control Systems: Operational technology
- **Level 4** — Administrative Systems: Business operations
- **Level 5** — Office Automation (Lowest Security)

## Architecture

```
k8s_nuclear_security_scanner.py     # Core scanner: security policies, finding engine, compliance checks
setup_nuclear_scanner.py            # Setup and orchestration script
demo_script.py                      # Demonstration with simulated nuclear facility K8s manifests
generate_desktop_reports.py         # Multi-format report generator (JSON, YAML, CSV, TXT)
nuclear_facility_manifests.yaml     # Sample K8s manifests simulating nuclear facility workloads
```

## Output Formats

- `nuclear_security_report.json` — Machine-readable findings with severity and compliance mapping
- `nuclear_security_report.yaml` — YAML-formatted findings for integration with CI/CD pipelines
- `nuclear_security_report.text` — Human-readable executive summary
- `security_findings.csv` — Tabular findings for spreadsheet analysis

## Key Features

- **Privileged container detection** in safety-critical namespaces
- **Network policy enforcement** for air-gapped nuclear facility segments
- **Security context analysis** across all IAEA security levels
- **Automated remediation recommendations** with priority ranking
- **Multi-framework compliance mapping** per finding

## Dependencies

```
pyyaml
```

> Minimal dependencies by design — suitable for deployment in restricted/air-gapped environments.

## Usage

```bash
pip install pyyaml
python setup_nuclear_scanner.py
```

Or run the scanner directly:

```bash
python k8s_nuclear_security_scanner.py
python generate_desktop_reports.py
```

## Sample Output

```
NUCLEAR FACILITY SECURITY ASSESSMENT
=====================================
Total Security Issues Identified: 5
  CRITICAL: 2 findings
  HIGH:     1 finding
  MEDIUM:   2 findings

Nuclear Security Level Impact:
  Level 1 - Protection Systems: 1 finding
  Level 2 - Safety Related:     1 finding
  Level 3 - Process Control:    2 findings
  Level 4 - Administrative:     1 finding
```

## Methodology

1. **Manifest Parsing**: Loads Kubernetes pod specs, service definitions, network policies, and RBAC configurations
2. **Policy Engine**: Evaluates each resource against IAEA NSS-17 security controls mapped to Kubernetes primitives
3. **Risk Scoring**: Assigns severity (CRITICAL/HIGH/MEDIUM/LOW) weighted by nuclear security level
4. **Compliance Mapping**: Cross-references findings against ISO 27001, CIS Benchmarks, and NIST CSF controls
5. **Report Generation**: Produces multi-format reports with executive summary, detailed findings, and remediation steps

## Disclaimer

This tool simulates nuclear facility Kubernetes environments for security assessment demonstration purposes. It is not certified for use in actual nuclear facility environments. Real nuclear facility deployments require additional regulatory approval and validation.

## Author

**Dr. Mosab Hawarey**
PhD, Geodetic & Photogrammetric Engineering | MSc, Geomatics (Purdue) | MBA (Wales)

- GitHub: [github.com/mhawarey](https://github.com/mhawarey)
- ORCID: [0000-0001-7846-951X](https://orcid.org/0000-0001-7846-951X)

## License

MIT License
