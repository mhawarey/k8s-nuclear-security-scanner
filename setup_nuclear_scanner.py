#!/usr/bin/env python3
"""
Setup and Run Script for Nuclear Facility Kubernetes Security Scanner
This script sets up all required files and runs the complete demonstration
"""

import os
import sys
from pathlib import Path
import subprocess

# File contents to be created
FILES_TO_CREATE = {
    "k8s_nuclear_security_scanner.py": '''#!/usr/bin/env python3
"""
Kubernetes Security Scanner for Nuclear Facilities
Based on IAEA Nuclear Security Series guidelines and ISO 27001 compliance
Simulates security scanning and policy enforcement for critical infrastructure
"""

import argparse
import json
import yaml
import logging
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import sys
import os
from pathlib import Path
import subprocess
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    """Security levels based on IAEA nuclear facility classification"""
    LEVEL_1 = "Level 1 - Protection Systems (Highest Security)"
    LEVEL_2 = "Level 2 - Safety Related Systems"
    LEVEL_3 = "Level 3 - Process Control Systems"
    LEVEL_4 = "Level 4 - Administrative Systems"
    LEVEL_5 = "Level 5 - Office Automation (Lowest Security)"

class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ComplianceFramework(Enum):
    """Compliance frameworks for nuclear facilities"""
    IAEA_NSS = "IAEA Nuclear Security Series"
    ISO_27001 = "ISO/IEC 27001:2022"
    CIS_KUBERNETES = "CIS Kubernetes Benchmark"
    NIST_CSF = "NIST Cybersecurity Framework"

@dataclass
class SecurityFinding:
    """Represents a security finding from the scan"""
    id: str
    title: str
    description: str
    severity: Severity
    security_level: SecurityLevel
    compliance_frameworks: List[ComplianceFramework]
    resource_type: str
    resource_name: str
    namespace: str
    remediation: str
    references: List[str]
    timestamp: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'security_level': self.security_level.value,
            'compliance_frameworks': [f.value for f in self.compliance_frameworks],
            'resource_type': self.resource_type,
            'resource_name': self.resource_name,
            'namespace': self.namespace,
            'remediation': self.remediation,
            'references': self.references,
            'timestamp': self.timestamp
        }

class SecurityPolicy:
    """Nuclear facility security policies based on IAEA guidelines"""
    
    @staticmethod
    def get_security_level(namespace: str, resource_type: str) -> SecurityLevel:
        """Determine security level based on namespace and resource type"""
        # Simulate nuclear facility zone classification
        if any(keyword in namespace.lower() for keyword in ['protection', 'safety', 'reactor', 'control']):
            if 'critical' in namespace.lower() or 'reactor' in namespace.lower():
                return SecurityLevel.LEVEL_1
            return SecurityLevel.LEVEL_2
        elif any(keyword in namespace.lower() for keyword in ['process', 'monitor', 'alarm']):
            return SecurityLevel.LEVEL_3
        elif any(keyword in namespace.lower() for keyword in ['admin', 'management', 'work']):
            return SecurityLevel.LEVEL_4
        else:
            return SecurityLevel.LEVEL_5
    
    @staticmethod
    def get_prohibited_configurations() -> Dict[str, Any]:
        """Get prohibited configurations for nuclear facilities"""
        return {
            'privileged_containers': {
                'allowed': False,
                'reason': 'IAEA NSS-17: No privileged access in safety systems'
            },
            'host_network': {
                'allowed': False,
                'reason': 'Network isolation required per defense-in-depth'
            },
            'host_pid': {
                'allowed': False,
                'reason': 'Process isolation critical for safety systems'
            },
            'root_containers': {
                'allowed': False,
                'reason': 'Principle of least privilege violation'
            },
            'external_traffic': {
                'level_1_allowed': False,
                'level_2_allowed': False,
                'reason': 'Air-gapped networks required for critical systems'
            }
        }

class KubernetesSecurityScanner:
    """Main security scanner for Kubernetes in nuclear facilities"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.findings: List[SecurityFinding] = []
        self.policies = SecurityPolicy()
        self.scan_timestamp = datetime.now(timezone.utc).isoformat()
        
    def scan_cluster(self, manifest_dir: str = None) -> List[SecurityFinding]:
        """Scan Kubernetes cluster or manifests for security issues"""
        logger.info("Starting nuclear facility security scan...")
        
        if manifest_dir:
            self._scan_manifests(manifest_dir)
        else:
            self._scan_live_cluster()
            
        logger.info(f"Security scan completed. Found {len(self.findings)} issues.")
        return self.findings
    
    def _scan_manifests(self, manifest_dir: str):
        """Scan YAML manifests in directory"""
        manifest_path = Path(manifest_dir)
        if not manifest_path.exists():
            logger.error(f"Manifest directory {manifest_dir} not found")
            return
            
        for yaml_file in manifest_path.glob("*.yaml"):
            try:
                with open(yaml_file, 'r') as f:
                    docs = yaml.safe_load_all(f)
                    for doc in docs:
                        if doc:
                            self._analyze_resource(doc, str(yaml_file))
            except Exception as e:
                logger.error(f"Error processing {yaml_file}: {e}")
    
    def _scan_live_cluster(self):
        """Scan live Kubernetes cluster"""
        try:
            # Check if kubectl is available
            result = subprocess.run(['kubectl', 'version', '--client'], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                logger.warning("kubectl not available, using simulated data")
                self._generate_simulated_findings()
                return
                
            # Get all resources
            namespaces = self._get_namespaces()
            for ns in namespaces:
                self._scan_namespace(ns)
                
        except Exception as e:
            logger.error(f"Error scanning live cluster: {e}")
            self._generate_simulated_findings()
    
    def _get_namespaces(self) -> List[str]:
        """Get list of namespaces"""
        try:
            result = subprocess.run(['kubectl', 'get', 'namespaces', '-o', 'json'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return [item['metadata']['name'] for item in data['items']]
        except:
            pass
        
        # Return simulated nuclear facility namespaces
        return [
            'reactor-protection',
            'safety-systems', 
            'process-control',
            'administrative',
            'office-automation',
            'default'
        ]
    
    def _scan_namespace(self, namespace: str):
        """Scan specific namespace"""
        resource_types = ['pods', 'deployments', 'services', 'networkpolicies']
        
        for resource_type in resource_types:
            try:
                result = subprocess.run([
                    'kubectl', 'get', resource_type, '-n', namespace, '-o', 'json'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    for item in data.get('items', []):
                        self._analyze_resource(item, f"{namespace}/{resource_type}")
            except Exception as e:
                logger.debug(f"Error scanning {resource_type} in {namespace}: {e}")
    
    def _analyze_resource(self, resource: Dict[str, Any], source: str):
        """Analyze a Kubernetes resource for security issues"""
        if not resource or 'kind' not in resource:
            return
            
        kind = resource['kind']
        metadata = resource.get('metadata', {})
        name = metadata.get('name', 'unknown')
        namespace = metadata.get('namespace', 'default')
        
        # Determine security level
        security_level = self.policies.get_security_level(namespace, kind)
        
        if kind == 'Pod':
            self._check_pod_security(resource, security_level)
        elif kind == 'Deployment':
            self._check_deployment_security(resource, security_level)
        elif kind == 'Service':
            self._check_service_security(resource, security_level)
        elif kind == 'NetworkPolicy':
            self._check_network_policy(resource, security_level)
    
    def _check_pod_security(self, pod: Dict[str, Any], security_level: SecurityLevel):
        """Check pod security configuration"""
        metadata = pod.get('metadata', {})
        spec = pod.get('spec', {})
        name = metadata.get('name', 'unknown')
        namespace = metadata.get('namespace', 'default')
        
        # Check for privileged containers
        for container in spec.get('containers', []):
            security_context = container.get('securityContext', {})
            if security_context.get('privileged', False):
                self._add_finding(
                    'PRIV-001',
                    'Privileged Container Detected',
                    f'Container {container.get("name", "unknown")} is running with privileged access',
                    Severity.CRITICAL,
                    security_level,
                    [ComplianceFramework.IAEA_NSS, ComplianceFramework.ISO_27001],
                    'Pod',
                    name,
                    namespace,
                    'Remove privileged: true from container securityContext',
                    ['IAEA NSS-17 Section 5.5.1', 'ISO 27001 A.13.1.3']
                )
        
        # Check for host network access
        if spec.get('hostNetwork', False):
            severity = Severity.CRITICAL if security_level in [SecurityLevel.LEVEL_1, SecurityLevel.LEVEL_2] else Severity.HIGH
            self._add_finding(
                'NET-001',
                'Host Network Access',
                'Pod is configured to use host network',
                severity,
                security_level,
                [ComplianceFramework.IAEA_NSS, ComplianceFramework.CIS_KUBERNETES],
                'Pod',
                name,
                namespace,
                'Remove hostNetwork: true from pod specification',
                ['CIS Kubernetes 5.1.4', 'IAEA NSS-17 Defense in Depth']
            )
        
        # Check for missing security context
        pod_security_context = spec.get('securityContext', {})
        if not pod_security_context:
            self._add_finding(
                'SEC-001',
                'Missing Pod Security Context',
                'Pod does not define security context',
                Severity.MEDIUM,
                security_level,
                [ComplianceFramework.CIS_KUBERNETES, ComplianceFramework.ISO_27001],
                'Pod',
                name,
                namespace,
                'Add securityContext with appropriate settings',
                ['CIS Kubernetes 5.1.1']
            )
    
    def _check_deployment_security(self, deployment: Dict[str, Any], security_level: SecurityLevel):
        """Check deployment security configuration"""
        metadata = deployment.get('metadata', {})
        spec = deployment.get('spec', {})
        template = spec.get('template', {})
        
        # Analyze pod template
        if template:
            # Create a pod-like structure for analysis
            pod_spec = {
                'kind': 'Pod',
                'metadata': template.get('metadata', metadata),
                'spec': template.get('spec', {})
            }
            self._check_pod_security(pod_spec, security_level)
    
    def _check_service_security(self, service: Dict[str, Any], security_level: SecurityLevel):
        """Check service security configuration"""
        metadata = service.get('metadata', {})
        spec = service.get('spec', {})
        name = metadata.get('name', 'unknown')
        namespace = metadata.get('namespace', 'default')
        
        # Check for LoadBalancer or NodePort services in critical systems
        service_type = spec.get('type', 'ClusterIP')
        if service_type in ['LoadBalancer', 'NodePort'] and security_level in [SecurityLevel.LEVEL_1, SecurityLevel.LEVEL_2]:
            self._add_finding(
                'SVC-001',
                'External Service Exposure in Critical System',
                f'Service of type {service_type} exposes critical system externally',
                Severity.CRITICAL,
                security_level,
                [ComplianceFramework.IAEA_NSS],
                'Service',
                name,
                namespace,
                'Use ClusterIP type for internal communication only',
                ['IAEA NSS-17 Section 5.5.1: Level 1 systems isolation']
            )
    
    def _check_network_policy(self, policy: Dict[str, Any], security_level: SecurityLevel):
        """Check network policy configuration"""
        metadata = policy.get('metadata', {})
        spec = policy.get('spec', {})
        name = metadata.get('name', 'unknown')
        namespace = metadata.get('namespace', 'default')
        
        # Check if critical namespaces have network policies
        if security_level in [SecurityLevel.LEVEL_1, SecurityLevel.LEVEL_2]:
            ingress_rules = spec.get('ingress', [])
            if not ingress_rules:
                self._add_finding(
                    'NET-002',
                    'No Network Ingress Policy',
                    'Critical system lacks ingress network policies',
                    Severity.HIGH,
                    security_level,
                    [ComplianceFramework.IAEA_NSS, ComplianceFramework.CIS_KUBERNETES],
                    'NetworkPolicy',
                    name,
                    namespace,
                    'Define explicit ingress rules for critical systems',
                    ['IAEA NSS-17 Defense in Depth', 'CIS Kubernetes 5.3.2']
                )
    
    def _add_finding(self, finding_id: str, title: str, description: str, 
                    severity: Severity, security_level: SecurityLevel,
                    frameworks: List[ComplianceFramework], resource_type: str,
                    resource_name: str, namespace: str, remediation: str,
                    references: List[str]):
        """Add a security finding"""
        finding = SecurityFinding(
            id=finding_id,
            title=title,
            description=description,
            severity=severity,
            security_level=security_level,
            compliance_frameworks=frameworks,
            resource_type=resource_type,
            resource_name=resource_name,
            namespace=namespace,
            remediation=remediation,
            references=references,
            timestamp=self.scan_timestamp
        )
        self.findings.append(finding)
    
    def _generate_simulated_findings(self):
        """Generate simulated findings for demonstration"""
        logger.info("Generating simulated nuclear facility security findings...")
        
        # Simulated critical findings
        self._add_finding(
            'SIM-001',
            'Privileged Container in Reactor Protection System',
            'Container reactor-controller is running with privileged access in critical safety system',
            Severity.CRITICAL,
            SecurityLevel.LEVEL_1,
            [ComplianceFramework.IAEA_NSS, ComplianceFramework.ISO_27001],
            'Pod',
            'reactor-controller-7d4b8',
            'reactor-protection',
            'Remove privileged: true and implement least-privilege access',
            ['IAEA NSS-17 Section 5.5.1', 'ISO 27001 A.13.1.3']
        )
        
        self._add_finding(
            'SIM-002',
            'External Network Access in Safety System',
            'Safety monitoring system exposed via LoadBalancer service',
            Severity.CRITICAL,
            SecurityLevel.LEVEL_2,
            [ComplianceFramework.IAEA_NSS, ComplianceFramework.CIS_KUBERNETES],
            'Service',
            'safety-monitor-lb',
            'safety-systems',
            'Change service type to ClusterIP and implement network policies',
            ['IAEA NSS-17 Air-gap requirements', 'CIS Kubernetes 5.1.4']
        )
        
        self._add_finding(
            'SIM-003',
            'Missing Network Policies in Control Systems',
            'Process control namespace lacks network segmentation policies',
            Severity.HIGH,
            SecurityLevel.LEVEL_3,
            [ComplianceFramework.IAEA_NSS, ComplianceFramework.CIS_KUBERNETES],
            'NetworkPolicy',
            'missing',
            'process-control',
            'Implement network policies for zone-based access control',
            ['IAEA NSS-17 Defense in Depth', 'CIS Kubernetes 5.3.2']
        )
        
        self._add_finding(
            'SIM-004',
            'Container Running as Root',
            'Administrative container running with UID 0 (root)',
            Severity.MEDIUM,
            SecurityLevel.LEVEL_4,
            [ComplianceFramework.ISO_27001, ComplianceFramework.CIS_KUBERNETES],
            'Pod',
            'admin-dashboard-9f2c1',
            'administrative',
            'Set runAsUser to non-root UID in securityContext',
            ['CIS Kubernetes 5.1.1', 'ISO 27001 A.9.2.3']
        )
        
        self._add_finding(
            'SIM-005',
            'Insecure Image Repository',
            'Container image pulled from unverified public registry',
            Severity.MEDIUM,
            SecurityLevel.LEVEL_3,
            [ComplianceFramework.IAEA_NSS, ComplianceFramework.ISO_27001],
            'Pod',
            'process-monitor-1a3d',
            'process-control',
            'Use verified internal registry with signed images',
            ['IAEA NSS-17 Supply Chain Security', 'ISO 27001 A.14.2.1']
        )
    
    def generate_report(self, output_format: str = 'json') -> str:
        """Generate security report"""
        if output_format.lower() == 'json':
            return self._generate_json_report()
        elif output_format.lower() == 'yaml':
            return self._generate_yaml_report()
        else:
            return self._generate_text_report()
    
    def _generate_json_report(self) -> str:
        """Generate JSON format report"""
        report = {
            'scan_metadata': {
                'timestamp': self.scan_timestamp,
                'scanner_version': '1.0.0',
                'compliance_frameworks': [f.value for f in ComplianceFramework],
                'total_findings': len(self.findings)
            },
            'summary': self._generate_summary(),
            'findings': [f.to_dict() for f in self.findings]
        }
        return json.dumps(report, indent=2)
    
    def _generate_yaml_report(self) -> str:
        """Generate YAML format report"""
        report_data = json.loads(self._generate_json_report())
        return yaml.dump(report_data, default_flow_style=False)
    
    def _generate_text_report(self) -> str:
        """Generate human-readable text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("KUBERNETES SECURITY SCAN REPORT - NUCLEAR FACILITY")
        lines.append("=" * 80)
        lines.append(f"Scan Time: {self.scan_timestamp}")
        lines.append(f"Total Findings: {len(self.findings)}")
        lines.append("")
        
        # Summary by severity
        summary = self._generate_summary()
        lines.append("SEVERITY BREAKDOWN:")
        lines.append("-" * 20)
        for severity, count in summary['by_severity'].items():
            lines.append(f"{severity}: {count}")
        lines.append("")
        
        # Summary by security level
        lines.append("SECURITY LEVEL BREAKDOWN:")
        lines.append("-" * 30)
        for level, count in summary['by_security_level'].items():
            lines.append(f"{level}: {count}")
        lines.append("")
        
        # Detailed findings
        lines.append("DETAILED FINDINGS:")
        lines.append("=" * 20)
        for finding in sorted(self.findings, key=lambda x: x.severity.value):
            lines.append("")
            lines.append(f"ID: {finding.id}")
            lines.append(f"Title: {finding.title}")
            lines.append(f"Severity: {finding.severity.value}")
            lines.append(f"Security Level: {finding.security_level.value}")
            lines.append(f"Resource: {finding.resource_type}/{finding.resource_name}")
            lines.append(f"Namespace: {finding.namespace}")
            lines.append(f"Description: {finding.description}")
            lines.append(f"Remediation: {finding.remediation}")
            lines.append(f"References: {', '.join(finding.references)}")
            lines.append("-" * 40)
        
        return '\\n'.join(lines)
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        summary = {
            'by_severity': {},
            'by_security_level': {},
            'by_compliance_framework': {}
        }
        
        for finding in self.findings:
            # Count by severity
            severity = finding.severity.value
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Count by security level
            level = finding.security_level.value
            summary['by_security_level'][level] = summary['by_security_level'].get(level, 0) + 1
            
            # Count by compliance framework
            for framework in finding.compliance_frameworks:
                fw_name = framework.value
                summary['by_compliance_framework'][fw_name] = summary['by_compliance_framework'].get(fw_name, 0) + 1
        
        return summary

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Kubernetes Security Scanner for Nuclear Facilities'
    )
    parser.add_argument(
        '--manifests', '-m',
        help='Directory containing Kubernetes YAML manifests to scan'
    )
    parser.add_argument(
        '--output', '-o',
        choices=['json', 'yaml', 'text'],
        default='text',
        help='Output format (default: text)'
    )
    parser.add_argument(
        '--output-file', '-f',
        help='Write report to file instead of stdout'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize scanner
    scanner = KubernetesSecurityScanner()
    
    # Perform scan
    findings = scanner.scan_cluster(args.manifests)
    
    # Generate report
    report = scanner.generate_report(args.output)
    
    # Output report
    if args.output_file:
        with open(args.output_file, 'w') as f:
            f.write(report)
        logger.info(f"Report written to {args.output_file}")
    else:
        print(report)
    
    # Exit with error code if critical findings
    critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    if critical_count > 0:
        logger.error(f"Found {critical_count} critical security issues!")
        sys.exit(1)
    
    logger.info("Security scan completed successfully")

if __name__ == '__main__':
    main()
''',

    "nuclear_facility_manifests.yaml": '''# Nuclear Facility Simulation Manifests
# These manifests simulate various systems in a nuclear facility
# with intentional security misconfigurations for testing

---
# Namespace: Reactor Protection System (Level 1)
apiVersion: v1
kind: Namespace
metadata:
  name: reactor-protection
  labels:
    security-level: "level-1"
    facility-zone: "critical"
---
# Namespace: Safety Systems (Level 2)
apiVersion: v1
kind: Namespace
metadata:
  name: safety-systems
  labels:
    security-level: "level-2"
    facility-zone: "safety"
---
# CRITICAL ISSUE: Privileged container in reactor protection system
apiVersion: apps/v1
kind: Deployment
metadata:
  name: reactor-controller
  namespace: reactor-protection
spec:
  replicas: 2
  selector:
    matchLabels:
      app: reactor-controller
  template:
    metadata:
      labels:
        app: reactor-controller
    spec:
      containers:
      - name: reactor-controller
        image: nuclear-registry.local/reactor-controller:v2.1.3
        securityContext:
          privileged: true  # SECURITY ISSUE: Privileged container
          runAsUser: 0      # SECURITY ISSUE: Running as root
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
---
# CRITICAL ISSUE: Safety system exposed externally
apiVersion: v1
kind: Service
metadata:
  name: safety-monitor-external
  namespace: safety-systems
spec:
  type: LoadBalancer  # SECURITY ISSUE: External exposure
  ports:
  - port: 8080
    targetPort: 8080
  selector:
    app: safety-monitor
---
# Safety monitoring deployment (Level 2)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: safety-monitor
  namespace: safety-systems
spec:
  replicas: 1
  selector:
    matchLabels:
      app: safety-monitor
  template:
    metadata:
      labels:
        app: safety-monitor
    spec:
      hostNetwork: true  # SECURITY ISSUE: Host network access
      containers:
      - name: safety-monitor
        image: docker.io/public/safety-monitor:latest  # SECURITY ISSUE: Public registry
        env:
        - name: DATABASE_PASSWORD
          value: "password123"  # SECURITY ISSUE: Hardcoded password
''',

    "demo_script.py": '''#!/usr/bin/env python3
"""
Demo script for Nuclear Facility Kubernetes Security Scanner
This script sets up a simulation environment and demonstrates
the security scanning capabilities for IAEA-compliant systems.
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path
import json
import yaml
import subprocess
from typing import Dict, Any

# Sample nuclear facility manifests with security issues
SAMPLE_MANIFESTS = {
    "namespaces.yaml": """
apiVersion: v1
kind: Namespace
metadata:
  name: reactor-protection
  labels:
    security-level: "level-1"
    facility-zone: "critical"
---
apiVersion: v1
kind: Namespace
metadata:
  name: safety-systems
  labels:
    security-level: "level-2"
    facility-zone: "safety"
---
apiVersion: v1
kind: Namespace
metadata:
  name: process-control
  labels:
    security-level: "level-3"
    facility-zone: "operational"
""",
    
    "reactor-systems.yaml": """
# CRITICAL: Privileged container in reactor protection
apiVersion: apps/v1
kind: Deployment
metadata:
  name: reactor-controller
  namespace: reactor-protection
  labels:
    app: reactor-controller
    criticality: "safety-critical"
spec:
  replicas: 2
  selector:
    matchLabels:
      app: reactor-controller
  template:
    metadata:
      labels:
        app: reactor-controller
    spec:
      containers:
      - name: reactor-controller
        image: nuclear-registry.local/reactor-controller:v2.1.3
        securityContext:
          privileged: true  # SECURITY ISSUE
          runAsUser: 0      # SECURITY ISSUE
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
        env:
        - name: REACTOR_MODE
          value: "PRODUCTION"
""",

    "safety-systems.yaml": """
# CRITICAL: External exposure of safety system
apiVersion: v1
kind: Service
metadata:
  name: safety-monitor-external
  namespace: safety-systems
spec:
  type: LoadBalancer  # SECURITY ISSUE
  ports:
  - port: 8080
    targetPort: 8080
  selector:
    app: safety-monitor
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: safety-monitor
  namespace: safety-systems
spec:
  replicas: 1
  selector:
    matchLabels:
      app: safety-monitor
  template:
    metadata:
      labels:
        app: safety-monitor
    spec:
      hostNetwork: true  # SECURITY ISSUE
      containers:
      - name: safety-monitor
        image: docker.io/public/safety-monitor:latest  # SECURITY ISSUE
        env:
        - name: DATABASE_PASSWORD
          value: "password123"  # SECURITY ISSUE
""",

    "maintenance-pod.yaml": """
# Extremely insecure maintenance pod
apiVersion: v1
kind: Pod
metadata:
  name: maintenance-pod
  namespace: process-control
spec:
  hostPID: true      # SECURITY ISSUE
  hostIPC: true      # SECURITY ISSUE
  hostNetwork: true  # SECURITY ISSUE
  containers:
  - name: maintenance-tools
    image: busybox:latest
    securityContext:
      privileged: true  # SECURITY ISSUE
      runAsUser: 0      # SECURITY ISSUE
      capabilities:
        add:
        - SYS_ADMIN     # SECURITY ISSUE
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /         # SECURITY ISSUE
"""
}

class NuclearFacilityDemo:
    """Demo class for nuclear facility security scanning"""
    
    def __init__(self):
        self.temp_dir = None
        self.manifest_dir = None
        
    def setup_simulation(self):
        """Set up the simulation environment"""
        print("🏭 Setting up Nuclear Facility Simulation Environment...")
        print("=" * 60)
        
        # Create temporary directory for manifests
        self.temp_dir = tempfile.mkdtemp(prefix="nuclear_facility_")
        self.manifest_dir = Path(self.temp_dir) / "manifests"
        self.manifest_dir.mkdir(exist_ok=True)
        
        # Write sample manifests
        for filename, content in SAMPLE_MANIFESTS.items():
            manifest_file = self.manifest_dir / filename
            with open(manifest_file, 'w') as f:
                f.write(content)
        
        print(f"📁 Created simulation manifests in: {self.manifest_dir}")
        print(f"📝 Generated {len(SAMPLE_MANIFESTS)} manifest files")
        
        # List the created files
        print("\\n📋 Manifest files created:")
        for manifest_file in self.manifest_dir.glob("*.yaml"):
            print(f"   • {manifest_file.name}")
        
        return str(self.manifest_dir)
    
    def run_security_scan(self, manifest_dir: str):
        """Run the security scanner"""
        print(f"\\n🔍 Running Nuclear Facility Security Scan...")
        print("=" * 60)
        
        try:
            # Import the scanner (assuming it's in the same directory)
            sys.path.insert(0, os.getcwd())
            
            # Run the scanner
            from k8s_nuclear_security_scanner import KubernetesSecurityScanner
            
            scanner = KubernetesSecurityScanner()
            findings = scanner.scan_cluster(manifest_dir)
            
            print(f"✅ Scan completed successfully")
            print(f"🚨 Found {len(findings)} security issues")
            
            return scanner, findings
            
        except ImportError as e:
            print(f"❌ Error importing scanner: {e}")
            return None, []
        except Exception as e:
            print(f"❌ Error during scan: {e}")
            return None, []
    
    def demonstrate_findings(self, scanner, findings):
        """Demonstrate the scan findings"""
        if not scanner or not findings:
            print("⚠️  No findings to display")
            return
        
        print(f"\\n📊 Security Scan Results Summary")
        print("=" * 60)
        
        # Generate summary
        summary = scanner._generate_summary()
        
        print("🎯 Findings by Severity:")
        for severity, count in sorted(summary['by_severity'].items()):
            emoji = self._get_severity_emoji(severity)
            print(f"   {emoji} {severity}: {count}")
        
        print(f"\\n🏭 Findings by Nuclear Security Level:")
        for level, count in sorted(summary['by_security_level'].items()):
            emoji = self._get_level_emoji(level)
            print(f"   {emoji} {level}: {count}")
        
        print(f"\\n📋 Compliance Framework Coverage:")
        for framework, count in summary['by_compliance_framework'].items():
            print(f"   📜 {framework}: {count} findings")
        
        # Show critical findings
        critical_findings = [f for f in findings if f.severity.value == "CRITICAL"]
        if critical_findings:
            print(f"\\n🚨 CRITICAL FINDINGS (Immediate Action Required):")
            print("-" * 60)
            
            for finding in critical_findings:
                print(f"\\n❌ {finding.id}: {finding.title}")
                print(f"   🎯 Security Level: {finding.security_level.value}")
                print(f"   📍 Resource: {finding.resource_type}/{finding.resource_name}")
                print(f"   🏢 Namespace: {finding.namespace}")
                print(f"   📝 Issue: {finding.description}")
                print(f"   🔧 Fix: {finding.remediation}")
                print(f"   📚 References: {', '.join(finding.references)}")
    
    def generate_reports(self, scanner):
        """Generate different report formats"""
        if not scanner:
            return
            
        print(f"\\n📄 Generating Compliance Reports...")
        print("=" * 60)
        
        # Generate reports in different formats
        formats = ['json', 'yaml', 'text']
        report_dir = Path(self.temp_dir) / "reports"
        report_dir.mkdir(exist_ok=True)
        
        for fmt in formats:
            try:
                report_content = scanner.generate_report(fmt)
                report_file = report_dir / f"security_report.{fmt}"
                
                with open(report_file, 'w') as f:
                    f.write(report_content)
                
                print(f"✅ Generated {fmt.upper()} report: {report_file}")
                
            except Exception as e:
                print(f"❌ Error generating {fmt} report: {e}")
        
        print(f"\\n📁 All reports saved to: {report_dir}")
    
    def show_remediation_guide(self, findings):
        """Show remediation guidance"""
        print(f"\\n🔧 Nuclear Facility Security Remediation Guide")
        print("=" * 60)
        
        # Group findings by security level
        by_level = {}
        for finding in findings:
            level = finding.security_level.value
            if level not in by_level:
                by_level[level] = []
            by_level[level].append(finding)
        
        for level, level_findings in sorted(by_level.items()):
            if "Level 1" in level or "Level 2" in level:
                priority = "🚨 IMMEDIATE"
            elif "Level 3" in level:
                priority = "⚠️  HIGH PRIORITY"
            else:
                priority = "📋 STANDARD"
            
            print(f"\\n{priority} - {level}")
            print("-" * 40)
            
            for finding in level_findings[:3]:  # Show top 3 per level
                print(f"• {finding.title}")
                print(f"  Action: {finding.remediation}")
                if finding.references:
                    print(f"  Reference: {finding.references[0]}")
                print()
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            print(f"\\n🧹 Cleaned up temporary files: {self.temp_dir}")
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        emoji_map = {
            "CRITICAL": "🚨",
            "HIGH": "🔴", 
            "MEDIUM": "🟠",
            "LOW": "🟡",
            "INFO": "ℹ️"
        }
        return emoji_map.get(severity, "❓")
    
    def _get_level_emoji(self, level: str) -> str:
        """Get emoji for security level"""
        if "Level 1" in level:
            return "🏭"  # Critical nuclear systems
        elif "Level 2" in level:
            return "⚛️"   # Safety systems
        elif "Level 3" in level:
            return "🎛️"  # Process control
        elif "Level 4" in level:
            return "📊"  # Administrative
        else:
            return "💼"  # Office systems

def main():
    """Main demo function"""
    print("🌟 Nuclear Facility Kubernetes Security Scanner Demo")
    print("🏭 Simulating IAEA-Compliant Critical Infrastructure Security")
    print("=" * 80)
    
    demo = NuclearFacilityDemo()
    
    try:
        # Setup simulation environment
        manifest_dir = demo.setup_simulation()
        
        # Run security scan
        scanner, findings = demo.run_security_scan(manifest_dir)
        
        # Display results
        demo.demonstrate_findings(scanner, findings)
        
        # Generate reports
        demo.generate_reports(scanner)
        
        # Show remediation guide
        demo.show_remediation_guide(findings)
        
        print(f"\\n✨ Demo completed successfully!")
        print(f"🔍 This scanner helps ensure nuclear facility compliance with:")
        print(f"   • IAEA Nuclear Security Series (NSS-17)")
        print(f"   • ISO/IEC 27001:2022 Information Security")
        print(f"   • CIS Kubernetes Security Benchmarks")
        print(f"   • Nuclear-specific defense-in-depth principles")
        
        print(f"\\n📖 Key Features Demonstrated:")
        print(f"   ✅ Security level classification (Level 1-5)")
        print(f"   ✅ Nuclear-specific policy enforcement")
        print(f"   ✅ Compliance framework mapping")
        print(f"   ✅ Risk-based vulnerability prioritization")
        print(f"   ✅ Detailed remediation guidance")
        
    except KeyboardInterrupt:
        print(f"\\n⏹️  Demo interrupted by user")
    except Exception as e:
        print(f"\\n❌ Demo error: {e}")
    finally:
        demo.cleanup()

if __name__ == "__main__":
    main()
'''
}

def create_files():
    """Create all necessary files"""
    print("🚀 Setting up Nuclear Facility Kubernetes Security Scanner")
    print("=" * 70)
    
    current_dir = Path.cwd()
    created_files = []
    
    for filename, content in FILES_TO_CREATE.items():
        file_path = current_dir / filename
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Make Python files executable
            if filename.endswith('.py'):
                file_path.chmod(0o755)
            
            created_files.append(filename)
            print(f"✅ Created: {filename}")
            
        except Exception as e:
            print(f"❌ Error creating {filename}: {e}")
            return False
    
    print(f"\n📁 Successfully created {len(created_files)} files:")
    for filename in created_files:
        print(f"   • {filename}")
    
    return True

def run_demo():
    """Run the complete demonstration"""
    print(f"\n🎯 Running Nuclear Facility Security Scanner Demo...")
    print("=" * 70)
    
    try:
        # Run the demo script
        result = subprocess.run([
            sys.executable, 
            'demo_script.py'
        ], cwd=Path.cwd(), capture_output=False, text=True)
        
        if result.returncode == 0:
            print(f"\n🎉 Demo completed successfully!")
        else:
            print(f"\n⚠️  Demo completed with warnings")
            
    except Exception as e:
        print(f"\n❌ Error running demo: {e}")
        print(f"\n💡 You can manually run: python demo_script.py")

def show_usage_instructions():
    """Show usage instructions for the tools"""
    print(f"\n📚 Usage Instructions:")
    print("=" * 50)
    print(f"")
    print(f"🎯 Quick Demo (Recommended):")
    print(f"   python demo_script.py")
    print(f"")
    print(f"🔍 Scan Existing Manifests:")
    print(f"   python k8s_nuclear_security_scanner.py --manifests ./manifests --output json")
    print(f"")
    print(f"⚡ Scan Live Cluster:")
    print(f"   python k8s_nuclear_security_scanner.py --output text")
    print(f"")
    print(f"📊 Generate Reports:")
    print(f"   python k8s_nuclear_security_scanner.py --output-file report.json --output json")
    print(f"")
    print(f"🔧 Available Output Formats:")
    print(f"   • json   - Machine-readable JSON report")
    print(f"   • yaml   - YAML format report")
    print(f"   • text   - Human-readable text report")
    print(f"")
    print(f"🏭 Nuclear Facility Compliance:")
    print(f"   • IAEA Nuclear Security Series (NSS-17)")
    print(f"   • ISO/IEC 27001:2022")
    print(f"   • CIS Kubernetes Benchmarks")
    print(f"   • Defense-in-depth principles")

def main():
    """Main setup function"""
    print("🌟 Nuclear Facility Kubernetes Security Scanner Setup")
    print("🔒 IAEA-Compliant Critical Infrastructure Security Solution")
    print("=" * 80)
    
    try:
        # Create all necessary files
        if not create_files():
            print(f"\n❌ Setup failed. Please check file permissions.")
            return 1
        
        # Show instructions
        show_usage_instructions()
        
        # Ask if user wants to run demo immediately
        print(f"\n❓ Would you like to run the demo now? (y/n): ", end="")
        response = input().lower().strip()
        
        if response in ['y', 'yes', '']:
            run_demo()
        else:
            print(f"\n✨ Setup complete! Run 'python demo_script.py' when ready.")
        
        return 0
        
    except KeyboardInterrupt:
        print(f"\n⏹️  Setup interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Setup error: {e}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)