#!/usr/bin/env python3
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
        
        return '\n'.join(lines)
    
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
