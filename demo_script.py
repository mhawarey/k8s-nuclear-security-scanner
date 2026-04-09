#!/usr/bin/env python3
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
        print("\n📋 Manifest files created:")
        for manifest_file in self.manifest_dir.glob("*.yaml"):
            print(f"   • {manifest_file.name}")
        
        return str(self.manifest_dir)
    
    def run_security_scan(self, manifest_dir: str):
        """Run the security scanner"""
        print(f"\n🔍 Running Nuclear Facility Security Scan...")
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
        
        print(f"\n📊 Security Scan Results Summary")
        print("=" * 60)
        
        # Generate summary
        summary = scanner._generate_summary()
        
        print("🎯 Findings by Severity:")
        for severity, count in sorted(summary['by_severity'].items()):
            emoji = self._get_severity_emoji(severity)
            print(f"   {emoji} {severity}: {count}")
        
        print(f"\n🏭 Findings by Nuclear Security Level:")
        for level, count in sorted(summary['by_security_level'].items()):
            emoji = self._get_level_emoji(level)
            print(f"   {emoji} {level}: {count}")
        
        print(f"\n📋 Compliance Framework Coverage:")
        for framework, count in summary['by_compliance_framework'].items():
            print(f"   📜 {framework}: {count} findings")
        
        # Show critical findings
        critical_findings = [f for f in findings if f.severity.value == "CRITICAL"]
        if critical_findings:
            print(f"\n🚨 CRITICAL FINDINGS (Immediate Action Required):")
            print("-" * 60)
            
            for finding in critical_findings:
                print(f"\n❌ {finding.id}: {finding.title}")
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
            
        print(f"\n📄 Generating Compliance Reports...")
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
        
        print(f"\n📁 All reports saved to: {report_dir}")
    
    def show_remediation_guide(self, findings):
        """Show remediation guidance"""
        print(f"\n🔧 Nuclear Facility Security Remediation Guide")
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
            
            print(f"\n{priority} - {level}")
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
            print(f"\n🧹 Cleaned up temporary files: {self.temp_dir}")
    
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
        
        print(f"\n✨ Demo completed successfully!")
        print(f"🔍 This scanner helps ensure nuclear facility compliance with:")
        print(f"   • IAEA Nuclear Security Series (NSS-17)")
        print(f"   • ISO/IEC 27001:2022 Information Security")
        print(f"   • CIS Kubernetes Security Benchmarks")
        print(f"   • Nuclear-specific defense-in-depth principles")
        
        print(f"\n📖 Key Features Demonstrated:")
        print(f"   ✅ Security level classification (Level 1-5)")
        print(f"   ✅ Nuclear-specific policy enforcement")
        print(f"   ✅ Compliance framework mapping")
        print(f"   ✅ Risk-based vulnerability prioritization")
        print(f"   ✅ Detailed remediation guidance")
        
    except KeyboardInterrupt:
        print(f"\n⏹️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
    finally:
        demo.cleanup()

if __name__ == "__main__":
    main()
