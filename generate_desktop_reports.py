#!/usr/bin/env python3
"""
Generate Nuclear Facility Security Reports to Desktop
This script runs the scanner and saves all reports to your Desktop
"""

import os
import sys
from pathlib import Path
from datetime import datetime

def generate_desktop_reports():
    """Generate security reports and save to Desktop"""
    print("🏭 Nuclear Facility Security Scanner - Desktop Report Generator")
    print("=" * 70)
    
    # Set up paths
    desktop_path = Path.home() / "Desktop"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = desktop_path / f"nuclear_security_reports_{timestamp}"
    
    # Create report directory
    report_dir.mkdir(exist_ok=True)
    print(f"📁 Creating reports in: {report_dir}")
    
    try:
        # Import the scanner
        from k8s_nuclear_security_scanner import KubernetesSecurityScanner
        
        # Initialize scanner
        print("🔍 Initializing nuclear facility security scanner...")
        scanner = KubernetesSecurityScanner()
        
        # Run scan (will use simulated data since no manifests specified)
        print("⚡ Performing security scan...")
        findings = scanner.scan_cluster()
        
        print(f"✅ Scan completed: Found {len(findings)} security issues")
        
        # Generate reports in all formats
        formats = ['json', 'yaml', 'text']
        report_files = []
        
        for fmt in formats:
            print(f"📄 Generating {fmt.upper()} report...")
            
            try:
                report_content = scanner.generate_report(fmt)
                report_file = report_dir / f"nuclear_security_report.{fmt}"
                
                with open(report_file, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                
                report_files.append(report_file)
                print(f"✅ Created: {report_file.name}")
                
            except Exception as e:
                print(f"❌ Error generating {fmt} report: {e}")
        
        # Generate summary report
        print("📊 Generating executive summary...")
        summary_file = report_dir / "EXECUTIVE_SUMMARY.txt"
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(generate_executive_summary(scanner, findings))
        
        report_files.append(summary_file)
        print(f"✅ Created: {summary_file.name}")
        
        # Generate findings CSV for analysis
        print("📈 Generating findings CSV...")
        csv_file = report_dir / "security_findings.csv"
        
        with open(csv_file, 'w', encoding='utf-8') as f:
            f.write(generate_findings_csv(findings))
        
        report_files.append(csv_file)
        print(f"✅ Created: {csv_file.name}")
        
        # Print completion summary
        print(f"\n🎉 Report Generation Complete!")
        print(f"📁 Location: {report_dir}")
        print(f"📝 Generated {len(report_files)} files:")
        
        for report_file in report_files:
            file_size = report_file.stat().st_size
            print(f"   • {report_file.name} ({file_size:,} bytes)")
        
        # Show key findings summary
        print(f"\n🚨 Key Security Issues Found:")
        summary = scanner._generate_summary()
        
        for severity, count in sorted(summary['by_severity'].items()):
            emoji = get_severity_emoji(severity)
            print(f"   {emoji} {severity}: {count} findings")
        
        print(f"\n🏭 Nuclear Security Level Breakdown:")
        for level, count in sorted(summary['by_security_level'].items()):
            emoji = get_level_emoji(level)
            print(f"   {emoji} {level}: {count}")
        
        print(f"\n📋 Compliance Frameworks Covered:")
        for framework, count in summary['by_compliance_framework'].items():
            print(f"   📜 {framework}: {count} findings")
        
        # Open the directory
        print(f"\n💡 Opening report directory...")
        try:
            if os.name == 'nt':  # Windows
                os.startfile(str(report_dir))
            elif os.name == 'posix':  # macOS/Linux
                os.system(f'open "{report_dir}"')
        except:
            print(f"   (Manual navigation required)")
        
        return True
        
    except ImportError as e:
        print(f"❌ Error: Scanner module not found. Run setup_nuclear_scanner.py first")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def generate_executive_summary(scanner, findings):
    """Generate executive summary for management"""
    summary = scanner._generate_summary()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    content = f"""
NUCLEAR FACILITY SECURITY ASSESSMENT
EXECUTIVE SUMMARY
================================================================================
Assessment Date: {timestamp}
Scanner Version: Nuclear Facility K8s Security Scanner v1.0
Compliance Standards: IAEA NSS-17, ISO/IEC 27001:2022, CIS Kubernetes

OVERALL SECURITY POSTURE
================================================================================
Total Security Issues Identified: {len(findings)}

Risk Level Distribution:
"""
    
    for severity, count in sorted(summary['by_severity'].items()):
        content += f"  • {severity}: {count} findings\n"
    
    content += f"""
Nuclear Security Level Impact:
"""
    
    for level, count in sorted(summary['by_security_level'].items()):
        content += f"  • {level}: {count} findings\n"
    
    # Critical findings
    critical_findings = [f for f in findings if f.severity.value == "CRITICAL"]
    
    content += f"""
CRITICAL SECURITY CONCERNS
================================================================================
{len(critical_findings)} CRITICAL issues require immediate attention:

"""
    
    for i, finding in enumerate(critical_findings[:5], 1):  # Top 5 critical
        content += f"{i}. {finding.title}\n"
        content += f"   Resource: {finding.resource_type}/{finding.resource_name}\n"
        content += f"   Namespace: {finding.namespace}\n"
        content += f"   Security Level: {finding.security_level.value}\n"
        content += f"   Action: {finding.remediation}\n\n"
    
    content += f"""
COMPLIANCE FRAMEWORK ALIGNMENT
================================================================================
This assessment covers nuclear facility-specific requirements:

• IAEA Nuclear Security Series (NSS-17): Computer Security at Nuclear Facilities
• ISO/IEC 27001:2022: Information Security Management Systems
• CIS Kubernetes Benchmark: Container orchestration security
• Defense-in-depth principles for critical infrastructure

RECOMMENDED ACTIONS
================================================================================
1. IMMEDIATE: Address all CRITICAL findings in Level 1 & 2 systems
2. HIGH PRIORITY: Implement network segmentation policies
3. STANDARD: Review and harden container security contexts
4. ONGOING: Establish continuous security monitoring

For detailed technical findings and remediation steps, refer to the
complete security reports in JSON, YAML, and text formats.

ASSESSMENT METHODOLOGY
================================================================================
This assessment simulates nuclear facility Kubernetes environments including:
- Reactor protection systems (Level 1 - Highest Security)
- Safety monitoring systems (Level 2 - Safety Related)
- Process control systems (Level 3 - Operational)
- Administrative systems (Level 4-5 - Support)

Security policies enforce IAEA guidelines for air-gapped networks,
privileged access controls, and nuclear-specific compliance requirements.
"""
    
    return content

def generate_findings_csv(findings):
    """Generate CSV of findings for analysis"""
    csv_content = "ID,Title,Severity,Security_Level,Resource_Type,Resource_Name,Namespace,Compliance_Frameworks,Remediation\n"
    
    for finding in findings:
        frameworks = "; ".join([f.value for f in finding.compliance_frameworks])
        remediation = finding.remediation.replace('"', '""')  # Escape quotes
        
        csv_content += f'"{finding.id}","{finding.title}","{finding.severity.value}","{finding.security_level.value}","{finding.resource_type}","{finding.resource_name}","{finding.namespace}","{frameworks}","{remediation}"\n'
    
    return csv_content

def get_severity_emoji(severity: str) -> str:
    """Get emoji for severity level"""
    emoji_map = {
        "CRITICAL": "🚨",
        "HIGH": "🔴", 
        "MEDIUM": "🟠",
        "LOW": "🟡",
        "INFO": "ℹ️"
    }
    return emoji_map.get(severity, "❓")

def get_level_emoji(level: str) -> str:
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

if __name__ == "__main__":
    print("🌟 Starting Nuclear Facility Security Report Generation...")
    
    success = generate_desktop_reports()
    
    if success:
        print(f"\n✨ Reports successfully generated on Desktop!")
        print(f"🔍 Use these reports to demonstrate:")
        print(f"   • IAEA compliance expertise")
        print(f"   • Nuclear security knowledge")
        print(f"   • Kubernetes security skills")
        print(f"   • Enterprise risk assessment")
    else:
        print(f"\n❌ Report generation failed. Check error messages above.")
    
    input(f"\nPress Enter to exit...")