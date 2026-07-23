#!/usr/bin/env python3
"""
SecGuard - Defensive Security Analysis Toolkit
Author: Cybersecurity Student
Version: 1.0.0

A comprehensive security analysis toolkit that combines multiple defensive 
security capabilities into one unified CLI tool.
"""

import argparse
import sys
import json
from datetime import datetime
from modules import log_analyzer
from modules import headers
from modules import metadata
from modules import password
from utils import logger
from utils import report

class SecGuard:
    """Main security analysis framework"""
    
    def __init__(self):
        self.logger = logger.setup_logger()
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'modules_used': []
        }
        self.banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    ███████╗███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ║
    ║    ██╔════╝██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗║
    ║    ███████╗█████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║║
    ║    ╚════██║██╔══╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║║
    ║    ███████║███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝║
    ║    ╚══════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ║
    ║                                                              ║
    ║         🛡️  Defensive Security Analysis Toolkit  🛡️         ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    Version: 1.0.0 | Author: Cybersecurity Student
    """
    
    def run(self, args):
        """Execute selected security analysis modules"""
        
        print(self.banner)
        self.logger.info(f"SecGuard initialized at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Log Analysis Module
        if args.logs:
            self.logger.info("📊 Analyzing logs for security threats...")
            log_results = log_analyzer.analyze_logs(args.logs, args.log_type)
            self.results['log_analysis'] = log_results
            self.results['modules_used'].append('log_analyzer')
            self._display_log_summary(log_results)
        
        # HTTP Headers Module
        if args.headers:
            self.logger.info(f"🌐 Analyzing security headers for: {args.headers}")
            headers_results = headers.analyze_headers(args.headers)
            self.results['headers_analysis'] = headers_results
            self.results['modules_used'].append('headers_analyzer')
            self._display_headers_summary(headers_results)
        
        # Metadata Module
        if args.metadata:
            self.logger.info(f"📄 Extracting metadata from: {args.metadata}")
            metadata_results = metadata.extract_metadata(args.metadata)
            self.results['metadata_analysis'] = metadata_results
            self.results['modules_used'].append('metadata_extractor')
            self._display_metadata_summary(metadata_results)
        
        # Password Module
        if args.password:
            self.logger.info(f"🔐 Analyzing password strength")
            password_results = password.analyze_password(args.password)
            self.results['password_analysis'] = password_results
            self.results['modules_used'].append('password_analyzer')
            self._display_password_summary(password_results)
        
        # Generate report
        if args.output:
            self.logger.info(f"📝 Generating report...")
            report_file = report.generate_report(self.results, args.output)
            print(f"\n✅ Report saved to: {report_file}")
        
        self.logger.info("✅ SecGuard analysis complete!")
        return self.results
    
    def _display_log_summary(self, results):
        """Display log analysis summary"""
        print("\n" + "="*60)
        print("📊 LOG ANALYSIS SUMMARY")
        print("="*60)
        print(f"  📁 File: {results.get('filename', 'N/A')}")
        print(f"  📏 Total Lines: {results.get('total_lines', 0)}")
        print(f"  ⚠️  Suspicious Events: {results.get('suspicious_count', 0)}")
        
        if results.get('top_attackers'):
            print("  🎯 Top Attackers (IPs):")
            for ip, count in list(results.get('top_attackers', {}).items())[:5]:
                print(f"     - {ip}: {count} attempts")
        
        if results.get('risk_level'):
            print(f"  📊 Risk Level: {results.get('risk_level')}")
        print("="*60)
    
    def _display_headers_summary(self, results):
        """Display headers analysis summary"""
        print("\n" + "="*60)
        print("🌐 HTTP SECURITY HEADERS ANALYSIS")
        print("="*60)
        print(f"  🌍 URL: {results.get('url', 'N/A')}")
        print(f"  📊 Grade: {results.get('grade', 'N/A')} (Score: {results.get('score', 0)}%)")
        
        # Show TLS info
        if results.get('tls_info'):
            tls = results['tls_info']
            print(f"  🔒 TLS Version: {tls.get('version', 'N/A')}")
            print(f"  🔑 Certificate: {'✅ Valid' if tls.get('cert_valid') else '❌ Invalid'}")
        
        # Show HTTPS enforcement
        https_status = "✅ Yes" if results.get('https_enforced') else "❌ No"
        print(f"  🔐 HTTPS Enforced: {https_status}")
        
        # Show known secure site context
        if results.get('is_known_secure'):
            print(f"  📝 Note: Known secure site using alternative security controls")
            if results.get('security_context', {}).get('alternative_security'):
                print(f"     Security mechanisms: {', '.join(results['security_context']['alternative_security'])}")
        
        print("\n  📋 Header Status:")
        for header, analysis in results.get('headers_analysis', {}).items():
            if analysis.get('present'):
                icon = "✅" if analysis.get('quality') == 'Good' else "⚠️"
                value = analysis.get('value', 'N/A')
                print(f"     {icon} {header}: {value[:60]}")
            else:
                print(f"     ❌ {header}: Missing")
        
        if results.get('suggestions'):
            print("\n  💡 Suggestions:")
            for suggestion in results.get('suggestions', [])[:5]:
                print(f"     - {suggestion}")
        
        if results.get('error'):
            print(f"\n  ❌ Error: {results.get('error')}")
        print("="*60)
    
    def _display_metadata_summary(self, results):
        """Display metadata summary"""
        print("\n" + "="*60)
        print("📄 METADATA ANALYSIS")
        print("="*60)
        print(f"  📁 File: {results.get('filename', 'N/A')}")
        print(f"  📏 Size: {results.get('size', 'N/A')}")
        print(f"  📂 Type: {results.get('file_type', 'N/A')}")
        print(f"  🔑 MD5: {results.get('md5', 'N/A')[:16]}...")
        print(f"  🔑 SHA256: {results.get('sha256', 'N/A')[:16]}...")
        
        if results.get('exif_data'):
            print("  📷 EXIF Data Found: Yes")
        
        if results.get('risk_level'):
            print(f"  📊 Risk Level: {results.get('risk_level')}")
        print("="*60)
    
    def _display_password_summary(self, results):
        """Display password analysis summary"""
        print("\n" + "="*60)
        print("🔐 PASSWORD STRENGTH ANALYSIS")
        print("="*60)
        print(f"  💪 Strength: {results.get('strength', 'N/A')}")
        print(f"  📊 Score: {results.get('score', 0)}/100")
        print(f"  📏 Length: {results.get('length', 0)}")
        print(f"  ⏱️  Time to crack: {results.get('crack_time', 'N/A')}")
        
        if results.get('entropy'):
            print(f"  🔑 Entropy: {results.get('entropy')} bits")
        
        if results.get('issues'):
            print("  ⚠️ Issues Found:")
            for issue in results.get('issues', [])[:3]:
                print(f"     - {issue}")
        print("="*60)

def main():
    """Command-line interface"""
    parser = argparse.ArgumentParser(
        description='SecGuard - Defensive Security Analysis Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secguard --logs /var/log/auth.log --log-type ssh
  secguard --headers https://example.com
  secguard --metadata suspicious_file.pdf
  secguard --password "MyP@ssw0rd"
  secguard --logs sample.log --output html
        """
    )
    
    # Module arguments
    parser.add_argument(
        '--logs',
        help='Path to log file for analysis'
    )
    parser.add_argument(
        '--log-type',
        choices=['ssh', 'http', 'auth', 'syslog'],
        default='ssh',
        help='Type of log file (default: ssh)'
    )
    parser.add_argument(
        '--headers',
        help='URL to analyze for security headers'
    )
    parser.add_argument(
        '--metadata',
        help='Path to file for metadata extraction'
    )
    parser.add_argument(
        '--password',
        help='Password to analyze for strength'
    )
    parser.add_argument(
        '-o', '--output',
        choices=['json', 'html'],
        help='Output format for report'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Check if at least one module is selected
    if not any([args.logs, args.headers, args.metadata, args.password]):
        parser.print_help()
        print("\n❌ Error: Please select at least one module to run.")
        sys.exit(1)
    
    # Initialize and run
    guard = SecGuard()
    guard.run(args)

if __name__ == '__main__':
    main()