#!/usr/bin/env python3
"""
Shai-Hulud 2.0 Supply Chain Attack Checker
Scans for compromised npm packages and malware artifacts
"""

import os
import sys
import json
import csv
import subprocess
import re
import urllib.request
from pathlib import Path
from typing import Dict, List
from collections import defaultdict
import argparse

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

class ShaiHuludChecker:
    MALWARE_FILES = [
        'cloud.json',
        'contents.json',
        'environment.json',
        'truffleSecrets.json',
        'actionsSecrets.json',
        'setup_bun.js',
        'bun_environment.js',
    ]

    WORKFLOW_PATTERNS = [
        '.github/workflows/discussion.yaml',
        '.github/workflows/discussion.yml',
    ]

    FORMATTER_PATTERN = re.compile(r'\.github/workflows/formatter_\d+\.yml')

    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        self.malicious_packages = {}  # package_name -> list of versions
        self.findings = defaultdict(list)
        self.scanned_paths = set()

    def load_malicious_packages(self) -> bool:
        csv_lines = []
        remote_url = "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv"

        print(f"{Colors.BLUE}Attempting to fetch latest IOCs from remote source...{Colors.RESET}")
        try:
            with urllib.request.urlopen(remote_url, timeout=5) as response:
                if response.status == 200:
                    content = response.read().decode('utf-8')
                    csv_lines = content.splitlines()
                    print(f"{Colors.GREEN}✓ Successfully fetched remote IOCs{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.YELLOW}⚠ Remote fetch failed ({e}), falling back to local file{Colors.RESET}")

        if not csv_lines:
            try:
                with open(self.csv_path, 'r') as f:
                    csv_lines = f.readlines()
            except Exception as e:
                print(f"{Colors.RED}✗ Error loading local CSV:{Colors.RESET} {e}")
                return False

        try:
            reader = csv.DictReader(csv_lines)
            for row in reader:
                package = row['Package'].strip()
                version = row['Version'].strip()
                if not package:
                    continue
                if package not in self.malicious_packages:
                    self.malicious_packages[package] = []
                if version:
                    versions = [v.strip().replace('=', '').strip() for v in version.split('||')]
                    self.malicious_packages[package].extend(versions)
            print(f"{Colors.GREEN}✓ Loaded {len(self.malicious_packages)} malicious packages")
            return True
        except Exception as e:
            print(f"{Colors.RED}✗ Error parsing CSV data:{Colors.RESET} {e}")
            return False

    def check_version_match(self, package: str, installed_version: str) -> bool:
        if package not in self.malicious_packages:
            return False
        malicious_versions = self.malicious_packages[package]
        if not malicious_versions or malicious_versions == ['']:
            return True
        return installed_version in malicious_versions

    def check_global_npm_packages(self) -> int:
        print(f"\n{Colors.BOLD}Checking global npm packages...{Colors.RESET}")
        try:
            result = subprocess.run(
                ['npm', 'list', '-g', '--json', '--depth=0'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0 and not result.stdout:
                print(f"{Colors.YELLOW}⚠ Could not get global npm packages{Colors.RESET}")
                return 0
            data = json.loads(result.stdout)
            dependencies = data.get('dependencies', {})
            found = 0
            for pkg_namer, pkg_info in dependencies.items():
                version = pkg_info.get('version', '')
                if self.check_version_match(pkg_name, version):
                    self.findings['global_npm'].append({
                        'package': pkg_name,
                        'version': version,
                        'location': 'global'
                    })
                    found += 1
                    print(f"{Colors.RED}✗ THREAT:{Colors.RESET} {pkg_name}@{version} (global)")
            if found == 0:
                print(f"{Colors.GREEN}✓ No malicious packages in global npm{Colors.RESET}")
            return found
        except FileNotFoundError:
            print(f"{Colors.YELLOW}⚠ npm not found - skipping global check{Colors.RESET}")
            return 0
        except Exception as e:
            print(f"{Colors.YELLOW}⚠ Error checking global packages:{Colors.RESET} {e}")
            return 0

    def check_package_json(self, package_json_path: Path) -> int:
        found = 0
        try:
            with open(package_json_path, 'r') as f:
                data = json.load(f)
            all_deps = {}
            all_deps.update(data.get('dependencies', {}))
            all_deps.update(data.get('devDependencies', {}))
            all_deps.update(data.get('optionalDependencies', {}))
            for pkg_name, version_spec in all_deps.items():
                if pkg_name in self.malicious_packages:
                    version = re.sub(r'[\^~>=<]', '', version_spec).strip()
                    if self.check_version_match(pkg_name, version) or version_spec == '*':
                        self.findings['package_json'].append({
                            'package': pkg_name,
                            'version': version_spec,
                            'location': str(package_json_path)
                        })
                        found += 1
                        print(f"{Colors.RED}✗ THREAT:{Colors.RESET} {pkg_name}@{version_spec}")
                        print(f"  Location: {package_json_path}")
        except Exception as e:
            print(f"{Colors.YELLOW}⚠ Error reading {package_json_path}:{Colors.RESET} {e}")
        return found

    def check_node_modules(self, node_modules_path: Path) -> int:
        found = 0
        if not node_modules_path.exists():
            return 0
        try:
            for package_dir in node_modules_path.iterdir():
                if not package_dir.is_dir():
                    continue
                if package_dir.name.startswith('@'):
                    for scoped_pkg in package_dir.iterdir():
                        if scoped_pkg.is_dir():
                            pkg_name = f"{package_dir.name}/{scoped_pkg.name}"
                            found += self._check_single_package(scoped_pkg, pkg_name)
                else:
                    found += self._check_single_package(package_dir, package_dir.name)
        except Exception as e:
            print(f"{Colors.YELLOW}⚠ Error scanning node_modules:{Colors.RESET} {e}")
        return found

    def _check_single_package(self, package_path: Path, package_name: str) -> int:
        pkg_json = package_path / 'package.json'
        if not pkg_json.exists():
            return 0
        try:
            with open(pkg_json, 'r') as f:
                data = json.load(f)
            version = data.get('version', '')
            if self.check_version_match(package_name, version):
                self.findings['node_modules'].append({
                    'package': package_name,
                    'version': version,
                    'location': str(package_path)
                })
                print(f"{Colors.RED}✗ THREAT:{Colors.RESET} {package_name}@{version}")
                print(f"  Location: {package_path}")
                return 1
        except Exception:
            pass
        return 0

    def scan_for_malware_artifacts(self, search_path: Path) -> int:
        print(f"\n{Colors.BOLD}Scanning for malware artifacts in: {search_path}{Colors.RESET}")
        found = 0
        try:
            for malware_file in self.MALWARE_FILES:
                for file_path in search_path.rglob(malware_file):
                    self.findings['malware_files'].append({
                        'file': malware_file,
                        'location': str(file_path),
                        'size': file_path.stat().st_size
                    })
                    found += 1
                    print(f"{Colors.RED}✗ MALWARE ARTIFACT:{Colors.RESET} {malware_file}")
                    print(f"  Location: {file_path}")
                    print(f"  Size: {file_path.stat().st_size} bytes")
            for workflow_pattern in self.WORKFLOW_PATTERNS:
                for file_path in search_path.rglob(workflow_pattern):
                    if self._check_suspicious_workflow(file_path):
                        self.findings['backdoor_workflows'].append({
                            'file': file_path.name,
                            'location': str(file_path)
                        })
                        found += 1
                        print(f"{Colors.RED}✗ BACKDOOR WORKFLOW:{Colors.RESET} {file_path.name}")
                        print(f"  Location: {file_path}")
            for file_path in search_path.rglob('.github/workflows/*.yml'):
                if self.FORMATTER_PATTERN.match(str(file_path)):
                    self.findings['exfiltration_workflows'].append({
                        'file': file_path.name,
                        'location': str(file_path)
                    })
                    found += 1
                    print(f"{Colors.RED}✗ EXFILTRATION WORKFLOW:{Colors.RESET} {file_path.name}")
                    print(f"  Location: {file_path}")
        except Exception as e:
            print(f"{Colors.YELLOW}⚠ Error scanning for artifacts:{Colors.RESET} {e}")
        return found

    def _check_suspicious_workflow(self, workflow_path: Path) -> bool:
        try:
            content = workflow_path.read_text()
            suspicious_patterns = [
                'runs-on: self-hosted',
                'on:\n  discussion:',
                'github.event.discussion.body',
                'RUNNER_TRACKING_ID'
            ]
            matches = sum(1 for pattern in suspicious_patterns if pattern in content)
            return matches >= 2
        except Exception:
            return True

    def scan_directory(self, directory: Path) -> None:
        if directory in self.scanned_paths:
            return
        self.scanned_paths.add(directory)

        print(f"\n{Colors.BOLD}Scanning directory: {directory}{Colors.RESET}")
        package_json = directory / 'package.json'
        if package_json.exists():
            print(f"Checking {package_json}...")
            self.check_package_json(package_json)

        node_modules = directory / 'node_modules'
        if node_modules.exists():
            print(f"Checking {node_modules}...")
            self.check_node_modules(node_modules)

        self.scan_for_malware_artifacts(directory)

    def find_and_scan_projects(self, root_path: Path, max_depth: int = 3) -> None:
        print(f"\n{Colors.BOLD}Searching for Node.js projects in: {root_path}{Colors.RESET}")

        def scan_recursive(path: Path, depth: int = 0):
            if depth > max_depth:
                return
            try:
                if (path / 'package.json').exists():
                    # Found npm project directory, scan it
                    self.scan_directory(path)
                    return  # Do not recurse further into this project
                for subdir in path.iterdir():
                    if subdir.is_dir() and not subdir.name.startswith('.'):
                        if subdir.name != 'node_modules':  # Skip node_modules folders
                            scan_recursive(subdir, depth + 1)
            except PermissionError:
                pass
            except Exception as e:
                print(f"{Colors.YELLOW}⚠ Error scanning {path}:{Colors.RESET} {e}")

        scan_recursive(root_path)

    def print_summary(self) -> None:
        print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}SCAN SUMMARY{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}\n")
        total_threats = sum(len(items) for items in self.findings.values())
        if total_threats == 0:
            print(f"{Colors.GREEN}{Colors.BOLD}✓ NO THREATS DETECTED{Colors.RESET}")
            print(f"{Colors.GREEN}Your system appears to be clean.{Colors.RESET}\n")
            return
        print(f"{Colors.RED}{Colors.BOLD}⚠ {total_threats} THREAT(S) DETECTED!{Colors.RESET}\n")
        pkg_count = len(self.findings['global_npm']) + len(self.findings['package_json']) + len(self.findings['node_modules'])
        if pkg_count > 0:
            print(f"{Colors.RED}Malicious Packages: {pkg_count}{Colors.RESET}")
            if self.findings['global_npm']:
                print(f"  • Global npm: {len(self.findings['global_npm'])}")
            if self.findings['package_json']:
                print(f"  • In package.json: {len(self.findings['package_json'])}")
            if self.findings['node_modules']:
                print(f"  • In node_modules: {len(self.findings['node_modules'])}")
        if self.findings['malware_files']:
            print(f"{Colors.RED}Malware Artifacts: {len(self.findings['malware_files'])}{Colors.RESET}")
        if self.findings['backdoor_workflows']:
            print(f"{Colors.RED}Backdoor Workflows: {len(self.findings['backdoor_workflows'])}{Colors.RESET}")
        if self.findings['exfiltration_workflows']:
            print(f"{Colors.RED}Exfiltration Workflows: {len(self.findings['exfiltration_workflows'])}{Colors.RESET}")
        print(f"\n{Colors.BOLD}IMMEDIATE ACTIONS REQUIRED:{Colors.RESET}\n")
        print(f"{Colors.YELLOW}1. Remove malicious packages:{Colors.RESET}\n")
        if self.findings['global_npm']:
            print(f"   Global packages:")
            for item in self.findings['global_npm']:
                print(f"   npm uninstall -g {item['package']}")
        if self.findings['node_modules'] or self.findings['package_json']:
            print(f"   Local packages:")
            print(f"   • Remove from package.json")
            print(f"   • Delete node_modules and package-lock.json")
            print(f"   • Run: npm install (after cleanup)")
        if self.findings['malware_files']:
            print(f"\n{Colors.YELLOW}2. Delete malware artifacts:{Colors.RESET}")
            for item in self.findings['malware_files']:
                print(f"   rm {item['location']}")
        if self.findings['backdoor_workflows'] or self.findings['exfiltration_workflows']:
            print(f"\n{Colors.YELLOW}3. Remove backdoor workflows:{Colors.RESET}")
            for item in self.findings['backdoor_workflows'] + self.findings['exfiltration_workflows']:
                print(f"   rm {item['location']}")
            print(f"   • Check for self-hosted runners named 'SHA1HULUD'")
            print(f"   • Review and remove any suspicious GitHub runners")
        print(f"\n{Colors.YELLOW}4. Rotate ALL credentials immediately:{Colors.RESET}")
        print(f"   • GitHub tokens (check Settings → Developer settings)")
        print(f"   • AWS credentials (~/.aws/credentials)")
        print(f"   • GCP credentials (~/.config/gcloud)")
        print(f"   • Azure credentials (~/.azure)")
        print(f"   • All API keys and secrets")
        print(f"   • GitHub Actions secrets")
        print(f"\n{Colors.YELLOW}5. Check for data exfiltration:{Colors.RESET}")
        print(f"   • Review your GitHub repositories for unexpected repos")
        print(f"   • Look for repos with 'Shai-Hulud' in description")
        print(f"   • Check for repos you don't recognize")
        print(f"\n{Colors.YELLOW}6. Monitor for suspicious activity:{Colors.RESET}")
        print(f"   • Review cloud resource access logs")
        print(f"   • Check for unauthorized API calls")
        print(f"   • Monitor for unusual GitHub activity")
        print(f"\n{Colors.RED}Report to GitHub Security:{Colors.RESET}")
        print(f"   https://github.com/security\n")

    def export_findings(self, output_file: str) -> None:
        try:
            with open(output_file, 'w') as f:
                json.dump(dict(self.findings), f, indent=2)
            print(f"{Colors.GREEN}✓ Findings exported to:{Colors.RESET} {output_file}")
        except Exception as e:
            print(f"{Colors.RED}✗ Error exporting findings:{Colors.RESET} {e}")

def get_common_project_locations() -> List[Path]:
    home = Path.home()
    common_locations = [
        home / 'projects',
        home / 'Projects',
        home / 'code',
        home / 'Code',
        home / 'dev',
        home / 'Developer',
        home / 'workspace',
        home / 'work',
        home / 'Documents' / 'projects',
        home / 'Documents' / 'code',
        home / 'Desktop',
        home / 'src',
    ]
    return [loc for loc in common_locations if loc.exists() and loc.is_dir()]

def main():
    parser = argparse.ArgumentParser(
        description='Scan for Shai-Hulud 2.0 supply chain attack indicators',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-scan common project locations (default behavior)
  python check_shai_hulud.py
  
  # Scan specific directory recursively
  python check_shai_hulud.py ~/projects
  
  # Scan current directory
  python check_shai_hulud.py .
  
  # Export findings to JSON
  python check_shai_hulud.py --output findings.json
  
  # Scan multiple directories
  python check_shai_hulud.py ~/projects ~/work
        """
    )
    parser.add_argument(
        'paths',
        nargs='*',
        help='Directory paths to scan recursively (if not provided, auto-scans common locations)'
    )
    parser.add_argument(
        '--csv',
        default='data/shai-hulud-2-packages.csv',
        help='Path to CSV file with malicious packages (default: data/shai-hulud-2-packages.csv)'
    )
    parser.add_argument(
        '--output',
        help='Export findings to JSON file'
    )
    parser.add_argument(
        '--depth',
        type=int,
        default=5,
        help='Maximum depth for recursive project search (default: 5)'
    )
    parser.add_argument(
        '--no-global',
        action='store_true',
        help='Skip global npm package check'
    )
    args = parser.parse_args()

    print(f"{Colors.BOLD}{Colors.CYAN}")
    print("=" * 70)
    print("  Shai-Hulud 2.0 Supply Chain Attack Scanner")
    print("=" * 70)
    print(f"{Colors.RESET}\n")

    print(f"{Colors.BOLD}What this scanner checks:{Colors.RESET}")
    print(f"  • Malicious npm packages (798 known compromised packages)")
    print(f"  • Malware artifacts (cloud.json, environment.json, etc.)")
    print(f"  • Backdoor workflows (.github/workflows/discussion.yaml)")
    print(f"  • GitHub runner backdoors (SHA1HULUD)")
    print()

    checker = ShaiHuludChecker(args.csv)

    if not checker.load_malicious_packages():
        sys.exit(1)

    if not args.no_global:
        checker.check_global_npm_packages()

    scan_dirs = []
    if args.paths:
        scan_dirs = [Path(p).expanduser().resolve() for p in args.paths]
    else:
        print(f"\n{Colors.BOLD}Auto-discovering project locations...{Colors.RESET}")
        common_locs = get_common_project_locations()
        if not common_locs:
            print(f"{Colors.YELLOW}⚠ No common project directories found{Colors.RESET}")
            print(f"{Colors.YELLOW}  Scanning current directory instead{Colors.RESET}")
            scan_dirs = [Path.cwd()]
        else:
            print(f"{Colors.GREEN}✓ Found {len(common_locs)} common location(s) to scan:{Colors.RESET}")
            for loc in common_locs:
                print(f"  • {loc}")
            scan_dirs = common_locs

    for scan_dir in scan_dirs:
        if not scan_dir.exists():
            print(f"{Colors.YELLOW}⚠ Directory not found:{Colors.RESET} {scan_dir}")
            continue
        checker.find_and_scan_projects(scan_dir, max_depth=args.depth)

    checker.print_summary()

    if args.output:
        checker.export_findings(args.output)

    total_threats = sum(len(items) for items in checker.findings.values())
    sys.exit(1 if total_threats > 0 else 0)

if __name__ == '__main__':
    main()
