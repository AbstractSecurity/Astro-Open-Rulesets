#!/usr/bin/env python3
"""NPM SBOM Generator

This script generates a Software Bill of Materials (SBOM) from a package.json file.
It recursively analyzes dependencies and devDependencies by installing each package
and parsing the resulting package-lock.json files.

Usage:
    python npm_sbom_generator.py <package_json_file> [output_file]
"""

import json
import os
import subprocess
import tempfile
import shutil
import sys
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Optional
from datetime import datetime
import argparse
import multiprocessing as mp
from multiprocessing import Manager, Pool, Queue
import time
import random


class NPMSBOMGenerator:
    def __init__(self, package_json_file: str, output_file: str = None):
        self.package_json_file = package_json_file
        self.output_file = output_file or "npm_sbom.json"
        self.temp_dir = None
        self.sbom_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "generator": "npm_sbom_generator.py",
                "source_package_json": package_json_file
            },
            "root_project": {},
            "packages": {},
            "dependency_tree": {},
            "statistics": {
                "total_dependencies": 0,
                "total_dev_dependencies": 0,
                "unique_packages": 0,
                "packages_with_dependencies": 0
            }
        }
        self.processed_packages: Set[str] = set()
        self.packages_to_process: List[Dict[str, str]] = []
        self.max_depth = None  # None means infinite depth
        self.current_depth = 0
        self.max_workers = mp.cpu_count()
        self.use_multiprocessing = True
        self.max_retries = 3
        self.retry_delay_base = 1.0  # Base delay in seconds
        
    def setup_temp_directory(self):
        """Create a temporary directory for npm operations"""
        self.temp_dir = tempfile.mkdtemp(prefix="npm_sbom_")
        print(f"Working directory: {self.temp_dir}")
        
    def cleanup_temp_directory(self):
        """Clean up temporary directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            print(f"Cleaned up temporary directory: {self.temp_dir}")
    
    def read_package_json(self) -> Optional[Dict]:
        """Read and parse package.json file"""
        try:
            with open(self.package_json_file, 'r', encoding='utf-8') as file:
                package_data = json.load(file)
            print(f"Read package.json for project: {package_data.get('name', 'unknown')}")
            return package_data
        except Exception as e:
            print(f"Error reading package.json file: {e}")
            return None
    
    def extract_packages_from_json(self, package_data: Dict) -> List[Dict[str, str]]:
        """Extract dependencies and devDependencies from package.json"""
        packages = []
        
        # Store root project info
        self.sbom_data["root_project"] = {
            "name": package_data.get("name", "unknown"),
            "version": package_data.get("version", "unknown"),
            "description": package_data.get("description", ""),
            "license": package_data.get("license", "")
        }
        
        # Extract regular dependencies
        dependencies = package_data.get("dependencies", {})
        for name, version in dependencies.items():
            packages.append({
                'name': name,
                'version': version.lstrip('^~>=<'),  # Remove version prefixes
                'type': 'dependency'
            })
        
        # Extract devDependencies
        dev_dependencies = package_data.get("devDependencies", {})
        for name, version in dev_dependencies.items():
            packages.append({
                'name': name,
                'version': version.lstrip('^~>=<'),  # Remove version prefixes
                'type': 'devDependency'
            })
        
        print(f"Found {len(dependencies)} dependencies and {len(dev_dependencies)} devDependencies")
        return packages
    
    def create_package_json(self, work_dir: str):
        """Create a minimal package.json for npm operations"""
        package_json = {
            "name": "sbom-temp-project",
            "version": "1.0.0",
            "description": "Temporary project for SBOM generation",
            "private": True
        }
        
        package_json_path = os.path.join(work_dir, "package.json")
        with open(package_json_path, 'w') as f:
            json.dump(package_json, f, indent=2)
    
    def install_package(self, package_name: str, version: str, work_dir: str) -> bool:
        """Install a single package using npm with --package-lock-only"""
        package_spec = f"{package_name}@{version}"
        
        try:
            # Remove existing package-lock.json if it exists
            lock_file = os.path.join(work_dir, "package-lock.json")
            if os.path.exists(lock_file):
                os.remove(lock_file)
            
            # Run npm install with the specified flags
            cmd = [
                "npm", "install", package_spec,
                "--package-lock-only",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund"
            ]
            
            print(f"Installing {package_spec}...")
            result = subprocess.run(
                cmd,
                cwd=work_dir,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout
            )
            
            if result.returncode == 0:
                print(f"✓ Successfully installed {package_spec}")
                return True
            else:
                print(f"✗ Failed to install {package_spec}: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"✗ Timeout installing {package_spec}")
            return False
        except Exception as e:
            print(f"✗ Error installing {package_spec}: {e}")
            return False
    
    def parse_package_lock(self, work_dir: str) -> Optional[Dict]:
        """Parse package-lock.json and extract dependency information"""
        lock_file = os.path.join(work_dir, "package-lock.json")
        
        if not os.path.exists(lock_file):
            print("No package-lock.json found")
            return None
        
        try:
            with open(lock_file, 'r', encoding='utf-8') as f:
                lock_data = json.load(f)
            return lock_data
        except Exception as e:
            print(f"Error parsing package-lock.json: {e}")
            return None
    
    def extract_dependencies(self, lock_data: Dict) -> Dict[str, Dict]:
        """Extract all dependencies from package-lock.json"""
        dependencies = {}
        
        # Handle both npm v6 and v7+ formats
        if "dependencies" in lock_data:
            # npm v6 format
            for name, info in lock_data.get("dependencies", {}).items():
                dependencies[name] = {
                    "version": info.get("version", "unknown"),
                    "resolved": info.get("resolved", ""),
                    "integrity": info.get("integrity", ""),
                    "dev": info.get("dev", False),
                    "optional": info.get("optional", False),
                    "requires": info.get("requires", {}),
                    "dependencies": info.get("dependencies", {})
                }
        
        if "packages" in lock_data:
            # npm v7+ format
            for path, info in lock_data.get("packages", {}).items():
                if path == "":  # Skip root package
                    continue
                
                # Extract package name from path
                name = path.replace("node_modules/", "").split("/")[-1]
                if path.startswith("node_modules/@"):
                    # Handle scoped packages
                    parts = path.replace("node_modules/", "").split("/")
                    if len(parts) >= 2:
                        name = f"{parts[0]}/{parts[1]}"
                
                dependencies[name] = {
                    "version": info.get("version", "unknown"),
                    "resolved": info.get("resolved", ""),
                    "integrity": info.get("integrity", ""),
                    "dev": info.get("dev", False),
                    "optional": info.get("optional", False),
                    "requires": info.get("dependencies", {}),
                    "peer": info.get("peerDependencies", {}),
                    "engines": info.get("engines", {})
                }
        
        return dependencies
    
    def process_package(self, package_info: Dict[str, str]) -> Dict:
        """Process a single package and return its dependency information"""
        package_name = package_info['name']
        version = package_info['version']
        package_type = package_info['type']
        
        package_key = f"{package_name}@{version}"
        
        if package_key in self.processed_packages:
            print(f"Skipping already processed package: {package_key}")
            return {}
        
        print(f"\n--- Processing {package_key} ({package_type}) ---")
        
        # Create a unique work directory for this package
        work_dir = os.path.join(self.temp_dir, f"pkg_{hashlib.md5(package_key.encode()).hexdigest()[:8]}")
        os.makedirs(work_dir, exist_ok=True)
        
        # Create package.json
        self.create_package_json(work_dir)
        
        # Install the package
        if not self.install_package(package_name, version, work_dir):
            return {}
        
        # Parse the resulting package-lock.json
        lock_data = self.parse_package_lock(work_dir)
        if not lock_data:
            return {}
        
        # Extract dependencies
        dependencies = self.extract_dependencies(lock_data)
        
        # Store package information
        package_data = {
            "name": package_name,
            "version": version,
            "type": package_type,
            "parent": package_info.get('parent', 'root'),
            "depth": package_info.get('depth', 0),
            "dependencies": dependencies,
            "dependency_count": len(dependencies),
            "processed_at": datetime.now().isoformat()
        }
        
        self.sbom_data["packages"][package_key] = package_data
        self.sbom_data["dependency_tree"][package_key] = list(dependencies.keys())
        self.processed_packages.add(package_key)
        
        print(f"✓ Found {len(dependencies)} dependencies for {package_key}")
        
        return dependencies
    
    def generate_statistics(self):
        """Generate statistics about the SBOM"""
        total_packages = len(self.sbom_data["packages"])
        
        # Count unique package names (ignoring versions)
        unique_names = set()
        packages_with_deps = 0
        dependencies_count = 0
        dev_dependencies_count = 0
        
        for package_key, package_data in self.sbom_data["packages"].items():
            unique_names.add(package_data["name"])
            if package_data["dependency_count"] > 0:
                packages_with_deps += 1
            
            if package_data["type"] == "dependency":
                dependencies_count += 1
            elif package_data["type"] == "devDependency":
                dev_dependencies_count += 1
        
        # Count all dependencies across all packages
        all_dependencies = set()
        for package_data in self.sbom_data["packages"].values():
            for dep_name in package_data["dependencies"].keys():
                all_dependencies.add(dep_name)
        
        # Count packages by depth
        depth_counts = {}
        for package_data in self.sbom_data["packages"].values():
            depth = package_data.get('depth', 0)
            depth_counts[depth] = depth_counts.get(depth, 0) + 1
        
        self.sbom_data["statistics"] = {
            "total_packages_analyzed": total_packages,
            "root_dependencies": dependencies_count,
            "root_dev_dependencies": dev_dependencies_count,
            "unique_package_names": len(unique_names),
            "packages_with_dependencies": packages_with_deps,
            "total_unique_dependencies": len(all_dependencies),
            "total_dependency_relationships": sum(
                len(pkg["dependencies"]) for pkg in self.sbom_data["packages"].values()
            ),
            "max_depth_reached": max(depth_counts.keys()) if depth_counts else 0,
            "packages_by_depth": depth_counts
        }
    
    def save_sbom(self):
        """Save the SBOM data to JSON file"""
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(self.sbom_data, f, indent=2, ensure_ascii=False)
            print(f"\n✓ SBOM saved to: {self.output_file}")
            
            # Print summary
            stats = self.sbom_data["statistics"]
            root_project = self.sbom_data["root_project"]
            print(f"\n--- SBOM Summary ---")
            print(f"Project: {root_project['name']} v{root_project['version']}")
            print(f"Total packages analyzed: {stats['total_packages_analyzed']}")
            print(f"Root dependencies: {stats['root_dependencies']}")
            print(f"Root devDependencies: {stats['root_dev_dependencies']}")
            print(f"Unique package names: {stats['unique_package_names']}")
            print(f"Packages with dependencies: {stats['packages_with_dependencies']}")
            print(f"Total unique dependencies found: {stats['total_unique_dependencies']}")
            print(f"Total dependency relationships: {stats['total_dependency_relationships']}")
            print(f"Maximum depth reached: {stats['max_depth_reached']}")
            print(f"Packages by depth: {stats['packages_by_depth']}")
            
        except Exception as e:
            print(f"Error saving SBOM: {e}")
    
    def add_packages_to_queue(self, dependencies: Dict, parent_package: str, depth: int):
        """Add discovered dependencies to the processing queue"""
        for dep_name, dep_info in dependencies.items():
            # Extract version, handling different formats
            version = dep_info.get('version', 'latest')
            if version.startswith('file:') or version.startswith('git+') or version.startswith('http'):
                continue  # Skip non-registry dependencies
            
            package_key = f"{dep_name}@{version}"
            
            # Only add if not already processed or queued
            if (package_key not in self.processed_packages and 
                not any(p['name'] == dep_name and p['version'] == version 
                       for p in self.packages_to_process)):
                
                self.packages_to_process.append({
                    'name': dep_name,
                    'version': version,
                    'type': 'transitive_dependency',
                    'parent': parent_package,
                    'depth': depth
                })
    
    def process_all_packages_recursively(self):
        """Process packages recursively until no more dependencies are found"""
        if not self.use_multiprocessing:
            return self._process_packages_sequential()
        else:
            return self._process_packages_parallel()
    
    def _process_packages_sequential(self):
        """Sequential processing (original method)"""
        processed_count = 0
        
        while self.packages_to_process:
            package_info = self.packages_to_process.pop(0)
            processed_count += 1
            
            # Check depth limit (if set)
            if self.max_depth is not None and package_info.get('depth', 0) > self.max_depth:
                print(f"Skipping {package_info['name']} - max depth ({self.max_depth}) reached")
                continue
            
            package_key = f"{package_info['name']}@{package_info['version']}"
            
            if package_key in self.processed_packages:
                continue
            
            print(f"\n[{processed_count}] Processing {package_key} (depth: {package_info.get('depth', 0)})")
            
            try:
                # Process the package and get its dependencies
                dependencies = self.process_package(package_info)
                
                # Add newly discovered dependencies to the queue
                if dependencies and (self.max_depth is None or package_info.get('depth', 0) < self.max_depth):
                    self.add_packages_to_queue(
                        dependencies, 
                        package_key, 
                        package_info.get('depth', 0) + 1
                    )
                    
            except Exception as e:
                print(f"Error processing package {package_info}: {e}")
                continue
    
    def _process_packages_parallel(self):
        """Parallel processing using multiprocessing"""
        processed_count = 0
        
        print(f"Using {self.max_workers} worker processes for parallel processing")
        
        while self.packages_to_process:
            # Get batch of packages to process
            current_batch = []
            batch_size = min(len(self.packages_to_process), self.max_workers * 2)
            
            for _ in range(batch_size):
                if not self.packages_to_process:
                    break
                    
                package_info = self.packages_to_process.pop(0)
                
                # Check depth limit and duplicates
                if self.max_depth is not None and package_info.get('depth', 0) > self.max_depth:
                    continue
                
                package_key = f"{package_info['name']}@{package_info['version']}"
                if package_key in self.processed_packages:
                    continue
                
                current_batch.append(package_info)
                self.processed_packages.add(package_key)
            
            if not current_batch:
                break
            
            print(f"\nProcessing batch of {len(current_batch)} packages...")
            
            # Process batch in parallel
            with Pool(processes=self.max_workers) as pool:
                # Use starmap to pass both arguments
                worker_args = [(pkg, self.temp_dir) for pkg in current_batch]
                
                # Process packages in parallel
                results = pool.starmap(process_package_worker, worker_args)
            
            # Process results
            for i, result in enumerate(results):
                processed_count += 1
                
                if result is None:
                    continue
                
                package_key = result["package_key"]
                package_data = result["package_data"]
                new_dependencies = result["new_dependencies"]
                
                print(f"✓ [{processed_count}] Completed {package_key} (depth: {package_data['depth']}) - {len(new_dependencies)} deps")
                
                # Store results
                self.sbom_data["packages"][package_key] = package_data
                self.sbom_data["dependency_tree"][package_key] = list(new_dependencies.keys())
                
                # Add newly discovered dependencies to queue
                if new_dependencies and (self.max_depth is None or package_data['depth'] < self.max_depth):
                    self.add_packages_to_queue(
                        new_dependencies,
                        package_key,
                        package_data['depth'] + 1
                    )
            
            print(f"Batch completed. Queue size: {len(self.packages_to_process)}")
    
    def run(self):
        """Main execution method"""
        try:
            print("Starting NPM SBOM Generation (Recursive Analysis)...")
            
            # Setup
            self.setup_temp_directory()
            
            # Read package.json
            package_data = self.read_package_json()
            if not package_data:
                print("Failed to read package.json")
                return
            
            # Extract packages from package.json
            initial_packages = self.extract_packages_from_json(package_data)
            if not initial_packages:
                print("No packages to process")
                return
            
            # Add initial packages to processing queue with depth 0
            for package_info in initial_packages:
                package_info['depth'] = 0
                self.packages_to_process.append(package_info)
            
            print(f"Starting with {len(initial_packages)} root packages")
            if self.max_depth is None:
                print("Maximum recursion depth: INFINITE (will process until no new dependencies found)")
            else:
                print(f"Maximum recursion depth: {self.max_depth}")
            
            if self.use_multiprocessing:
                print(f"Multiprocessing enabled with {self.max_workers} workers")
            else:
                print("Sequential processing (multiprocessing disabled)")
            
            # Process all packages recursively
            self.process_all_packages_recursively()
            
            # Generate statistics
            self.generate_statistics()
            
            # Save results
            self.save_sbom()
            
        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user")
        except Exception as e:
            print(f"Unexpected error: {e}")
        finally:
            # Cleanup
            self.cleanup_temp_directory()




def calculate_retry_delay(attempt: int, base_delay: float = 1.0, max_delay: float = 30.0) -> float:
    """Calculate exponential backoff delay with jitter"""
    # Exponential backoff: base_delay * (2 ^ attempt)
    delay = base_delay * (2 ** attempt)
    
    # Add jitter (±25% randomization)
    jitter = delay * 0.25 * (2 * random.random() - 1)
    delay += jitter
    
    # Cap at max_delay
    return min(delay, max_delay)


def process_package_worker(package_info: Dict, temp_base_dir: str) -> Optional[Dict]:
    """Worker function for multiprocessing - processes a single package"""
    try:
        package_name = package_info['name']
        version = package_info['version']
        package_type = package_info['type']
        package_key = f"{package_name}@{version}"
        
        # Create unique work directory for this worker
        worker_id = os.getpid()
        work_dir = os.path.join(temp_base_dir, f"worker_{worker_id}_{hashlib.md5(package_key.encode()).hexdigest()[:8]}")
        os.makedirs(work_dir, exist_ok=True)
        
        try:
            # Create package.json
            package_json = {
                "name": "sbom-temp-project",
                "version": "1.0.0",
                "description": "Temporary project for SBOM generation",
                "private": True
            }
            
            package_json_path = os.path.join(work_dir, "package.json")
            with open(package_json_path, 'w') as f:
                json.dump(package_json, f, indent=2)
            
            # Install package with retry logic
            package_spec = f"{package_name}@{version}"
            
            success = False
            last_error = None
            
            for attempt in range(3):  # max_retries = 3
                try:
                    cmd = [
                        "npm", "install", package_spec,
                        "--package-lock-only",
                        "--ignore-scripts",
                        "--no-audit",
                        "--no-fund"
                    ]
                    
                    result = subprocess.run(
                        cmd,
                        cwd=work_dir,
                        capture_output=True,
                        text=True,
                        timeout=120
                    )
                    
                    if result.returncode == 0:
                        success = True
                        break
                    else:
                        last_error = result.stderr
                        
                        # Retry on any failure
                        if attempt < 2:  # Don't sleep on last attempt
                            delay = calculate_retry_delay(attempt)
                            print(f"⚠ Attempt {attempt + 1} failed for {package_spec}, retrying in {delay:.1f}s...")
                            time.sleep(delay)
                        continue
                            
                except subprocess.TimeoutExpired:
                    last_error = "Timeout expired"
                    if attempt < 2:
                        delay = calculate_retry_delay(attempt)
                        print(f"⚠ Timeout for {package_spec} (attempt {attempt + 1}), retrying in {delay:.1f}s...")
                        time.sleep(delay)
                    continue
                except Exception as e:
                    last_error = str(e)
                    break
            
            if not success:
                print(f"✗ Failed to install {package_spec} after 3 attempts: {last_error}")
                return None
            
            # Parse package-lock.json
            lock_file = os.path.join(work_dir, "package-lock.json")
            if not os.path.exists(lock_file):
                return None
            
            with open(lock_file, 'r', encoding='utf-8') as f:
                lock_data = json.load(f)
            
            # Extract dependencies
            dependencies = {}
            
            # Handle both npm v6 and v7+ formats
            if "dependencies" in lock_data:
                for name, info in lock_data.get("dependencies", {}).items():
                    dependencies[name] = {
                        "version": info.get("version", "unknown"),
                        "resolved": info.get("resolved", ""),
                        "integrity": info.get("integrity", ""),
                        "dev": info.get("dev", False),
                        "optional": info.get("optional", False),
                        "requires": info.get("requires", {}),
                        "dependencies": info.get("dependencies", {})
                    }
            
            if "packages" in lock_data:
                for path, info in lock_data.get("packages", {}).items():
                    if path == "":
                        continue
                    
                    name = path.replace("node_modules/", "").split("/")[-1]
                    if path.startswith("node_modules/@"):
                        parts = path.replace("node_modules/", "").split("/")
                        if len(parts) >= 2:
                            name = f"{parts[0]}/{parts[1]}"
                    
                    dependencies[name] = {
                        "version": info.get("version", "unknown"),
                        "resolved": info.get("resolved", ""),
                        "integrity": info.get("integrity", ""),
                        "dev": info.get("dev", False),
                        "optional": info.get("optional", False),
                        "requires": info.get("dependencies", {}),
                        "peer": info.get("peerDependencies", {}),
                        "engines": info.get("engines", {})
                    }
            
            return {
                "package_key": package_key,
                "package_data": {
                    "name": package_name,
                    "version": version,
                    "type": package_type,
                    "parent": package_info.get('parent', 'root'),
                    "depth": package_info.get('depth', 0),
                    "dependencies": dependencies,
                    "dependency_count": len(dependencies),
                    "processed_at": datetime.now().isoformat()
                },
                "new_dependencies": dependencies
            }
            
        finally:
            # Cleanup worker directory
            if os.path.exists(work_dir):
                shutil.rmtree(work_dir)
                
    except Exception as e:
        print(f"Error processing {package_info}: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Generate NPM SBOM from package.json file (recursive analysis)")
    parser.add_argument("package_json", help="Path to package.json file")
    parser.add_argument("-o", "--output", help="Output JSON file (default: npm_sbom.json)", 
                       default="npm_sbom.json")
    parser.add_argument("-d", "--max-depth", type=int, default=10,
                       help="Maximum recursion depth (default: 10, use 0 for infinite)")
    parser.add_argument("-w", "--workers", type=int, default=mp.cpu_count(),
                       help=f"Number of worker processes (default: {mp.cpu_count()})")
    parser.add_argument("--no-multiprocessing", action="store_true",
                       help="Disable multiprocessing (use single thread)")
    parser.add_argument("-r", "--max-retries", type=int, default=3,
                       help="Maximum number of retry attempts for failed npm installs (default: 3)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.package_json):
        print(f"Error: package.json file not found: {args.package_json}")
        sys.exit(1)
    
    generator = NPMSBOMGenerator(args.package_json, args.output)
    generator.max_depth = None if args.max_depth == 0 else args.max_depth
    generator.max_workers = args.workers
    generator.use_multiprocessing = not args.no_multiprocessing
    generator.max_retries = args.max_retries
    generator.run()


if __name__ == "__main__":
    main()
