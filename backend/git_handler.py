import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional, Tuple
import re

try:
    from git import Repo, GitCommandError
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False
    GitCommandError = Exception


class GitHandler:
    """Handles Git repository operations"""
    
    def __init__(self, temp_dir: Optional[str] = None):
        """
        Initialize Git handler
        
        Args:
            temp_dir: Directory to store cloned repositories. If None, uses system temp directory
        """
        self.temp_dir = temp_dir or tempfile.gettempdir()
        self.repos_dir = os.path.join(self.temp_dir, "vulnerability_scanner_repos")
        os.makedirs(self.repos_dir, exist_ok=True)
    
    def clone_repository(self, repo_url: str, branch: Optional[str] = None) -> Tuple[str, str]:
        """
        Clone a Git repository
        
        Args:
            repo_url: URL of the Git repository
            branch: Optional branch name to checkout. If None, uses default branch
        
        Returns:
            Tuple of (repo_path, repo_name)
        
        Raises:
            Exception: If cloning fails
        """
        if not GIT_AVAILABLE:
            raise Exception("GitPython is not installed. Install with: pip install gitpython")
        
        try:
            # Extract repo name from URL
            repo_name = self._extract_repo_name(repo_url)
            
            # Create unique directory for this repo
            repo_path = os.path.join(self.repos_dir, repo_name)
            
            # Remove existing directory if it exists
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
            
            # Clone repository
            print(f"Cloning repository: {repo_url}")
            if branch:
                repo = Repo.clone_from(repo_url, repo_path, branch=branch, depth=1)
            else:
                repo = Repo.clone_from(repo_url, repo_path, depth=1)
            
            print(f"Repository cloned successfully to: {repo_path}")
            return repo_path, repo_name
        
        except GitCommandError as e:
            raise Exception(f"Failed to clone repository: {str(e)}")
        except Exception as e:
            raise Exception(f"Error cloning repository: {str(e)}")
    
    def _extract_repo_name(self, repo_url: str) -> str:
        """Extract repository name from URL"""
        # Handle different URL formats
        # https://github.com/user/repo.git -> user-repo
        # git@github.com:user/repo.git -> user-repo
        # https://github.com/user/repo -> user-repo
        
        # Remove .git extension
        repo_url = repo_url.rstrip('.git')
        
        # Extract last part of path
        if '/' in repo_url:
            parts = repo_url.rstrip('/').split('/')
            repo_name = parts[-1]
            
            # Add username for uniqueness if available
            if len(parts) >= 2 and ('github.com' in repo_url or 'gitlab.com' in repo_url):
                username = parts[-2]
                repo_name = f"{username}-{repo_name}"
        else:
            repo_name = repo_url
        
        # Clean repo name (remove invalid characters)
        repo_name = re.sub(r'[^\w\-_.]', '_', repo_name)
        
        return repo_name
    
    def get_repository_files(self, repo_path: str, languages: list = ['python', 'cpp', 'ros2', 'automotive']) -> dict:
        """
        Get all code files from repository
        
        Args:
            repo_path: Path to cloned repository
            languages: List of languages to filter (python, cpp, ros2, automotive)
        
        Returns:
            Dictionary mapping file paths to language types
        """
        languages = languages or ['python', 'cpp', 'ros2', 'automotive']
        files = {}
        
        extensions = {
            'python': ['.py'],
            'cpp': ['.cpp', '.cxx', '.cc', '.c++', '.c', '.hpp', '.h', '.hxx', '.h++'],  # Added .c to cpp
            'automotive': [
                # Source code files
                '.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx',
                # AUTOSAR files
                '.arxml',  # AUTOSAR XML
                '.arxml.gz',  # Compressed AUTOSAR XML
                # CAN/LIN files
                '.dbc',  # CAN Database (Vector CANdb++)
                '.ldf',  # LIN Description File
                '.sym',  # CAN Symbol file
                # Diagnostic files
                '.a2l',  # ASAM MCD-2MC (A2L) - ECU description
                '.odx',  # Open Diagnostic Data Exchange
                '.pdx',  # PDX diagnostic files
                '.cdd',  # CANdelaStudio diagnostic description
                # ECU configuration
                '.ecuc',  # ECU Configuration
                '.epc',  # ECU Parameter Configuration
                # Other automotive formats
                '.hex',  # Intel HEX files (firmware)
                '.s19',  # Motorola S-record files
                '.srec',  # S-record files
                '.elf',  # Executable and Linkable Format
                '.bin',  # Binary files (firmware)
            ],
            'frontend': [
                '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte',  # JavaScript/TypeScript frameworks
                '.html', '.css', '.scss', '.sass', '.less',  # Web files
            ]
        }
        
        allowed_extensions = []
        if 'python' in languages:
            allowed_extensions.extend(extensions['python'])
        if 'cpp' in languages:
            allowed_extensions.extend(extensions['cpp'])
        if 'automotive' in languages:
            # Add automotive extensions, but avoid duplicates
            for ext in extensions['automotive']:
                if ext not in allowed_extensions:
                    allowed_extensions.append(ext)
        if 'frontend' in languages:
            # Add frontend extensions, but avoid duplicates
            for ext in extensions['frontend']:
                if ext not in allowed_extensions:
                    allowed_extensions.append(ext)
        
        for root, dirs, filenames in os.walk(repo_path):
            # Skip hidden directories and common ignored directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'venv', 'env', 'build', 'dist', '.git']]
            
            for filename in filenames:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, repo_path)
                
                ext = Path(filename).suffix.lower()
                
                # Skip .json files - only scan code files, not configuration files
                # But keep automotive-specific files (ARXML, DBC, A2L, etc.)
                if ext == '.json':
                    continue
                
                # Standard Python/C++/Frontend files
                if ext in allowed_extensions:
                    # Determine language based on extension
                    if ext in extensions.get('python', []):
                        language = 'python'
                    elif ext in extensions.get('frontend', []):
                        language = 'javascript'  # Treat frontend files as JavaScript for scanning
                    elif ext in extensions.get('cpp', []):
                        language = 'cpp'
                    elif ext in extensions.get('automotive', []):
                        # For .c files, check if it's C or C++ based on context
                        if ext == '.c':
                            language = 'cpp'  # Treat .c files as C++ for scanning
                        else:
                            language = 'automotive'
                    else:
                        language = 'cpp'  # Default fallback
                    
                    files[rel_path] = {
                        'full_path': file_path,
                        'language': language,
                        'extension': ext
                    }
                    continue
                
                # ROS 2 specific configuration / launch files
                if 'ros2' in languages and self._is_ros2_config_file(rel_path):
                    files[rel_path] = {
                        'full_path': file_path,
                        'language': 'ros2',
                        'extension': ext
                    }
                    continue
                
                # Automotive-specific files (AUTOSAR, CAN, ECU, etc.)
                if 'automotive' in languages and self._is_automotive_file(rel_path, ext):
                    files[rel_path] = {
                        'full_path': file_path,
                        'language': 'automotive',
                        'extension': ext
                    }
        
        return files
    
    def cleanup_repository(self, repo_path: str) -> None:
        """Remove cloned repository"""
        try:
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
                print(f"Cleaned up repository: {repo_path}")
        except Exception as e:
            print(f"Error cleaning up repository {repo_path}: {e}")
    
    def validate_repo_url(self, repo_url: str) -> bool:
        """Validate if the URL is a valid Git repository URL"""
        if not repo_url or not isinstance(repo_url, str):
            return False
        
        # Common Git URL patterns
        patterns = [
            r'^https?://(?:www\.)?github\.com/[^/\s]+/[^/\s]+(?:\.git)?/?$',
            r'^https?://(?:www\.)?gitlab\.com/[^/\s]+/[^/\s]+(?:\.git)?/?$',
            r'^git@(?:github|gitlab)\.com:[^/\s]+/[^/\s]+(?:\.git)?/?$',
            r'^https?://[^/\s]+/[^/\s]+/[^/\s]+(?:\.git)?/?$',  # Generic Git server
        ]
        
        return any(re.match(pattern, repo_url.strip()) for pattern in patterns)

    def _is_ros2_config_file(self, rel_path: str) -> bool:
        """Identify ROS 2 specific launch or parameter files."""
        rel_path_lower = rel_path.lower()
        filename = os.path.basename(rel_path_lower)
        
        if filename == "package.xml":
            return True
        if filename.endswith((".launch.xml", ".launch.yaml", ".launch.yml")):
            return True
        if filename.endswith((".params.yaml", ".params.yml")):
            return True
        if filename.endswith((".yaml", ".yml")) and any(
            token in rel_path_lower for token in ["launch", "param", "config", "ros2", "dds", "security"]
        ):
            return True
        if filename.endswith(".xml") and "launch" in filename:
            return True
        
        return False

    def _is_automotive_file(self, rel_path: str, ext: str) -> bool:
        """Identify automotive-specific files (AUTOSAR, CAN, ECU, diagnostic, etc.)."""
        rel_path_lower = rel_path.lower()
        filename = os.path.basename(rel_path_lower)
        dir_path = os.path.dirname(rel_path_lower)
        
        # AUTOSAR ARXML files (including compressed)
        if ext in ['.arxml', '.arxml.gz']:
            return True
        
        # CAN/LIN database files
        if ext in ['.dbc', '.ldf', '.sym']:
            return True
        
        # Diagnostic files
        if ext in ['.a2l', '.odx', '.pdx', '.cdd']:
            return True
        
        # ECU configuration files
        if ext in ['.ecuc', '.epc']:
            return True
        
        # Firmware/binary files in automotive context
        if ext in ['.hex', '.s19', '.srec', '.elf', '.bin']:
            # Only include if in automotive directories or with automotive keywords
            automotive_dirs = ['ecu', 'autosar', 'can', 'diagnostic', 'vehicle', 'embedded', 'bsw', 'rte', 'com', 'firmware', 'bootloader']
            automotive_keywords = ['can', 'ecu', 'autosar', 'firmware', 'bootloader', 'flash']
            if any(token in dir_path for token in automotive_dirs) or any(keyword in filename for keyword in automotive_keywords):
                return True
        
        # Files in automotive-related directories
        automotive_dirs = [
            'ecu', 'autosar', 'can', 'diagnostic', 'vehicle', 'embedded', 'bsw', 'rte', 'com',
            'lin', 'flexray', 'most', 'uds', 'obd', 'sensor', 'actuator', 'gateway',
            'firmware', 'bootloader', 'calibration', 'configuration'
        ]
        if any(token in dir_path for token in automotive_dirs):
            # Only include code files, not configuration files like .json, .yaml, .yml
            if ext in ['.c', '.cpp', '.h', '.hpp']:
                return True
        
        # Files with automotive-related names
        automotive_keywords = [
            'can', 'ecu', 'autosar', 'uds', 'obd', 'diagnostic', 'sensor', 'actuator',
            'bcm', 'ecm', 'tcm', 'watchdog', 'bootloader', 'isr', 'interrupt',
            'lin', 'flexray', 'most', 'gateway', 'bsw', 'rte', 'com', 'dcm', 'dem',
            'nvm', 'fim', 'wdtm', 'crypto', 'secoc', 'calibration', 'flash'
        ]
        if any(keyword in filename for keyword in automotive_keywords):
            return True
        
        # XML files with automotive context (but not .json, .yaml, .yml)
        if ext == '.xml':
            automotive_tokens = [
                'ecu', 'autosar', 'can', 'diagnostic', 'vehicle', 'dds', 'lin', 'flexray',
                'uds', 'obd', 'bsw', 'rte', 'com', 'calibration', 'configuration'
            ]
            if any(token in rel_path_lower for token in automotive_tokens):
                return True
        
        return False

