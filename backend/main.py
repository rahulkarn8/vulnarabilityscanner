from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, HTMLResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from datetime import datetime
from suggestion_engine import SuggestionEngine
import os
import sys
import tempfile
import shutil
from dotenv import load_dotenv
from security_middleware import RateLimitMiddleware, SecurityHeadersMiddleware

# Add backend directory to Python path to allow imports when running from project root
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Load environment variables from .env file
load_dotenv()

from code_analyzer import CodeAnalyzer
from vulnerability_detector import VulnerabilityDetector
from model_integration import ModelIntegration
from git_handler import GitHandler
from vulnerability_scanner import VulnerabilityScanner
from ros2_security_scanner import ROS2SecurityScanner
from automotive_security_scanner import AutomotiveSecurityScanner
from ai_attack_scanner import AIAttackScanner
from enhanced_suggestions import EnhancedSuggestions
from pdf_generator import PDFReportGenerator
from compliance_report_generator import ComplianceReportGenerator
from auth import router as auth_router, get_current_user, get_current_user_optional, get_current_admin, User, check_scan_limit, get_db, log_usage, UsageLog
from usage_analytics import get_usage_statistics, get_user_usage_stats
from support_email import send_support_email

app = FastAPI(title="Stratum API - AI Cybersecurity Scanner by Daifend")

# Add security middleware (rate limiting and security headers)
# Rate limit: 60 requests per minute per IP (adjustable)
app.add_middleware(RateLimitMiddleware, requests_per_minute=60)
app.add_middleware(SecurityHeadersMiddleware)

# Include authentication routes
app.include_router(auth_router)

# CORS middleware
# Get allowed origins from environment variable or use defaults
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").split(",") if os.getenv("CORS_ORIGINS") else [
    "https://stratum.daifend.ai",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174"
]
# Filter out empty strings
CORS_ORIGINS = [origin.strip() for origin in CORS_ORIGINS if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Initialize components (will be re-initialized with DB in endpoints)
analyzer = CodeAnalyzer()
vuln_detector = None  # Will be initialized per request with DB
model_integration = ModelIntegration()
git_handler = GitHandler()
vulnerability_scanner = VulnerabilityScanner()
ros2_scanner = ROS2SecurityScanner()
automotive_scanner = AutomotiveSecurityScanner()
ai_attack_scanner = AIAttackScanner()
enhanced_suggestions = EnhancedSuggestions()
compliance_report_generator = ComplianceReportGenerator()

def get_vulnerability_detector(db: Session = Depends(get_db)) -> VulnerabilityDetector:
    """
    Get vulnerability detector with database session for learning.
    For performance, we skip database if it's slow (learned patterns are optional).
    """
    # For faster scans with remote databases, we can skip DB entirely
    # Learned patterns are nice-to-have but not critical
    try:
        return VulnerabilityDetector(db=db)
    except Exception as e:
        # If database is causing issues, create detector without it
        print(f"[WARNING] Creating detector without database (faster scans): {e}")
        return VulnerabilityDetector(db=None)


class AnalysisRequest(BaseModel):
    code: str
    language: str  # "python", "cpp", "ros2", or "automotive"
    file_path: Optional[str] = None


class GitRepoRequest(BaseModel):
    repo_url: str
    branch: Optional[str] = None
    languages: Optional[List[str]] = ["python", "cpp", "ros2", "automotive", "frontend"]

class AIAttackScanRequest(BaseModel):
    code: str
    file_path: Optional[str] = None
    language: Optional[str] = None

class AIAttackScanRequest(BaseModel):
    code: str
    file_path: Optional[str] = None
    language: Optional[str] = None


class VulnerabilityResponse(BaseModel):
    line_number: int
    severity: str
    vulnerability_type: str
    description: str
    code_snippet: str
    suggested_fix: Optional[str] = None
    scanner: Optional[str] = None
    confidence: Optional[str] = None


@app.get("/")
async def root():
    return {
        "message": "Stratum API - AI Cybersecurity Scanner by Daifend",
        "auth_routes": [
            "/auth/test",
            "/auth/github/login",
            "/auth/google/login",
            "/auth/github/callback",
            "/auth/google/callback",
            "/auth/me",
            "/auth/logout"
        ]
    }

@app.get("/routes")
async def list_routes():
    """List all available routes"""
    routes = []
    for route in app.routes:
        if hasattr(route, "path") and hasattr(route, "methods"):
            routes.append({
                "path": route.path,
                "methods": list(route.methods) if route.methods else []
            })
    return {"routes": routes}


@app.post("/analyze", response_model=List[VulnerabilityResponse])
async def analyze_code(
    request: AnalysisRequest,
    request_obj: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
    _: bool = Depends(check_scan_limit)
):
    """Analyze code for vulnerabilities"""
    import time
    start_time = time.time()
    try:
        # Get detector with database for learning
        detector = get_vulnerability_detector(db)
        vulnerabilities = []
        
        # Debug logging
        print(f"[DEBUG] Analyzing code - Language: {request.language}, Code length: {len(request.code)}")
        print(f"[DEBUG] Code preview (first 200 chars): {request.code[:200]}")
        
        # Parse code structure for supported languages
        if request.language in ("python", "cpp"):
            structure = analyzer.parse_code(request.code, request.language)
            detected = detector.detect(request.code, request.language, structure)
            print(f"[DEBUG] Core detector found {len(detected)} vulnerabilities")
            vulnerabilities.extend(detected)
            
            # Learn from discovered vulnerabilities (non-blocking)
            try:
                from vulnerability_learner import VulnerabilityLearner
                learner = VulnerabilityLearner(db)
                for vuln in vulnerabilities:
                    try:
                        code_snippet = vuln.get("code_snippet", "")
                        learner.learn_from_vulnerability(vuln, request.language, code_snippet)
                    except Exception as learn_error:
                        print(f"[WARNING] Failed to learn from vulnerability: {learn_error}")
            except Exception as e:
                print(f"[WARNING] Learning system error (non-blocking): {e}")
        else:
            structure = None
        
        # Add ROS 2 specific findings if applicable
        ros2_vulns = ros2_scanner.scan_code(request.code, request.file_path, request.language)
        if ros2_vulns:
            print(f"[DEBUG] ROS2 scanner found {len(ros2_vulns)} vulnerabilities")
            vulnerabilities.extend(ros2_vulns)
        
        # Add automotive-specific findings if applicable
        automotive_vulns = automotive_scanner.scan_code(request.code, request.file_path, request.language)
        if automotive_vulns:
            print(f"[DEBUG] Automotive scanner found {len(automotive_vulns)} vulnerabilities")
            vulnerabilities.extend(automotive_vulns)
        
        # Add AI-powered attack findings if applicable
        ai_attack_vulns = ai_attack_scanner.scan_code(request.code, request.file_path, request.language)
        if ai_attack_vulns:
            print(f"[DEBUG] AI attack scanner found {len(ai_attack_vulns)} vulnerabilities")
            vulnerabilities.extend(ai_attack_vulns)
        
        print(f"[DEBUG] Total vulnerabilities found: {len(vulnerabilities)}")
        
        # Get suggestions from enhanced model
        results = []
        for vuln in vulnerabilities:
            suggested_fix = await enhanced_suggestions.get_suggestion(
                request.code,
                request.language,
                vuln
            )
            results.append(VulnerabilityResponse(
                line_number=vuln["line_number"],
                severity=vuln["severity"],
                vulnerability_type=vuln["type"],
                description=vuln["description"],
                code_snippet=vuln["code_snippet"],
                suggested_fix=suggested_fix,
                scanner=vuln.get("scanner"),
                confidence=vuln.get("confidence")
            ))
        
        print(f"[DEBUG] Returning {len(results)} vulnerability results")
        
        # Log usage (non-blocking - run in background)
        scan_duration_ms = int((time.time() - start_time) * 1000)
        ip_address = request_obj.client.host if request_obj else None
        # Don't block on usage logging - run in background thread
        import threading
        def log_usage_background():
            try:
                log_usage(
                    db=db,
                    user=current_user,
                    action_type="code_analyze",
                    ip_address=ip_address,
                    files_count=1,
                    vulnerabilities_found=len(results),
                    scan_duration_ms=scan_duration_ms
                )
            except Exception as e:
                print(f"[WARNING] Usage logging failed (non-critical): {e}")
        
        log_thread = threading.Thread(target=log_usage_background, daemon=True)
        log_thread.start()
        
        return results
    except Exception as e:
        import traceback
        print(f"[ERROR] Exception in analyze_code: {str(e)}")
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan-ai-attacks", response_model=List[VulnerabilityResponse])
async def scan_ai_attacks(
    request: AIAttackScanRequest,
    request_obj: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
    _: bool = Depends(check_scan_limit)
):
    """
    Dedicated endpoint to scan code specifically for AI-powered attack vulnerabilities.
    This focuses only on vulnerabilities that make code susceptible to AI attacks like:
    - Prompt injection
    - AI model security issues
    - Adversarial attacks
    - Data poisoning
    - AI code generation security
    - AI API security
    """
    import time
    start_time = time.time()
    try:
        print(f"[DEBUG] AI Attack Scan - Language: {request.language}, Code length: {len(request.code)}")
        
        # Only run AI attack scanner
        ai_attack_vulns = ai_attack_scanner.scan_code(
            request.code, 
            request.file_path, 
            request.language
        )
        
        print(f"[DEBUG] AI attack scanner found {len(ai_attack_vulns)} vulnerabilities")
        
        # Get suggestions for AI attack vulnerabilities
        results = []
        for vuln in ai_attack_vulns:
            suggested_fix = await enhanced_suggestions.get_suggestion(
                request.code,
                request.language or "python",
                vuln
            )
            results.append(VulnerabilityResponse(
                line_number=vuln["line_number"],
                severity=vuln["severity"],
                vulnerability_type=vuln["type"],
                description=vuln["description"],
                code_snippet=vuln["code_snippet"],
                suggested_fix=suggested_fix,
                scanner=vuln.get("scanner") or "ai_attack",
                confidence=vuln.get("confidence")
            ))
        
        # Log usage (non-blocking)
        scan_duration_ms = int((time.time() - start_time) * 1000)
        ip_address = request_obj.client.host if request_obj else None
        import threading
        def log_usage_background():
            try:
                log_usage(
                    db=db,
                    user=current_user,
                    action_type="ai_attack_scan",
                    files_count=1,
                    vulnerabilities_found=len(results),
                    scan_duration_ms=scan_duration_ms,
                    ip_address=ip_address
                )
            except Exception as e:
                print(f"Error logging AI attack scan usage: {e}")
        
        threading.Thread(target=log_usage_background, daemon=True).start()
        
        return results
        
    except Exception as e:
        import traceback
        print(f"[ERROR] Exception in scan_ai_attacks: {str(e)}")
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze-directory")
async def analyze_directory(
    directory_path: str,
    db: Session = Depends(get_db),
    _: bool = Depends(check_scan_limit)
):
    """Analyze all Python and C++ files in a directory"""
    try:
        if not os.path.exists(directory_path):
            raise HTTPException(status_code=404, detail="Directory not found")
        
        results = {}
        
        # Find all Python, C++, and C files
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.endswith(('.py', '.cpp', '.cxx', '.cc', '.c++', '.c', '.hpp', '.h', '.arxml')):
                    file_path = os.path.join(root, file)
                    if file.endswith('.py'):
                        language = "python"
                    elif file.endswith(('.cpp', '.cxx', '.cc', '.c++', '.c', '.hpp', '.h')):
                        language = "cpp"
                    else:
                        language = "automotive"
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            code = f.read()
                        
                        # Get detector with database for learning
                        # Note: This loads learned patterns from DB, which may be slow for remote DBs
                        # The detector will timeout after 3 seconds if DB is too slow
                        detector = get_vulnerability_detector(db)
                        structure = analyzer.parse_code(code, language)
                        vulnerabilities = detector.detect(code, language, structure)
                        
                        # Learn from discovered vulnerabilities (non-blocking)
                        try:
                            from vulnerability_learner import VulnerabilityLearner
                            learner = VulnerabilityLearner(db)
                            for vuln in vulnerabilities:
                                try:
                                    code_snippet = vuln.get("code_snippet", "")
                                    learner.learn_from_vulnerability(vuln, language, code_snippet)
                                except Exception as learn_error:
                                    print(f"[WARNING] Failed to learn from vulnerability: {learn_error}")
                        except Exception as e:
                            print(f"[WARNING] Learning system error (non-blocking): {e}")
                        
                        ros2_vulns = ros2_scanner.scan_code(code, file_path, language)
                        if ros2_vulns:
                            vulnerabilities.extend(ros2_vulns)
                        
                        automotive_vulns = automotive_scanner.scan_code(code, file_path, language)
                        if automotive_vulns:
                            vulnerabilities.extend(automotive_vulns)
                        
                        # Add AI-powered attack findings if applicable
                        ai_attack_vulns = ai_attack_scanner.scan_code(code, file_path, language)
                        if ai_attack_vulns:
                            vulnerabilities.extend(ai_attack_vulns)
                        
                        # Get suggestions for each vulnerability
                        file_results = []
                        for vuln in vulnerabilities:
                            suggested_fix = await enhanced_suggestions.get_suggestion(
                                code, language, vuln
                            )
                            file_results.append({
                                "line_number": vuln["line_number"],
                                "severity": vuln["severity"],
                                "vulnerability_type": vuln["type"],
                                "description": vuln["description"],
                                "code_snippet": vuln["code_snippet"],
                                "suggested_fix": suggested_fix,
                                "scanner": vuln.get("scanner"),
                                "confidence": vuln.get("confidence")
                            })
                        
                        results[file_path] = {
                            "language": language,
                            "vulnerabilities": file_results,
                            "total_vulnerabilities": len(file_results)
                        }
                    except Exception as e:
                        results[file_path] = {
                            "error": str(e),
                            "language": language
                        }
        
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/upload-files")
async def upload_files(
    files: List[UploadFile] = File(...),
    request_obj: Request = None,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
    _: bool = Depends(check_scan_limit)
):
    """Upload and analyze multiple files"""
    import time
    start_time = time.time()
    print(f"[DEBUG] upload-files endpoint called with {len(files)} files")
    results = {}
    
    # Create detector once for all files (faster - avoids repeated DB queries)
    # If database is slow, it will skip learned patterns automatically
    try:
        detector = get_vulnerability_detector(db)
        print("[DEBUG] Detector created with database support")
    except Exception as e:
        print(f"[WARNING] Creating detector without database (faster): {e}")
        detector = VulnerabilityDetector(db=None)
    
    for file in files:
        try:
            content = await file.read()
            code = content.decode('utf-8')
            
            # Get the filename - this should preserve the relative path from directory selection
            # FastAPI's UploadFile.filename should contain the full path if sent correctly
            file_path = file.filename
            print(f"[DEBUG] Processing file: {file_path}, size: {len(code)} chars")
            
            # Determine language from extension
            filename_lower = file_path.lower()
            if filename_lower.endswith('.py'):
                language = "python"
            elif filename_lower.endswith(('.cpp', '.cxx', '.cc', '.c++', '.c', '.hpp', '.h')):
                language = "cpp"
            elif filename_lower.endswith('.arxml'):
                language = "automotive"
            else:
                language = "python"  # Default fallback
            
            print(f"[DEBUG] Detected language: {language} for file {file_path}")
            
            # Use the detector we created once for all files (faster)
            # Parse code structure for supported languages
            if language in ("python", "cpp"):
                structure = analyzer.parse_code(code, language)
                vulnerabilities = detector.detect(code, language, structure)
                print(f"[DEBUG] Core detector found {len(vulnerabilities)} vulnerabilities in {file_path}")
            else:
                structure = None
                vulnerabilities = []
                print(f"[DEBUG] Language {language} not supported for core detection")
            
            # Learn from discovered vulnerabilities (truly non-blocking - run in background)
            # Don't wait for learning to complete, just fire and forget
            if vulnerabilities:
                import threading
                def learn_in_background():
                    try:
                        from vulnerability_learner import VulnerabilityLearner
                        learner = VulnerabilityLearner(db)
                        for vuln in vulnerabilities:
                            try:
                                code_snippet = vuln.get("code_snippet", "")
                                learner.learn_from_vulnerability(vuln, language, code_snippet)
                            except Exception as learn_error:
                                # Learning failed for this vulnerability, but continue processing
                                print(f"[WARNING] Failed to learn from vulnerability: {learn_error}")
                    except Exception as e:
                        # Learning system failed entirely, but don't block the scan
                        print(f"[WARNING] Learning system error (non-blocking): {e}")
                
                # Start learning in background thread, don't wait for it
                learning_thread = threading.Thread(target=learn_in_background, daemon=True)
                learning_thread.start()
            
            # Add ROS 2 specific findings if applicable
            ros2_vulns = ros2_scanner.scan_code(code, file.filename, language)
            if ros2_vulns:
                print(f"[DEBUG] ROS2 scanner found {len(ros2_vulns)} vulnerabilities in {file_path}")
                vulnerabilities.extend(ros2_vulns)
            
            # Add automotive-specific findings if applicable
            automotive_vulns = automotive_scanner.scan_code(code, file.filename, language)
            if automotive_vulns:
                print(f"[DEBUG] Automotive scanner found {len(automotive_vulns)} vulnerabilities in {file_path}")
                vulnerabilities.extend(automotive_vulns)
            
            # Add AI-powered attack findings if applicable
            ai_attack_vulns = ai_attack_scanner.scan_code(code, file.filename, language)
            if ai_attack_vulns:
                print(f"[DEBUG] AI attack scanner found {len(ai_attack_vulns)} vulnerabilities in {file_path}")
                vulnerabilities.extend(ai_attack_vulns)
            
            print(f"[DEBUG] Total vulnerabilities found for {file_path}: {len(vulnerabilities)}")
            
            file_results = []
            for vuln in vulnerabilities:
                suggested_fix = await enhanced_suggestions.get_suggestion(
                    code, language, vuln
                )
                file_results.append({
                    "line_number": vuln["line_number"],
                    "severity": vuln["severity"],
                    "vulnerability_type": vuln["type"],
                    "description": vuln["description"],
                    "code_snippet": vuln["code_snippet"],
                    "suggested_fix": suggested_fix,
                    "scanner": vuln.get("scanner"),
                    "confidence": vuln.get("confidence")
                })
            
            # Use the full filename (which may include relative path from directory selection)
            # This should match the webkitRelativePath from the frontend
            results[file_path] = {
                "language": language,
                "vulnerabilities": file_results,
                "total_vulnerabilities": len(file_results)
            }
            print(f"[DEBUG] Final result for {file_path}: {len(file_results)} vulnerabilities")
        except Exception as e:
            import traceback
            print(f"[ERROR] Exception processing file {file_path if 'file_path' in locals() else 'unknown'}: {str(e)}")
            print(f"[ERROR] Traceback: {traceback.format_exc()}")
            results[file_path if 'file_path' in locals() else 'unknown'] = {
                "error": str(e),
                "language": language if 'language' in locals() else "unknown"
            }
    
    print(f"[DEBUG] Returning results for {len(results)} files")
    return results


@app.post("/analyze-git-repo")
async def analyze_git_repo(
    request: GitRepoRequest,
    request_obj: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
    _: bool = Depends(check_scan_limit)
):
    """Analyze a Git repository for vulnerabilities"""
    import time
    start_time = time.time()
    repo_path = None
    try:
        # Validate repository URL
        if not git_handler.validate_repo_url(request.repo_url):
            raise HTTPException(status_code=400, detail="Invalid Git repository URL")
        
        # Clone repository
        repo_path, repo_name = git_handler.clone_repository(request.repo_url, request.branch)
        
        # Get all code files
        files = git_handler.get_repository_files(repo_path, request.languages)
        
        if not files:
            return {
                "repo_name": repo_name,
                "repo_path": repo_path,
                "message": "No supported source files found in repository",
                "files": {},
                "total_vulnerabilities": 0
            }
        
        results = {}
        total_vulnerabilities = 0
        
        # Analyze each file
        for rel_path, file_info in files.items():
            file_path = file_info['full_path']
            language = file_info['language']
            
            try:
                # Handle text and binary files differently
                # Binary files (.hex, .s19, .srec, .elf, .bin) need special handling
                is_binary = file_path.endswith(('.hex', '.s19', '.srec', '.elf', '.bin'))
                
                if is_binary:
                    # For binary files, read as binary and convert to hex string for analysis
                    with open(file_path, 'rb') as f:
                        binary_data = f.read()
                        # Convert to hex string representation for pattern matching
                        code = binary_data.hex()
                else:
                    # For text files, read normally
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                
                # Use external scanners (Bandit for Python, cppcheck for C++)
                vulnerabilities = []
                if language == "python" and vulnerability_scanner.bandit_path:
                    vulnerabilities = vulnerability_scanner.scan_python_file(file_path)
                elif language == "cpp" and vulnerability_scanner.cppcheck_path:
                    vulnerabilities = vulnerability_scanner.scan_cpp_file(file_path)
                
                # Also use our pattern-based detector for supported languages
                pattern_vulns = []
                if language in ("python", "cpp"):
                    # Get detector with database for learning
                    detector = get_vulnerability_detector(db)
                    structure = analyzer.parse_code(code, language)
                    pattern_vulns = detector.detect(code, language, structure)
                    
                    # Learn from discovered vulnerabilities
                    from vulnerability_learner import VulnerabilityLearner
                    # Learn from discovered vulnerabilities (non-blocking)
                    try:
                        learner = VulnerabilityLearner(db)
                        for vuln in pattern_vulns:
                            try:
                                code_snippet = vuln.get("code_snippet", "")
                                learner.learn_from_vulnerability(vuln, language, code_snippet)
                            except Exception as learn_error:
                                print(f"[WARNING] Failed to learn from vulnerability: {learn_error}")
                    except Exception as e:
                        print(f"[WARNING] Learning system error (non-blocking): {e}")
                
                # Merge vulnerabilities (avoid duplicates)
                existing_signatures = {(v.get("line_number"), v.get("type")) for v in vulnerabilities}
                for pattern_vuln in pattern_vulns:
                    signature = (pattern_vuln.get("line_number"), pattern_vuln.get("type"))
                    if signature not in existing_signatures:
                        vulnerabilities.append(pattern_vuln)
                        existing_signatures.add(signature)
                
                # Add ROS 2 specific findings
                ros2_vulns = ros2_scanner.scan_code(code, file_path, language)
                for ros2_vuln in ros2_vulns:
                    signature = (ros2_vuln.get("line_number"), ros2_vuln.get("type"))
                    if signature not in existing_signatures:
                        vulnerabilities.append(ros2_vuln)
                        existing_signatures.add(ros2_vuln)
                
                # Add automotive-specific findings (for all automotive files including .arxml, .dbc, .a2l, etc.)
                if language == "automotive" or file_path.endswith(('.arxml', '.dbc', '.ldf', '.a2l', '.odx', '.pdx', '.cdd', '.ecuc', '.epc')):
                    automotive_vulns = automotive_scanner.scan_code(code, file_path, language)
                    for automotive_vuln in automotive_vulns:
                        signature = (automotive_vuln.get("line_number"), automotive_vuln.get("type"))
                        if signature not in existing_signatures:
                            vulnerabilities.append(automotive_vuln)
                            existing_signatures.add(signature)
                
                # Add automotive-specific findings
                automotive_vulns = automotive_scanner.scan_code(code, file_path, language)
                for automotive_vuln in automotive_vulns:
                    signature = (automotive_vuln.get("line_number"), automotive_vuln.get("type"))
                    if signature not in existing_signatures:
                        vulnerabilities.append(automotive_vuln)
                        existing_signatures.add(signature)
                
                # Add AI-powered attack findings
                ai_attack_vulns = ai_attack_scanner.scan_code(code, file_path, language)
                for ai_attack_vuln in ai_attack_vulns:
                    signature = (ai_attack_vuln.get("line_number"), ai_attack_vuln.get("type"))
                    if signature not in existing_signatures:
                        vulnerabilities.append(ai_attack_vuln)
                        existing_signatures.add(signature)
                
                # Get suggestions for each vulnerability
                file_results = []
                for vuln in vulnerabilities:
                    suggested_fix = await enhanced_suggestions.get_suggestion(
                        code, language, vuln
                    )
                    file_results.append({
                        "line_number": vuln.get("line_number", 0),
                        "severity": vuln.get("severity", "medium"),
                        "vulnerability_type": vuln.get("type", "Unknown"),
                        "description": vuln.get("description", ""),
                        "code_snippet": vuln.get("code_snippet", ""),
                        "suggested_fix": suggested_fix,
                        "scanner": vuln.get("scanner", "pattern"),
                        "confidence": vuln.get("confidence")
                    })
                
                total_vulnerabilities += len(file_results)
                results[rel_path] = {
                    "language": language,
                    "vulnerabilities": file_results,
                    "total_vulnerabilities": len(file_results),
                    "full_path": file_path
                }
            
            except Exception as e:
                results[rel_path] = {
                    "error": str(e),
                    "language": language,
                    "full_path": file_path
                }
        
        # Log usage
        scan_duration_ms = int((time.time() - start_time) * 1000)
        ip_address = request_obj.client.host if request_obj else None
        log_usage(
            db=db,
            user=current_user,
            action_type="git_repo_scan",
            ip_address=ip_address,
            files_count=len(files),
            vulnerabilities_found=total_vulnerabilities,
            scan_duration_ms=scan_duration_ms
        )
        
        return {
            "repo_name": repo_name,
            "repo_url": request.repo_url,
            "branch": request.branch,
            "files": results,
            "total_vulnerabilities": total_vulnerabilities,
            "total_files": len(files),
            "repo_path": repo_path  # Return for potential cleanup
        }
    
    except HTTPException:
        raise
    except Exception as e:
        # Cleanup on error
        if repo_path and os.path.exists(repo_path):
            try:
                git_handler.cleanup_repository(repo_path)
            except:
                pass
        raise HTTPException(status_code=500, detail=f"Error analyzing repository: {str(e)}")


@app.get("/read-file")
async def read_file(file_path: str):
    """Read file content from a repository"""
    try:
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="File not found")
        
        # Security check: ensure file is within allowed directory
        if not file_path.startswith(git_handler.repos_dir):
            raise HTTPException(status_code=403, detail="Access denied")
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        return {
            "content": content,
            "file_path": file_path
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/cleanup-repo/{repo_path:path}")
async def cleanup_repository(repo_path: str):
    """Clean up a cloned repository"""
    try:
        if not os.path.exists(repo_path):
            raise HTTPException(status_code=404, detail="Repository path not found")
        
        # Security check
        if not repo_path.startswith(git_handler.repos_dir):
            raise HTTPException(status_code=403, detail="Access denied")
        
        git_handler.cleanup_repository(repo_path)
        return {"message": "Repository cleaned up successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Payment endpoints
try:
    import stripe
    stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
    STRIPE_ENABLED = bool(stripe.api_key)
except ImportError:
    STRIPE_ENABLED = False
    stripe = None

class CheckoutRequest(BaseModel):
    plan_id: str
    success_url: str
    cancel_url: str

# Pricing plans configuration
PRICING_PLANS = {
    "enterprise-basic": {
        "name": "Basic Plan",
        "price": 1000,
        "stripe_price_id": os.getenv("STRIPE_PRICE_ID_BASIC", ""),
        "includes_reports": False,
        "includes_api": False
    },
    "enterprise-pro": {
        "name": "Professional Plan",
        "price": 1500,
        "stripe_price_id": os.getenv("STRIPE_PRICE_ID_PRO", ""),
        "includes_reports": True,
        "includes_api": True
    }
}

@app.post("/payment/create-checkout-session")
async def create_checkout_session(request: CheckoutRequest):
    """Create a Stripe checkout session for subscription"""
    if not STRIPE_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="Payment processing is not configured. Please contact support."
        )
    
    if request.plan_id not in PRICING_PLANS:
        raise HTTPException(status_code=400, detail="Invalid plan ID")
    
    plan = PRICING_PLANS[request.plan_id]
    
    try:
        # Create description based on plan features
        if request.plan_id == "enterprise-basic":
            description = "Unlimited code scanning and vulnerability detection"
        else:
            description = "Unlimited code scanning, vulnerability reports, compliance reports, and API access"
        
        # Create Stripe checkout session
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': plan['name'],
                        'description': description,
                    },
                    'unit_amount': plan['price'] * 100,  # Convert to cents
                    'recurring': {
                        'interval': 'month',
                    },
                },
                'quantity': 1,
            }],
            mode='subscription',
            success_url=request.success_url,
            cancel_url=request.cancel_url,
            metadata={
                'plan_id': request.plan_id,
                'includes_reports': str(plan.get('includes_reports', False)),
                'includes_api': str(plan.get('includes_api', False))
            }
        )
        
        return {
            "session_id": checkout_session.id,
            "session_url": checkout_session.url
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create checkout session: {str(e)}"
        )

@app.get("/payment/supported-languages")
async def get_supported_languages():
    """Get list of supported programming languages"""
    return {
        "languages": [
            {
                "name": "Python",
                "extensions": [".py"],
                "features": [
                    "SQL injection detection",
                    "Command injection prevention",
                    "Hardcoded credentials detection",
                    "Bandit integration"
                ]
            },
            {
                "name": "C++",
                "extensions": [".cpp", ".cxx", ".cc", ".c++", ".hpp", ".h"],
                "features": [
                    "Buffer overflow detection",
                    "Memory leak identification",
                    "cppcheck integration"
                ]
            },
            {
                "name": "C",
                "extensions": [".c", ".h"],
                "features": [
                    "MISRA C compliance",
                    "Unsafe function detection",
                    "Memory safety checks"
                ]
            },
            {
                "name": "ROS 2",
                "extensions": [".launch.py", ".launch.xml", ".launch.yaml"],
                "features": [
                    "Parameter validation",
                    "Security strategy validation",
                    "DDS security configuration"
                ]
            },
            {
                "name": "Automotive",
                "extensions": [".c", ".cpp", ".arxml", ".xml"],
                "features": [
                    "CAN bus security",
                    "AUTOSAR architecture checks",
                    "UDS/OBD-II diagnostic security",
                    "ISO 26262 functional safety"
                ]
            }
        ]
    }

# Vulnerability Learning Endpoints
class AddPatternRequest(BaseModel):
    name: str
    pattern: str
    language: str
    severity: str
    description: str

@app.post("/vulnerabilities/learn")
async def add_vulnerability_pattern(
    request: AddPatternRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add a custom vulnerability pattern (requires authentication)"""
    from vulnerability_learner import VulnerabilityLearner
    
    if request.language not in ("python", "cpp"):
        raise HTTPException(status_code=400, detail="Language must be 'python' or 'cpp'")
    
    if request.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(status_code=400, detail="Severity must be: critical, high, medium, or low")
    
    learner = VulnerabilityLearner(db)
    learned_vuln = learner.add_custom_pattern(
        name=request.name,
        pattern=request.pattern,
        language=request.language,
        severity=request.severity,
        description=request.description
    )
    
    return {
        "id": learned_vuln.id,
        "name": learned_vuln.name,
        "pattern": learned_vuln.pattern,
        "language": learned_vuln.language,
        "severity": learned_vuln.severity,
        "description": learned_vuln.description,
        "message": "Vulnerability pattern added successfully"
    }

@app.get("/vulnerabilities/learned")
async def get_learned_vulnerabilities(
    language: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get all learned vulnerability patterns"""
    from vulnerability_learner import VulnerabilityLearner
    from auth import LearnedVulnerability
    
    learner = VulnerabilityLearner(db)
    
    # Get full details from database
    query = db.query(LearnedVulnerability).filter(
        LearnedVulnerability.is_active == 1
    )
    
    if language:
        query = query.filter(LearnedVulnerability.language == language)
    
    all_patterns = query.all()
    
    return {
        "total": len(all_patterns),
        "patterns": [
            {
                "id": p.id,
                "name": p.name,
                "pattern": p.pattern,
                "language": p.language,
                "severity": p.severity,
                "description": p.description,
                "discovered_count": p.discovered_count,
                "created_at": p.created_at.isoformat() if p.created_at else None,
                "updated_at": p.updated_at.isoformat() if p.updated_at else None
            }
            for p in all_patterns
        ]
    }

# PDF Report Generation
class PDFReportRequest(BaseModel):
    results: Dict[str, Any]  # FileAnalysis results
    scan_type: str = "Code Scan"
    scan_target: str = "Unknown"

@app.post("/generate-pdf-report")
async def generate_pdf_report(
    request: PDFReportRequest,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Generate PDF report from scan results"""
    try:
        pdf_generator = PDFReportGenerator()
        pdf_bytes = pdf_generator.generate_report(
            results=request.results,
            scan_type=request.scan_type,
            scan_target=request.scan_target
        )
        
        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"vulnerability_report_{timestamp}.pdf"
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")


# Compliance Report Generation
class ComplianceReportRequest(BaseModel):
    results: Dict[str, Any]  # FileAnalysis results
    scan_type: str = "Automotive Compliance Scan"
    scan_target: str = "Unknown"

@app.post("/generate-compliance-report")
async def generate_compliance_report(
    request: ComplianceReportRequest,
    request_obj: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Generate compliance report for ISO 21434 and UN R155"""
    try:
        # Collect all vulnerabilities from results
        all_vulnerabilities = []
        files_analyzed = 0
        
        for file_path, file_data in request.results.items():
            if isinstance(file_data, dict):
                files_analyzed += 1
                vulnerabilities = file_data.get("vulnerabilities", [])
                all_vulnerabilities.extend(vulnerabilities)
        
        # Generate compliance report
        compliance_data = compliance_report_generator.generate_compliance_report(
            vulnerabilities=all_vulnerabilities,
            files_analyzed=files_analyzed,
            scan_type=request.scan_type,
            scan_target=request.scan_target
        )
        
        # Log usage
        ip_address = request_obj.client.host if request_obj else None
        total_vulns = sum(
            len(res.get("vulnerabilities", [])) 
            for res in request.results.values() 
            if isinstance(res, dict)
        )
        log_usage(
            db=db,
            user=current_user,
            action_type="compliance_report",
            ip_address=ip_address,
            files_count=len(request.results),
            vulnerabilities_found=total_vulns
        )
        
        return JSONResponse(content=compliance_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate compliance report: {str(e)}")


@app.post("/generate-compliance-pdf")
async def generate_compliance_pdf(
    request: ComplianceReportRequest,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Generate PDF compliance report for ISO 21434 and UN R155"""
    try:
        import traceback
        
        # Collect all vulnerabilities from results
        all_vulnerabilities = []
        files_analyzed = 0
        
        for file_path, file_data in request.results.items():
            if isinstance(file_data, dict):
                files_analyzed += 1
                vulnerabilities = file_data.get("vulnerabilities", [])
                if isinstance(vulnerabilities, list):
                    all_vulnerabilities.extend(vulnerabilities)
        
        print(f"[DEBUG] Generating compliance report for {files_analyzed} files, {len(all_vulnerabilities)} vulnerabilities")
        
        # Generate compliance report data
        compliance_data = compliance_report_generator.generate_compliance_report(
            vulnerabilities=all_vulnerabilities,
            files_analyzed=files_analyzed,
            scan_type=request.scan_type,
            scan_target=request.scan_target
        )
        
        print(f"[DEBUG] Compliance data generated: {list(compliance_data.keys())}")
        
        # Generate PDF
        pdf_generator = PDFReportGenerator()
        pdf_bytes = pdf_generator.generate_compliance_report(
            compliance_data=compliance_data,
            scan_type=request.scan_type,
            scan_target=request.scan_target
        )
        
        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"compliance_report_{timestamp}.pdf"
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
    except Exception as e:
        import traceback
        error_detail = f"Failed to generate compliance PDF: {str(e)}"
        print(f"[ERROR] {error_detail}")
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=error_detail)


# =====================================================================
# Analytics & Usage Tracking Endpoints
# =====================================================================

@app.get("/analytics/usage")
async def get_platform_usage_stats(
    days: int = 30,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin)
):
    """
    Get platform usage statistics (admin/authenticated users only).
    
    Args:
        days: Number of days to look back (default: 30)
        start_date: Start date in ISO format (optional)
        end_date: End date in ISO format (optional)
    """
    try:
        start = datetime.fromisoformat(start_date.replace('Z', '+00:00')) if start_date else None
        end = datetime.fromisoformat(end_date.replace('Z', '+00:00')) if end_date else None
        
        stats = get_usage_statistics(db, days=days, start_date=start, end_date=end)
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get usage statistics: {str(e)}")


@app.get("/analytics/user/{user_id}")
async def get_user_usage_stats_endpoint(
    user_id: int,
    days: int = 30,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin)
):
    """Get usage statistics for a specific user (admin only)"""
    try:
        # Admin can view any user's stats
        stats = get_user_usage_stats(db, user_id, days=days)
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get user statistics: {str(e)}")


@app.get("/analytics/summary")
async def get_usage_summary(
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin)
):
    """Get a quick summary of platform usage"""
    try:
        # Last 7 days
        stats_7d = get_usage_statistics(db, days=7)
        # Last 30 days
        stats_30d = get_usage_statistics(db, days=30)
        # All time
        stats_all = get_usage_statistics(db, days=3650)  # ~10 years
        
        return {
            "last_7_days": stats_7d["summary"],
            "last_30_days": stats_30d["summary"],
            "all_time": stats_all["summary"],
            "recent_trends": stats_30d["daily_trend"][-7:]  # Last 7 days trend
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get usage summary: {str(e)}")


@app.get("/analytics/users")
async def get_users_with_scans(
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
    days: int = 30
):
    """
    Get list of all users who have performed scans.
    Returns user info with their scan statistics.
    """
    try:
        from sqlalchemy import func, and_
        from datetime import timedelta
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Get all users who have scans in the period
        user_scan_stats = db.query(
            User.id,
            User.email,
            User.name,
            User.subscription_plan,
            User.created_at,
            func.count(UsageLog.id).label('total_scans'),
            func.sum(UsageLog.files_count).label('total_files'),
            func.sum(UsageLog.vulnerabilities_found).label('total_vulns'),
            func.max(UsageLog.created_at).label('last_scan')
        ).join(
            UsageLog, User.id == UsageLog.user_id
        ).filter(
            and_(
                UsageLog.created_at >= start_date,
                UsageLog.action_type.in_(['file_upload', 'directory_scan', 'git_repo_scan', 'code_analyze'])
            )
        ).group_by(
            User.id, User.email, User.name, User.subscription_plan, User.created_at
        ).order_by(
            func.count(UsageLog.id).desc()  # Order by most scans first
        ).all()
        
        users_list = []
        for user_id, email, name, plan, created_at, scans, files, vulns, last_scan in user_scan_stats:
            users_list.append({
                "user_id": user_id,
                "email": email,
                "name": name,
                "subscription_plan": plan,
                "account_created": created_at.isoformat() if created_at else None,
                "total_scans": scans,
                "total_files_scanned": int(files or 0),
                "total_vulnerabilities_found": int(vulns or 0),
                "last_scan_date": last_scan.isoformat() if last_scan else None
            })
        
        # Also get anonymous users (by IP)
        anonymous_stats = db.query(
            UsageLog.ip_address,
            func.count(UsageLog.id).label('total_scans'),
            func.sum(UsageLog.files_count).label('total_files'),
            func.max(UsageLog.created_at).label('last_scan')
        ).filter(
            and_(
                UsageLog.created_at >= start_date,
                UsageLog.user_id.is_(None),
                UsageLog.action_type.in_(['file_upload', 'directory_scan', 'git_repo_scan', 'code_analyze'])
            )
        ).group_by(UsageLog.ip_address).all()
        
        anonymous_list = []
        for ip, scans, files, last_scan in anonymous_stats:
            anonymous_list.append({
                "ip_address": ip,
                "total_scans": scans,
                "total_files_scanned": int(files or 0),
                "last_scan_date": last_scan.isoformat() if last_scan else None
            })
        
        return {
            "period_days": days,
            "authenticated_users": users_list,
            "anonymous_users": anonymous_list,
            "total_authenticated_users": len(users_list),
            "total_anonymous_users": len(anonymous_list)
        }
    except Exception as e:
        import traceback
        print(f"[ERROR] Failed to get users with scans: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Failed to get users with scans: {str(e)}")


@app.get("/analytics/users-table", response_class=HTMLResponse)
async def get_users_table_html(
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
    days: int = 30,
    api_key: Optional[str] = None
):
    """
    Display users who have scanned in a nice HTML table format.
    Access at: http://localhost:8000/analytics/users-table
    """
    try:
        from sqlalchemy import func, and_
        from datetime import timedelta
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Get authenticated users
        user_scan_stats = db.query(
            User.id,
            User.email,
            User.name,
            User.subscription_plan,
            User.created_at,
            func.count(UsageLog.id).label('total_scans'),
            func.sum(UsageLog.files_count).label('total_files'),
            func.sum(UsageLog.vulnerabilities_found).label('total_vulns'),
            func.max(UsageLog.created_at).label('last_scan')
        ).join(
            UsageLog, User.id == UsageLog.user_id
        ).filter(
            and_(
                UsageLog.created_at >= start_date,
                UsageLog.action_type.in_(['file_upload', 'directory_scan', 'git_repo_scan', 'code_analyze'])
            )
        ).group_by(
            User.id, User.email, User.name, User.subscription_plan, User.created_at
        ).order_by(
            func.count(UsageLog.id).desc()
        ).all()
        
        # Get anonymous users
        anonymous_stats = db.query(
            UsageLog.ip_address,
            func.count(UsageLog.id).label('total_scans'),
            func.sum(UsageLog.files_count).label('total_files'),
            func.max(UsageLog.created_at).label('last_scan')
        ).filter(
            and_(
                UsageLog.created_at >= start_date,
                UsageLog.user_id.is_(None),
                UsageLog.action_type.in_(['file_upload', 'directory_scan', 'git_repo_scan', 'code_analyze'])
            )
        ).group_by(UsageLog.ip_address).all()
        
        # Generate HTML
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Users Who Have Scanned - Vulnerability Scanner</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        .controls {{
            padding: 20px 30px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }}
        .controls a {{
            padding: 10px 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 500;
            transition: background 0.3s;
        }}
        .controls a:hover {{
            background: #5568d3;
        }}
        .stats {{
            display: flex;
            gap: 20px;
            padding: 20px 30px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
            flex-wrap: wrap;
        }}
        .stat-box {{
            background: white;
            padding: 15px 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            flex: 1;
            min-width: 200px;
        }}
        .stat-box h3 {{
            color: #667eea;
            font-size: 0.9em;
            margin-bottom: 5px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .stat-box .value {{
            font-size: 2em;
            font-weight: bold;
            color: #2d3748;
        }}
        .content {{
            padding: 30px;
        }}
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            color: #2d3748;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        thead {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        th {{
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }}
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e2e8f0;
        }}
        tbody tr:hover {{
            background: #f7fafc;
        }}
        tbody tr:last-child td {{
            border-bottom: none;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        .badge-paid {{
            background: #c6f6d5;
            color: #22543d;
        }}
        .badge-free {{
            background: #fed7d7;
            color: #742a2a;
        }}
        .no-data {{
            text-align: center;
            padding: 40px;
            color: #718096;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>👥 Users Who Have Scanned</h1>
            <p>Last {days} days</p>
        </div>
        
        <div class="controls">
            <div>
                <a href="?days=7">Last 7 days</a>
                <a href="?days=30">Last 30 days</a>
                <a href="?days=90">Last 90 days</a>
                <a href="?days=365">Last year</a>
            </div>
            <div>
                <a href="/analytics/users">JSON API</a>
                <a href="/docs">API Docs</a>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <h3>Authenticated Users</h3>
                <div class="value">{len(user_scan_stats)}</div>
            </div>
            <div class="stat-box">
                <h3>Anonymous IPs</h3>
                <div class="value">{len(anonymous_stats)}</div>
            </div>
            <div class="stat-box">
                <h3>Total Scans</h3>
                <div class="value">{sum(s[5] for s in user_scan_stats) + sum(s[1] for s in anonymous_stats)}</div>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📧 Authenticated Users</h2>
"""
        
        if user_scan_stats:
            html += """
                <table>
                    <thead>
                        <tr>
                            <th>Email</th>
                            <th>Name</th>
                            <th>Plan</th>
                            <th>Scans</th>
                            <th>Files</th>
                            <th>Vulnerabilities</th>
                            <th>Last Scan</th>
                        </tr>
                    </thead>
                    <tbody>
"""
            for user_id, email, name, plan, created_at, scans, files, vulns, last_scan in user_scan_stats:
                plan_badge = f'<span class="badge badge-paid">{plan or "Free"}</span>' if plan else '<span class="badge badge-free">Free</span>'
                name_str = name or "N/A"
                files_str = int(files or 0)
                vulns_str = int(vulns or 0)
                last_scan_str = last_scan.strftime("%Y-%m-%d %H:%M") if last_scan else "Never"
                
                html += f"""
                        <tr>
                            <td><strong>{email}</strong></td>
                            <td>{name_str}</td>
                            <td>{plan_badge}</td>
                            <td>{scans}</td>
                            <td>{files_str}</td>
                            <td>{vulns_str}</td>
                            <td>{last_scan_str}</td>
                        </tr>
"""
            html += """
                    </tbody>
                </table>
"""
        else:
            html += '<div class="no-data">No authenticated users found in this period.</div>'
        
        html += """
            </div>
            
            <div class="section">
                <h2>🌐 Anonymous Users (by IP)</h2>
"""
        
        if anonymous_stats:
            html += """
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Scans</th>
                            <th>Files</th>
                            <th>Last Scan</th>
                        </tr>
                    </thead>
                    <tbody>
"""
            for ip, scans, files, last_scan in anonymous_stats:
                files_str = int(files or 0)
                last_scan_str = last_scan.strftime("%Y-%m-%d %H:%M") if last_scan else "Never"
                
                html += f"""
                        <tr>
                            <td><strong>{ip}</strong></td>
                            <td>{scans}</td>
                            <td>{files_str}</td>
                            <td>{last_scan_str}</td>
                        </tr>
"""
            html += """
                    </tbody>
                </table>
"""
        else:
            html += '<div class="no-data">No anonymous users found in this period.</div>'
        
        html += """
            </div>
        </div>
    </div>
</body>
</html>
"""
        
        return HTMLResponse(content=html)
    except Exception as e:
        import traceback
        error_html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <style>
        body {{
            font-family: sans-serif;
            padding: 40px;
            background: #fee;
            color: #c33;
        }}
    </style>
</head>
<body>
    <h1>Error Loading Users</h1>
    <p>{str(e)}</p>
    <pre>{traceback.format_exc()}</pre>
</body>
</html>
"""
        return HTMLResponse(content=error_html, status_code=500)


# Support email endpoint
class SupportEmailRequest(BaseModel):
    email: str
    issue: str

@app.post("/support/send-email")
async def send_support_email_endpoint(request: SupportEmailRequest):
    """
    Send a support email to support@daifend.com from a customer.
    """
    try:
        # Validate email format
        import re
        email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_pattern, request.email):
            raise HTTPException(status_code=400, detail="Invalid email address format")
        
        # Validate issue is not empty
        if not request.issue.strip():
            raise HTTPException(status_code=400, detail="Issue description cannot be empty")
        
        # Send email
        success, error_message = send_support_email(request.email, request.issue)
        
        if success:
            return {"success": True, "message": "Your message has been sent successfully!"}
        else:
            raise HTTPException(status_code=500, detail=error_message or "Failed to send email")
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in send_support_email_endpoint: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

