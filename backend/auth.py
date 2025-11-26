from fastapi import APIRouter, HTTPException, Depends, status, Request
from fastapi import Request as FastAPIRequest
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr
from typing import Optional
from jose import JWTError, jwt
from datetime import datetime, timedelta
import secrets
import httpx
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, String, Integer, DateTime, UniqueConstraint, text
from sqlalchemy.orm import sessionmaker, Session, declarative_base
# Using bcrypt directly instead of passlib to avoid initialization issues
import bcrypt

load_dotenv()

# Database setup - supports SQLite (local dev) and PostgreSQL/MySQL (cloud)
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL:
    # Use provided database URL (PostgreSQL/MySQL for cloud)
    SQLALCHEMY_DATABASE_URL = DATABASE_URL
    # Optimize connection pool for remote databases (reduce latency)
    # - pool_size: Number of connections to maintain
    # - max_overflow: Additional connections beyond pool_size
    # - pool_timeout: Seconds to wait for connection from pool
    # - pool_pre_ping: Verify connections before using
    # - pool_recycle: Recycle connections after this many seconds
    # - connect_args: Add connection timeout for remote databases
    connect_args = {}
    if 'postgresql' in DATABASE_URL.lower() or 'postgres' in DATABASE_URL.lower():
        # PostgreSQL connection timeout settings for remote databases
        # Note: Neon's connection pooler doesn't support statement_timeout in options
        # So we only set connect_timeout here
        connect_args = {
            "connect_timeout": 3,  # 3 second connection timeout
        }
        # Check if using Neon (has 'neon' or 'pooler' in URL) - don't use statement_timeout
        if 'neon' in DATABASE_URL.lower() or 'pooler' in DATABASE_URL.lower():
            # Neon pooler doesn't support statement_timeout parameter
            # Just use connect_timeout
            pass
        else:
            # For other PostgreSQL providers, we can use statement_timeout
            connect_args["options"] = "-c statement_timeout=5000"  # 5 second query timeout
    elif 'mysql' in DATABASE_URL.lower():
        # MySQL connection timeout settings
        connect_args = {
            "connect_timeout": 5,
            "read_timeout": 10,
            "write_timeout": 10
        }
    
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        pool_pre_ping=True,  # Verify connections before using
        pool_recycle=300,  # Recycle connections after 5 minutes
        pool_size=10,  # Maintain 10 connections (increased for concurrent requests)
        max_overflow=20,  # Allow up to 20 additional connections
        pool_timeout=30,  # Wait max 30 seconds for a connection (increased timeout)
        connect_args=connect_args,
        echo=False  # Disable SQL logging for performance
    )
else:
    # Default to SQLite for local development
    SQLALCHEMY_DATABASE_URL = "sqlite:///./auth.db"
    engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)  # Removed unique=True to allow same email for different providers
    name = Column(String)
    provider = Column(String)  # 'github', 'google', or 'email'
    provider_id = Column(String, index=True, nullable=True)  # Nullable for email/password users
    password_hash = Column(String, nullable=True)  # Hashed password for email/password users
    avatar_url = Column(String, nullable=True)
    github_access_token = Column(String, nullable=True)  # Store GitHub OAuth token for API access
    subscription_plan = Column(String, nullable=True)  # 'enterprise-basic', 'enterprise-pro', or None for free
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Composite unique constraint: same provider_id can't exist twice for same provider
    # For email/password users, provider_id is None, so we need unique email for email provider
    # We'll handle email uniqueness in application logic since SQL doesn't support NULL in unique constraints well
    __table_args__ = (
        UniqueConstraint('provider', 'provider_id', name='uq_provider_provider_id'),
    )

class ScanCount(Base):
    __tablename__ = "scan_counts"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True, index=True)  # None for non-authenticated users
    ip_address = Column(String, nullable=True, index=True)  # For tracking non-authenticated users
    scan_count = Column(Integer, default=0)
    reset_date = Column(DateTime, default=datetime.utcnow)  # Track when to reset counts

class RegistrationAttempt(Base):
    __tablename__ = "registration_attempts"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, nullable=False, index=True)
    email = Column(String, nullable=True, index=True)
    attempt_count = Column(Integer, default=1)
    last_attempt = Column(DateTime, default=datetime.utcnow, index=True)
    blocked_until = Column(DateTime, nullable=True, index=True)

class UsageLog(Base):
    __tablename__ = "usage_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True, index=True)  # None for non-authenticated users
    user_email = Column(String, nullable=True, index=True)  # For quick lookups
    user_type = Column(String, nullable=False, index=True)  # 'free' or 'paid'
    subscription_plan = Column(String, nullable=True)  # 'enterprise-10', 'enterprise-20', or None
    action_type = Column(String, nullable=False, index=True)  # 'file_upload', 'directory_scan', 'git_repo_scan', 'code_analyze', 'compliance_report'
    ip_address = Column(String, nullable=True, index=True)
    files_count = Column(Integer, default=0)  # Number of files scanned
    vulnerabilities_found = Column(Integer, default=0)  # Number of vulnerabilities detected
    scan_duration_ms = Column(Integer, nullable=True)  # Scan duration in milliseconds
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

class LearnedVulnerability(Base):
    __tablename__ = "learned_vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)
    pattern = Column(String, nullable=False)  # Regex pattern
    language = Column(String, nullable=False, index=True)  # 'python' or 'cpp'
    severity = Column(String, nullable=False)  # 'critical', 'high', 'medium', 'low'
    description = Column(String, nullable=True)
    code_snippet = Column(String, nullable=True)  # Example code that triggered this
    discovered_count = Column(Integer, default=1)  # How many times this was found
    is_active = Column(Integer, default=1)  # 1 for active, 0 for disabled
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)  # When this pattern expires (for TTL)

# Helper function to log platform usage
def log_usage(
    db: Session,
    user: Optional[User] = None,
    action_type: str = "unknown",
    ip_address: Optional[str] = None,
    files_count: int = 0,
    vulnerabilities_found: int = 0,
    scan_duration_ms: Optional[int] = None
):
    """
    Log platform usage for analytics tracking.
    
    Args:
        db: Database session
        user: User object (None for anonymous users)
        action_type: Type of action ('file_upload', 'directory_scan', 'git_repo_scan', 'code_analyze', 'compliance_report')
        ip_address: IP address of the user
        files_count: Number of files processed
        vulnerabilities_found: Number of vulnerabilities detected
        scan_duration_ms: Duration of scan in milliseconds
    """
    try:
        user_type = "paid" if user and user.subscription_plan else "free"
        subscription_plan = user.subscription_plan if user else None
        user_id = user.id if user else None
        user_email = user.email if user else None
        
        usage_log = UsageLog(
            user_id=user_id,
            user_email=user_email,
            user_type=user_type,
            subscription_plan=subscription_plan,
            action_type=action_type,
            ip_address=ip_address,
            files_count=files_count,
            vulnerabilities_found=vulnerabilities_found,
            scan_duration_ms=scan_duration_ms
        )
        db.add(usage_log)
        db.commit()
    except Exception as e:
        print(f"Warning: Failed to log usage: {e}")
        db.rollback()

# Migration: Add usage_logs table if it doesn't exist
def migrate_add_usage_logs():
    """Create usage_logs table if it doesn't exist (works with SQLite, PostgreSQL, MySQL)"""
    from sqlalchemy import inspect, text
    try:
        inspector = inspect(engine)
        if not inspector.has_table('usage_logs'):
            with engine.begin() as conn:
                # Detect database type
                db_url = str(engine.url)
                is_sqlite = 'sqlite' in db_url.lower()
                is_postgres = 'postgresql' in db_url.lower() or 'postgres' in db_url.lower()
                
                if is_sqlite:
                    # SQLite syntax
                    conn.execute(text("""
                        CREATE TABLE usage_logs (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER,
                            user_email VARCHAR,
                            user_type VARCHAR NOT NULL,
                            subscription_plan VARCHAR,
                            action_type VARCHAR NOT NULL,
                            ip_address VARCHAR,
                            files_count INTEGER DEFAULT 0,
                            vulnerabilities_found INTEGER DEFAULT 0,
                            scan_duration_ms INTEGER,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                else:
                    # PostgreSQL/MySQL syntax
                    auto_increment = "SERIAL" if is_postgres else "AUTO_INCREMENT"
                    timestamp_default = "DEFAULT CURRENT_TIMESTAMP" if is_postgres else "DEFAULT CURRENT_TIMESTAMP"
                    conn.execute(text(f"""
                        CREATE TABLE usage_logs (
                            id INTEGER PRIMARY KEY {auto_increment},
                            user_id INTEGER,
                            user_email VARCHAR(255),
                            user_type VARCHAR(50) NOT NULL,
                            subscription_plan VARCHAR(50),
                            action_type VARCHAR(50) NOT NULL,
                            ip_address VARCHAR(45),
                            files_count INTEGER DEFAULT 0,
                            vulnerabilities_found INTEGER DEFAULT 0,
                            scan_duration_ms INTEGER,
                            created_at TIMESTAMP {timestamp_default}
                        )
                    """))
                
                # Create indexes (syntax is mostly compatible)
                conn.execute(text("CREATE INDEX idx_usage_logs_user_id ON usage_logs(user_id)"))
                conn.execute(text("CREATE INDEX idx_usage_logs_user_email ON usage_logs(user_email)"))
                conn.execute(text("CREATE INDEX idx_usage_logs_user_type ON usage_logs(user_type)"))
                conn.execute(text("CREATE INDEX idx_usage_logs_action_type ON usage_logs(action_type)"))
                conn.execute(text("CREATE INDEX idx_usage_logs_created_at ON usage_logs(created_at)"))
            print("Migration: Created usage_logs table")
    except Exception as e:
        if "already exists" not in str(e).lower() and "duplicate" not in str(e).lower():
            print(f"Warning: Migration check failed: {e}")

Base.metadata.create_all(bind=engine)
migrate_add_usage_logs()

# Migration: Add expires_at column if it doesn't exist
def migrate_add_expires_at():
    """Add expires_at column to learned_vulnerabilities table if it doesn't exist (works with SQLite, PostgreSQL, MySQL)"""
    from sqlalchemy import inspect, text
    try:
        inspector = inspect(engine)
        if inspector.has_table('learned_vulnerabilities'):
            columns = [col['name'] for col in inspector.get_columns('learned_vulnerabilities')]
            
            if 'expires_at' not in columns:
                with engine.begin() as conn:
                    # Detect database type for proper column type
                    db_url = str(engine.url)
                    is_sqlite = 'sqlite' in db_url.lower()
                    
                    if is_sqlite:
                        conn.execute(text("ALTER TABLE learned_vulnerabilities ADD COLUMN expires_at DATETIME"))
                    else:
                        # PostgreSQL/MySQL use TIMESTAMP
                        conn.execute(text("ALTER TABLE learned_vulnerabilities ADD COLUMN expires_at TIMESTAMP"))
                print("Migration: Added expires_at column to learned_vulnerabilities table")
    except Exception as e:
        # Table might not exist yet, that's okay
        error_str = str(e).lower()
        if "no such table" not in error_str and "no such column" not in error_str and "duplicate" not in error_str:
            print(f"Warning: Migration check failed: {e}")

# Run migration on import
migrate_add_expires_at()

# Migration: Remove unique constraint on email to allow same email for different providers
def migrate_remove_email_unique():
    """Remove unique constraint on email column to allow same email for different providers"""
    from sqlalchemy import inspect, text
    try:
        inspector = inspect(engine)
        if inspector.has_table('users'):
            # Check if unique constraint exists on email
            db_url = str(engine.url)
            is_sqlite = 'sqlite' in db_url.lower()
            is_postgres = 'postgresql' in db_url.lower() or 'postgres' in db_url.lower()
            
            with engine.begin() as conn:
                if is_postgres:
                    # PostgreSQL: Drop unique index if it exists
                    try:
                        conn.execute(text("DROP INDEX IF EXISTS ix_users_email"))
                        print("Migration: Removed unique constraint on email column (PostgreSQL)")
                    except Exception as e:
                        if "does not exist" not in str(e).lower():
                            print(f"Migration note: {e}")
                elif is_sqlite:
                    # SQLite: Can't easily drop unique constraint, but we can recreate table
                    # For now, just note that new tables won't have the constraint
                    print("Migration: SQLite - unique constraint on email will be removed for new tables")
                else:
                    # MySQL: Drop unique index if it exists
                    try:
                        conn.execute(text("DROP INDEX ix_users_email ON users"))
                        print("Migration: Removed unique constraint on email column (MySQL)")
                    except Exception as e:
                        if "does not exist" not in str(e).lower():
                            print(f"Migration note: {e}")
    except Exception as e:
        print(f"Warning: Email unique constraint migration check failed: {e}")

migrate_remove_email_unique()

# Migration: Add github_access_token column
def migrate_add_github_token():
    """Add github_access_token column to users table if it doesn't exist"""
    from sqlalchemy import inspect, text
    try:
        inspector = inspect(engine)
        if inspector.has_table('users'):
            # Check if column exists
            columns = [col['name'] for col in inspector.get_columns('users')]
            if 'github_access_token' not in columns:
                db_url = str(engine.url)
                is_sqlite = 'sqlite' in db_url.lower()
                is_postgres = 'postgresql' in db_url.lower() or 'postgres' in db_url.lower()
                
                with engine.begin() as conn:
                    if is_postgres:
                        conn.execute(text("ALTER TABLE users ADD COLUMN github_access_token VARCHAR"))
                        print("Migration: Added github_access_token column (PostgreSQL)")
                    elif is_sqlite:
                        conn.execute(text("ALTER TABLE users ADD COLUMN github_access_token VARCHAR"))
                        print("Migration: Added github_access_token column (SQLite)")
                    else:
                        # MySQL
                        conn.execute(text("ALTER TABLE users ADD COLUMN github_access_token VARCHAR(255)"))
                        print("Migration: Added github_access_token column (MySQL)")
    except Exception as e:
        print(f"Warning: GitHub token column migration check failed: {e}")

migrate_add_github_token()

# Migration: Add password_hash column for email/password authentication
def migrate_add_password_hash():
    """Add password_hash column to users table for email/password authentication"""
    from sqlalchemy import inspect, text
    try:
        inspector = inspect(engine)
        if inspector.has_table('users'):
            columns = [col['name'] for col in inspector.get_columns('users')]
            if 'password_hash' not in columns:
                with engine.connect() as conn:
                    if 'sqlite' in SQLALCHEMY_DATABASE_URL.lower():
                        conn.execute(text("ALTER TABLE users ADD COLUMN password_hash VARCHAR(255)"))
                        print("Migration: Added password_hash column (SQLite)")
                    elif 'postgresql' in SQLALCHEMY_DATABASE_URL.lower() or 'postgres' in SQLALCHEMY_DATABASE_URL.lower():
                        conn.execute(text("ALTER TABLE users ADD COLUMN password_hash VARCHAR(255)"))
                        conn.commit()
                        print("Migration: Added password_hash column (PostgreSQL)")
                    elif 'mysql' in SQLALCHEMY_DATABASE_URL.lower():
                        conn.execute(text("ALTER TABLE users ADD COLUMN password_hash VARCHAR(255)"))
                        print("Migration: Added password_hash column (MySQL)")
    except Exception as e:
        error_str = str(e).lower()
        if "duplicate" not in error_str and "already exists" not in error_str:
            print(f"Warning: Password hash column migration check failed: {e}")

migrate_add_password_hash()

# Migration: Create registration_attempts table for rate limiting
def migrate_add_registration_attempts():
    """Create registration_attempts table for rate limiting"""
    from sqlalchemy import inspect, text
    try:
        inspector = inspect(engine)
        if not inspector.has_table('registration_attempts'):
            with engine.begin() as conn:
                db_url = str(engine.url)
                is_sqlite = 'sqlite' in db_url.lower()
                is_postgres = 'postgresql' in db_url.lower() or 'postgres' in db_url.lower()
                
                if is_postgres:
                    conn.execute(text("""
                        CREATE TABLE registration_attempts (
                            id SERIAL PRIMARY KEY,
                            ip_address VARCHAR(255) NOT NULL,
                            email VARCHAR(255),
                            attempt_count INTEGER DEFAULT 1,
                            last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            blocked_until TIMESTAMP
                        )
                    """))
                    conn.execute(text("CREATE INDEX idx_registration_attempts_ip ON registration_attempts(ip_address)"))
                    conn.execute(text("CREATE INDEX idx_registration_attempts_email ON registration_attempts(email)"))
                    conn.execute(text("CREATE INDEX idx_registration_attempts_blocked ON registration_attempts(blocked_until)"))
                    print("Migration: Created registration_attempts table (PostgreSQL)")
                elif is_sqlite:
                    conn.execute(text("""
                        CREATE TABLE registration_attempts (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ip_address VARCHAR(255) NOT NULL,
                            email VARCHAR(255),
                            attempt_count INTEGER DEFAULT 1,
                            last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            blocked_until TIMESTAMP
                        )
                    """))
                    conn.execute(text("CREATE INDEX idx_registration_attempts_ip ON registration_attempts(ip_address)"))
                    conn.execute(text("CREATE INDEX idx_registration_attempts_email ON registration_attempts(email)"))
                    conn.execute(text("CREATE INDEX idx_registration_attempts_blocked ON registration_attempts(blocked_until)"))
                    print("Migration: Created registration_attempts table (SQLite)")
                else:
                    # MySQL
                    conn.execute(text("""
                        CREATE TABLE registration_attempts (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            ip_address VARCHAR(255) NOT NULL,
                            email VARCHAR(255),
                            attempt_count INT DEFAULT 1,
                            last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            blocked_until TIMESTAMP NULL,
                            INDEX idx_ip (ip_address),
                            INDEX idx_email (email),
                            INDEX idx_blocked (blocked_until)
                        )
                    """))
                    print("Migration: Created registration_attempts table (MySQL)")
    except Exception as e:
        error_str = str(e).lower()
        if "already exists" not in error_str and "duplicate" not in error_str:
            print(f"Warning: Registration attempts table migration check failed: {e}")

migrate_add_registration_attempts()

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 Configuration
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
# Check if running in development (can be set via environment variable)
IS_DEVELOPMENT = os.getenv("ENVIRONMENT", "").lower() == "development" or os.getenv("DEBUG", "").lower() == "true"

GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI", "http://localhost:8000/auth/github/callback" if IS_DEVELOPMENT else "https://stratum.daifend.ai/auth/github/callback")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback" if IS_DEVELOPMENT else "https://stratum.daifend.ai/auth/google/callback")

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173" if IS_DEVELOPMENT else "https://stratum.daifend.ai")

# Password hashing - use bcrypt directly to avoid passlib initialization issues
import bcrypt

def _truncate_password_for_bcrypt(password: str) -> bytes:
    """Truncate password to 72 bytes for bcrypt, handling UTF-8 boundaries"""
    password_bytes = password.encode('utf-8')
    if len(password_bytes) <= 72:
        return password_bytes
    
    # Truncate to 72 bytes, handling UTF-8 character boundaries
    truncated = password_bytes[:72]
    # Try to decode, if it fails at the end (broken UTF-8 sequence), remove bytes until valid
    while truncated:
        try:
            # Verify it decodes correctly
            truncated.decode('utf-8')
            return truncated
        except UnicodeDecodeError:
            truncated = truncated[:-1]
    
    # Fallback: use first 72 bytes with error handling
    return password_bytes[:72]

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    try:
        # Truncate password to 72 bytes before verification
        password_bytes = _truncate_password_for_bcrypt(plain_password)
        # hashed_password is already a string, convert to bytes
        if isinstance(hashed_password, str):
            hashed_bytes = hashed_password.encode('utf-8')
        else:
            hashed_bytes = hashed_password
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False

def get_password_hash(password: str) -> str:
    """Hash a password - bcrypt has a 72-byte limit"""
    # Truncate password to 72 bytes before hashing
    password_bytes = _truncate_password_for_bcrypt(password)
    # Generate salt and hash
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

# Security
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)
security = HTTPBearer(auto_error=False)

router = APIRouter(prefix="/auth", tags=["authentication"])

# Pydantic models
class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict

class UserResponse(BaseModel):
    id: int
    email: str
    name: str
    provider: str
    avatar_url: Optional[str] = None

# Helper functions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    # Convert 'sub' to string if it exists (jose library requires string for sub claim)
    if 'sub' in to_encode and not isinstance(to_encode['sub'], str):
        to_encode['sub'] = str(to_encode['sub'])
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if not credentials:
        print("DEBUG: No credentials provided")
        raise credentials_exception
    
    token = credentials.credentials
    print(f"DEBUG: Received token (first 50 chars): {token[:50] if token else 'None'}...")
    print(f"DEBUG: SECRET_KEY (first 20 chars): {SECRET_KEY[:20] if SECRET_KEY else 'None'}...")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"DEBUG: Token decoded successfully, payload: {payload}")
        user_id_str = payload.get("sub")
        if user_id_str is None:
            print(f"DEBUG: Token payload missing 'sub': {payload}")
            raise credentials_exception
        # Convert sub (string) back to int for database query
        try:
            user_id: int = int(user_id_str)
        except (ValueError, TypeError):
            print(f"DEBUG: Invalid user_id format in token: {user_id_str}")
            raise credentials_exception
        print(f"DEBUG: Extracted user_id: {user_id}")
    except JWTError as e:
        print(f"DEBUG: JWT decode error: {str(e)}")
        print(f"DEBUG: Error type: {type(e).__name__}")
        raise credentials_exception
    except Exception as e:
        print(f"DEBUG: Unexpected error during token validation: {str(e)}")
        print(f"DEBUG: Error type: {type(e).__name__}")
        raise credentials_exception
    
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        print(f"DEBUG: User with id {user_id} not found in database")
        raise credentials_exception
    print(f"DEBUG: User found: {user.email}")
    return user

async def get_current_admin(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Simple admin authentication using API key or password.
    No OAuth required - internal use only.
    """
    # Get admin credentials from environment
    admin_api_key = os.getenv("ADMIN_API_KEY", "")
    admin_password = os.getenv("ADMIN_PASSWORD", "")
    
    if not admin_api_key and not admin_password:
        raise HTTPException(
            status_code=403,
            detail="Admin access not configured. Set ADMIN_API_KEY or ADMIN_PASSWORD in environment."
        )
    
    # Check for API key in Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        provided_key = auth_header.replace("Bearer ", "")
        if provided_key == admin_api_key:
            return {"admin": True, "method": "api_key"}
    
    # Check for password in Authorization header (Basic auth style)
    if auth_header.startswith("Basic "):
        import base64
        try:
            decoded = base64.b64decode(auth_header.replace("Basic ", "")).decode()
            username, password = decoded.split(":", 1)
            if password == admin_password:
                return {"admin": True, "method": "password"}
        except:
            pass
    
    # Check for API key in query parameter (for easy browser access)
    api_key_param = request.query_params.get("api_key")
    if api_key_param and api_key_param == admin_api_key:
        return {"admin": True, "method": "api_key"}
    
    # If no valid credentials, return 401 with instructions
    raise HTTPException(
        status_code=401,
        detail="Admin authentication required. Provide ADMIN_API_KEY in Authorization header or ?api_key= query parameter."
    )


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Optional authentication - returns None if no token provided"""
    if not credentials:
        return None
    
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            return None
    except JWTError:
        return None
    
    user = db.query(User).filter(User.id == user_id).first()
    return user

# Rate Limiting for Scans
# Read from environment variable, default to 5
FREE_SCAN_LIMIT = int(os.getenv("FREE_SCAN_LIMIT", "5"))

async def check_scan_limit(
    request: Request,
    user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """Check if user/IP has exceeded scan limit. Raises HTTPException if limit exceeded."""
    # Users with active subscription have unlimited scans
    if user and user.subscription_plan:
        return True
    
    # Get client IP address
    client_ip = request.client.host if request.client else "unknown"
    
    # Find or create scan count record
    if user:
        scan_record = db.query(ScanCount).filter(ScanCount.user_id == user.id).first()
    else:
        scan_record = db.query(ScanCount).filter(
            ScanCount.ip_address == client_ip,
            ScanCount.user_id.is_(None)
        ).first()
    
    # Reset count if it's a new day (optional - for daily limits)
    # For now, we'll track lifetime counts for free users
    
    if not scan_record:
        # Create new record
        scan_record = ScanCount(
            user_id=user.id if user else None,
            ip_address=client_ip if not user else None,
            scan_count=0,
            reset_date=datetime.utcnow()
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)
    
    # Check if limit exceeded
    if scan_record.scan_count >= FREE_SCAN_LIMIT:
        if user:
            # Logged-in user without subscription
            message = f"Scan limit reached. You have used {scan_record.scan_count} of {FREE_SCAN_LIMIT} free scans. Please subscribe to a plan to continue scanning."
        else:
            # Non-logged-in user
            message = f"Scan limit reached. You have used {scan_record.scan_count} of {FREE_SCAN_LIMIT} free scans. Please log in and subscribe to continue scanning."
        
        raise HTTPException(
            status_code=403,
            detail={
                "error": "scan_limit_reached",
                "message": message,
                "scans_used": scan_record.scan_count,
                "scan_limit": FREE_SCAN_LIMIT,
                "is_authenticated": user is not None
            }
        )
    
    # Increment scan count
    scan_record.scan_count += 1
    db.commit()
    
    return True

# Authentication Routes

@router.get("/test")
async def test_auth():
    """Test endpoint to verify auth routes are accessible"""
    return {
        "message": "Auth routes are working",
        "github_configured": bool(GITHUB_CLIENT_ID),
        "google_configured": bool(GOOGLE_CLIENT_ID),
        "github_redirect_uri": GITHUB_REDIRECT_URI,
        "google_redirect_uri": GOOGLE_REDIRECT_URI
    }

# Email/Password Authentication Models
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

@router.post("/register")
async def register(request: RegisterRequest, request_obj: FastAPIRequest, db: Session = Depends(get_db)):
    """Register a new user with email and password - with rate limiting to prevent spam"""
    # Get client IP address for rate limiting
    client_ip = request_obj.client.host if request_obj.client else "unknown"
    
    # Rate limiting: Check if IP is blocked
    from sqlalchemy import and_
    blocked_attempt = db.query(RegistrationAttempt).filter(
        and_(
            RegistrationAttempt.ip_address == client_ip,
            RegistrationAttempt.blocked_until.isnot(None),
            RegistrationAttempt.blocked_until > datetime.utcnow()
        )
    ).first()
    
    if blocked_attempt:
        raise HTTPException(
            status_code=429,
            detail="Too many registration attempts. Please try again later."
        )
    
    # Rate limiting: Check attempt count (max 5 registrations per hour per IP)
    attempt_record = db.query(RegistrationAttempt).filter(
        RegistrationAttempt.ip_address == client_ip
    ).first()
    
    if attempt_record:
        # Check if within the last hour
        time_since_last = datetime.utcnow() - attempt_record.last_attempt
        if time_since_last < timedelta(hours=1):
            if attempt_record.attempt_count >= 5:
                # Block for 1 hour
                attempt_record.blocked_until = datetime.utcnow() + timedelta(hours=1)
                attempt_record.attempt_count += 1
                db.commit()
                raise HTTPException(
                    status_code=429,
                    detail="Too many registration attempts from this IP. Please try again in 1 hour."
                )
            else:
                attempt_record.attempt_count += 1
                attempt_record.last_attempt = datetime.utcnow()
                db.commit()
        else:
            # Reset count if more than 1 hour has passed
            attempt_record.attempt_count = 1
            attempt_record.last_attempt = datetime.utcnow()
            attempt_record.blocked_until = None
            db.commit()
    else:
        # Create new attempt record
        attempt_record = RegistrationAttempt(
            ip_address=client_ip,
            email=request.email,
            attempt_count=1,
            last_attempt=datetime.utcnow()
        )
        db.add(attempt_record)
        db.commit()
    
    # Check if user with this email already exists (for email provider)
    existing_user = db.query(User).filter(
        User.email == request.email,
        User.provider == 'email'
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered. Please login instead."
        )
    
    # Validate password strength
    if len(request.password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long"
        )
    
    # Bcrypt limitation: passwords cannot exceed 72 bytes
    # Check password length in bytes (not characters, as UTF-8 can be multi-byte)
    password_bytes = request.password.encode('utf-8')
    if len(password_bytes) > 72:
        raise HTTPException(
            status_code=400,
            detail="Password is too long. Maximum 72 bytes allowed (approximately 72 ASCII characters or fewer for multi-byte characters)."
        )
    
    # Additional password validation: require at least one letter and one number
    has_letter = any(c.isalpha() for c in request.password)
    has_number = any(c.isdigit() for c in request.password)
    if not (has_letter and has_number):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one letter and one number"
        )
    
    # Validate name (prevent empty or too long names)
    name = request.name.strip() if request.name else ""
    if not name or len(name) < 2:
        raise HTTPException(
            status_code=400,
            detail="Name must be at least 2 characters long"
        )
    if len(name) > 100:
        name = name[:100]  # Truncate if too long
    
    # Create new user
    password_hash = get_password_hash(request.password)
    user = User(
        email=request.email.lower().strip(),  # Normalize email
        name=name,
        provider='email',
        provider_id=None,  # Email users don't have provider_id
        password_hash=password_hash
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Reset attempt count on successful registration
    if attempt_record:
        attempt_record.attempt_count = 0
        attempt_record.blocked_until = None
        db.commit()
    
    # Create JWT token
    jwt_token = create_access_token({"sub": str(user.id)})
    
    return {
        "access_token": jwt_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "provider": user.provider
        }
    }

@router.post("/login")
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    """Login with email and password"""
    # Find user by email and provider
    user = db.query(User).filter(
        User.email == request.email,
        User.provider == 'email'
    ).first()
    
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )
    
    if not user.password_hash:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )
    
    # Verify password
    if not verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )
    
    # Create JWT token
    jwt_token = create_access_token({"sub": str(user.id)})
    
    return {
        "access_token": jwt_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "provider": user.provider
        }
    }

@router.get("/github/login")
async def github_login():
    """Initiate GitHub OAuth login"""
    if not GITHUB_CLIENT_ID:
        raise HTTPException(status_code=500, detail="GitHub OAuth not configured")
    
    github_auth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={GITHUB_REDIRECT_URI}"
        f"&scope=user:email repo"
    )
    return RedirectResponse(url=github_auth_url)

@router.get("/github/callback")
async def github_callback(code: str, db: Session = Depends(get_db)):
    """Handle GitHub OAuth callback"""
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not provided")
    
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="GitHub OAuth not configured. Please set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET."
        )
    
    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        try:
            token_response = await client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": GITHUB_CLIENT_ID,
                    "client_secret": GITHUB_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": GITHUB_REDIRECT_URI,
                },
                headers={"Accept": "application/json"},
            )
            token_response.raise_for_status()
            token_data = token_response.json()
            
            # Check for errors in token response
            if "error" in token_data:
                raise HTTPException(
                    status_code=400,
                    detail=f"Failed to get access token: {token_data.get('error_description', token_data.get('error'))}"
                )
            
            access_token = token_data.get("access_token")
            
            if not access_token:
                raise HTTPException(status_code=400, detail="Failed to get access token from GitHub")
            
            # Get user info from GitHub
            user_response = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {access_token}"},
            )
            user_response.raise_for_status()
            user_data = user_response.json()
            
            # Get user email (may need to make separate request)
            email_response = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"token {access_token}"},
            )
            email_response.raise_for_status()
            emails = email_response.json()
            email = next((e["email"] for e in emails if e["primary"]), emails[0]["email"] if emails else None)
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=500,
                detail=f"Error communicating with GitHub: {str(e)}"
            )
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Unexpected error during GitHub OAuth: {str(e)}"
            )
    
    # Create or get user - separate accounts per provider (even if email is same)
    provider_id = str(user_data["id"])
    user = db.query(User).filter(User.provider_id == provider_id, User.provider == "github").first()
    
    if not user:
        # Create new user - separate account for GitHub even if email exists for another provider
        # This allows same email to have separate Google and GitHub accounts
        user = User(
            email=email or f"github_{provider_id}@example.com",
            name=user_data.get("name") or user_data.get("login"),
            provider="github",
            provider_id=provider_id,
            avatar_url=user_data.get("avatar_url"),
            github_access_token=access_token,  # Store GitHub access token
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        print(f"DEBUG: Created new GitHub user: {user.email}, name: {user.name}, provider: {user.provider}")
    else:
        # Update existing GitHub user info with latest GitHub data
        user.email = email or user.email
        user.name = user_data.get("name") or user_data.get("login") or user.name
        user.avatar_url = user_data.get("avatar_url") or user.avatar_url
        user.github_access_token = access_token  # Update GitHub access token
        db.commit()
        print(f"DEBUG: Updated existing GitHub user: {user.email}, name: {user.name}, provider: {user.provider}")
    
    # Create JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    jwt_token = create_access_token(
        data={"sub": user.id}, expires_delta=access_token_expires
    )
    
    print(f"DEBUG: Created JWT token for GitHub user {user.id} (email: {user.email})")
    print(f"DEBUG: Token (first 50 chars): {jwt_token[:50]}...")
    print(f"DEBUG: Redirecting to: {FRONTEND_URL}/?token={jwt_token[:50]}...&user_id={user.id}")
    
    # Redirect to frontend with token (use root path since there's no routing)
    return RedirectResponse(
        url=f"{FRONTEND_URL}/?token={jwt_token}&user_id={user.id}"
    )

@router.get("/google/login")
async def google_login():
    """Initiate Google OAuth login"""
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Google OAuth not configured")
    
    # URL encode the redirect URI
    from urllib.parse import quote
    encoded_redirect_uri = quote(GOOGLE_REDIRECT_URI, safe='')
    
    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={encoded_redirect_uri}"
        f"&response_type=code"
        f"&scope=openid email profile"
        f"&access_type=offline"
        f"&prompt=consent"
    )
    return RedirectResponse(url=google_auth_url)

@router.get("/google/callback")
async def google_callback(
    code: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Handle Google OAuth callback"""
    # Check for errors from Google
    if error:
        error_msg = error_description or error
        raise HTTPException(
            status_code=400,
            detail=f"Google OAuth error: {error_msg}"
        )
    
    if not code:
        raise HTTPException(
            status_code=400,
            detail="Authorization code not provided. Please try logging in again."
        )
    
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Google OAuth not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET."
        )
    
    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        try:
            token_response = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": GOOGLE_REDIRECT_URI,
                },
            )
            token_response.raise_for_status()
            token_data = token_response.json()
            
            # Check for errors in token response
            if "error" in token_data:
                raise HTTPException(
                    status_code=400,
                    detail=f"Failed to get access token: {token_data.get('error_description', token_data.get('error'))}"
                )
            
            access_token = token_data.get("access_token")
            
            if not access_token:
                raise HTTPException(
                    status_code=400,
                    detail="Failed to get access token from Google"
                )
            
            # Get user info from Google
            user_response = await client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            user_response.raise_for_status()
            user_data = user_response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=500,
                detail=f"Error communicating with Google: {str(e)}"
            )
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Unexpected error during Google OAuth: {str(e)}"
            )
    
    # Create or get user - separate accounts per provider (even if email is same)
    provider_id = str(user_data["id"])
    user = db.query(User).filter(User.provider_id == provider_id, User.provider == "google").first()
    
    if not user:
        # Create new user - separate account for Google even if email exists for another provider
        # This allows same email to have separate Google and GitHub accounts
        user = User(
            email=user_data["email"],
            name=user_data.get("name"),
            provider="google",
            provider_id=provider_id,
            avatar_url=user_data.get("picture"),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        print(f"DEBUG: Created new Google user: {user.email}, name: {user.name}, provider: {user.provider}")
    else:
        # Update existing Google user info with latest Google data
        user.email = user_data.get("email") or user.email
        user.name = user_data.get("name") or user.name
        user.avatar_url = user_data.get("picture") or user.avatar_url
        db.commit()
        print(f"DEBUG: Updated existing Google user: {user.email}, name: {user.name}, provider: {user.provider}")
    
    # Create JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    jwt_token = create_access_token(
        data={"sub": user.id}, expires_delta=access_token_expires
    )
    
    # Redirect to frontend with token (use root path since there's no routing)
    return RedirectResponse(
        url=f"{FRONTEND_URL}/?token={jwt_token}&user_id={user.id}"
    )

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        name=current_user.name,
        provider=current_user.provider,
        avatar_url=current_user.avatar_url,
    )

@router.post("/logout")
async def logout():
    """Logout endpoint (client-side token removal)"""
    return {"message": "Logged out successfully"}

@router.get("/github/repositories")
async def get_github_repositories(current_user: User = Depends(get_current_user)):
    """Get list of GitHub repositories for the authenticated user"""
    if current_user.provider != "github":
        raise HTTPException(status_code=403, detail="Only GitHub users can access repositories")
    
    if not current_user.github_access_token:
        raise HTTPException(status_code=400, detail="GitHub access token not available. Please log in again.")
    
    # Configure httpx client with longer timeouts for GitHub API
    timeout = httpx.Timeout(30.0, connect=10.0)  # 30s total, 10s for connection
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            # Fetch user repositories
            # GitHub OAuth tokens use "token" prefix (not "Bearer")
            auth_header = f"token {current_user.github_access_token}"
            repos_response = await client.get(
                "https://api.github.com/user/repos",
                headers={"Authorization": auth_header, "Accept": "application/vnd.github.v3+json"},
                params={"per_page": 100, "sort": "updated"}
            )
            repos_response.raise_for_status()
            repos = repos_response.json()
            
            # Format repository list
            repo_list = [
                {
                    "id": repo["id"],
                    "name": repo["name"],
                    "full_name": repo["full_name"],
                    "url": repo["html_url"],
                    "clone_url": repo["clone_url"],
                    "default_branch": repo.get("default_branch", "main")
                }
                for repo in repos
            ]
            
            return {"repositories": repo_list}
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=500,
                detail=f"Error fetching repositories from GitHub: {str(e)}"
            )
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Unexpected error: {str(e)}"
            )

@router.get("/github/repositories/{owner}/{repo}/branches")
async def get_github_branches(
    owner: str,
    repo: str,
    current_user: User = Depends(get_current_user)
):
    """Get list of branches for a specific GitHub repository"""
    if current_user.provider != "github":
        raise HTTPException(status_code=403, detail="Only GitHub users can access branches")
    
    if not current_user.github_access_token:
        raise HTTPException(status_code=400, detail="GitHub access token not available. Please log in again.")
    
    print(f"DEBUG: Fetching branches for {owner}/{repo}, token length: {len(current_user.github_access_token) if current_user.github_access_token else 0}")
    
    # Configure httpx client with longer timeouts for GitHub API
    timeout = httpx.Timeout(30.0, connect=10.0)  # 30s total, 10s for connection
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            # Fetch repository branches
            # GitHub OAuth tokens use "token" prefix (not "Bearer")
            auth_header = f"token {current_user.github_access_token}"
            url = f"https://api.github.com/repos/{owner}/{repo}/branches"
            print(f"DEBUG: Requesting branches from: {url}")
            
            branches_response = await client.get(
                url,
                headers={"Authorization": auth_header, "Accept": "application/vnd.github.v3+json"},
                params={"per_page": 100}
            )
            branches_response.raise_for_status()
            branches = branches_response.json()
            
            print(f"DEBUG: Successfully fetched {len(branches)} branches")
            
            # Format branch list
            branch_list = [{"name": branch["name"]} for branch in branches]
            
            return {"branches": branch_list}
        except httpx.ConnectTimeout as e:
            print(f"ERROR: Connection timeout when connecting to GitHub API: {e}")
            raise HTTPException(
                status_code=504,
                detail="Connection timeout: Unable to reach GitHub API. Please check your internet connection and try again."
            )
        except httpx.TimeoutException as e:
            print(f"ERROR: Request timeout when fetching from GitHub API: {e}")
            raise HTTPException(
                status_code=504,
                detail="Request timeout: GitHub API took too long to respond. Please try again."
            )
        except httpx.HTTPStatusError as e:
            print(f"ERROR: GitHub API error: {e.response.status_code} - {e.response.text}")
            if e.response.status_code == 404:
                raise HTTPException(status_code=404, detail="Repository not found or access denied")
            elif e.response.status_code == 401:
                raise HTTPException(status_code=401, detail="GitHub authentication failed. Please log in again.")
            raise HTTPException(
                status_code=500,
                detail=f"Error fetching branches from GitHub: {str(e)}"
            )
        except httpx.RequestError as e:
            print(f"ERROR: Network error when connecting to GitHub API: {e}")
            raise HTTPException(
                status_code=503,
                detail=f"Network error: Unable to connect to GitHub API. {str(e)}"
            )
        except Exception as e:
            print(f"ERROR: Unexpected error fetching branches: {e}")
            import traceback
            print(traceback.format_exc())
            raise HTTPException(
                status_code=500,
                detail=f"Unexpected error: {str(e)}"
            )

