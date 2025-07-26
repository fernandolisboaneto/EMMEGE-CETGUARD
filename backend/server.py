from fastapi import FastAPI, APIRouter, HTTPException, Request, Depends, status
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
import uuid
from datetime import datetime, timedelta
import json
import httpx
import asyncio
from enum import Enum
import hashlib
import hmac
import time
import jwt
from passlib.context import CryptContext
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import base64

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connections
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]
audit_db = client['certguard_audit']  # Separate database for audit

# Security
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Create the main app
app = FastAPI(title="CertGuard AI API", version="2.0.0")
api_router = APIRouter(prefix="/api")

# NVIDIA API Configuration
NVIDIA_API_KEY = os.environ.get('NVIDIA_API_KEY', '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')
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
NVIDIA_MODEL = "meta/llama-3.3-70b-instruct"

# Enums
class UserRole(str, Enum):
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    USER = "user"

class CertificateStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    EXPIRING_SOON = "expiring_soon"
    REVOKED = "revoked"
    SUSPENDED = "suspended"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ActionType(str, Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    CERTIFICATE_ACCESS = "certificate_access"
    SITE_ACCESS = "site_access"
    DOCUMENT_SIGN = "document_sign"
    NAVIGATION = "navigation"
    CLICK = "click"
    FORM_SUBMIT = "form_submit"
    ANOMALY_DETECTED = "anomaly_detected"

# Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: str
    full_name: str
    role: UserRole
    password: str
    created_by: Optional[str] = None
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None

class UserCreate(BaseModel):
    username: str
    email: str
    full_name: str
    password: str
    role: UserRole

class UserLogin(BaseModel):
    username: str
    password: str

class Certificate(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    common_name: str
    organization: str
    department: str
    email: str
    serial_number: str
    issuer: str
    subject: str
    valid_from: datetime
    valid_to: datetime
    status: CertificateStatus = CertificateStatus.ACTIVE
    algorithm: str = "RSA-2048"
    key_usage: List[str] = []
    san_dns: List[str] = []
    assigned_to: Optional[str] = None  # User ID
    assigned_by: Optional[str] = None  # Admin ID
    container_hash: Optional[str] = None  # Secure container hash
    blockchain_hash: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_used: Optional[datetime] = None
    usage_count: int = 0
    risk_level: RiskLevel = RiskLevel.LOW
    prediction_score: float = 0.0

class TribunalSite(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    abbreviation: str
    url: str
    category: str  # "Superior", "Regional Federal", "Estadual", "Trabalhista"
    state: Optional[str] = None
    consultation_url: Optional[str] = None
    requires_certificate: bool = True
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)

class UserSiteAccess(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    site_id: str
    certificate_id: str
    assigned_by: str  # Admin ID
    access_type: str = "full"  # "full", "read_only", "restricted"
    allowed_hours: Optional[List[str]] = None  # ["08:00-18:00"]
    allowed_days: Optional[List[str]] = None  # ["monday", "tuesday", ...]
    ip_restrictions: Optional[List[str]] = None
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None

class AuditLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    certificate_id: Optional[str] = None
    site_id: Optional[str] = None
    action_type: ActionType
    action_details: Dict[str, Any] = {}
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ip_address: str
    user_agent: str
    location: Optional[str] = None
    device_fingerprint: Optional[str] = None
    session_id: Optional[str] = None
    url: Optional[str] = None
    success: bool = True
    risk_score: float = 0.0
    anomaly_flags: List[str] = []
    blockchain_hash: Optional[str] = None
    previous_hash: Optional[str] = None

class SecurityAlert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    alert_type: str
    severity: RiskLevel
    message: str
    details: Dict[str, Any] = {}
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    resolved: bool = False
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None

class ContainerAccess(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    certificate_id: str
    site_url: str
    access_token: str
    expires_at: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)
    used_at: Optional[datetime] = None
    ip_address: str
    user_agent: str

# Tribunal Sites Data
TRIBUNAL_SITES = [
    # Superior Courts
    {"name": "Supremo Tribunal Federal", "abbreviation": "STF", "url": "https://www.stf.jus.br", "category": "Superior", "consultation_url": "https://www.stf.jus.br/portal/consultaProcessual/consultaProcessual.asp"},
    {"name": "Superior Tribunal de Justiça", "abbreviation": "STJ", "url": "https://www.stj.jus.br", "category": "Superior", "consultation_url": "https://www.stj.jus.br/webstj/Consulta/consulta_processo.asp"},
    {"name": "Tribunal Superior do Trabalho", "abbreviation": "TST", "url": "https://www.tst.jus.br", "category": "Superior", "consultation_url": "https://www.tst.jus.br/consulta-unificada"},
    
    # Regional Federal Courts
    {"name": "Tribunal Regional Federal 1ª Região", "abbreviation": "TRF1", "url": "https://www.trf1.jus.br", "category": "Regional Federal", "consultation_url": "https://www.trf1.jus.br/siscon/ConsultaProcessual/"},
    {"name": "Tribunal Regional Federal 2ª Região", "abbreviation": "TRF2", "url": "https://www.trf2.jus.br", "category": "Regional Federal", "consultation_url": "https://www.trf2.jus.br/siscon/ConsultaProcessual/"},
    {"name": "Tribunal Regional Federal 3ª Região", "abbreviation": "TRF3", "url": "https://www.trf3.jus.br", "category": "Regional Federal", "consultation_url": "https://www.trf3.jus.br/siscon/ConsultaProcessual/"},
    {"name": "Tribunal Regional Federal 4ª Região", "abbreviation": "TRF4", "url": "https://www.trf4.jus.br", "category": "Regional Federal", "consultation_url": "https://www.trf4.jus.br/siscon/ConsultaProcessual/"},
    {"name": "Tribunal Regional Federal 5ª Região", "abbreviation": "TRF5", "url": "https://www.trf5.jus.br", "category": "Regional Federal", "consultation_url": "https://www.trf5.jus.br/siscon/ConsultaProcessual/"},
    
    # State Courts (Major ones)
    {"name": "Tribunal de Justiça de São Paulo", "abbreviation": "TJSP", "url": "https://www.tjsp.jus.br", "category": "Estadual", "state": "SP", "consultation_url": "https://esaj.tjsp.jus.br/cpopg/open.do"},
    {"name": "Tribunal de Justiça do Rio de Janeiro", "abbreviation": "TJRJ", "url": "https://www.tjrj.jus.br", "category": "Estadual", "state": "RJ", "consultation_url": "https://www4.tjrj.jus.br/consultaProcessoWebV2/consultaMov.do"},
    {"name": "Tribunal de Justiça de Minas Gerais", "abbreviation": "TJMG", "url": "https://www.tjmg.jus.br", "category": "Estadual", "state": "MG", "consultation_url": "https://www4.tjmg.jus.br/juridico/sf/proc_completo.jsp"},
    {"name": "Tribunal de Justiça do Rio Grande do Sul", "abbreviation": "TJRS", "url": "https://www.tjrs.jus.br", "category": "Estadual", "state": "RS", "consultation_url": "https://www.tjrs.jus.br/site_php/consulta/consulta_processo.php"},
    {"name": "Tribunal de Justiça do Paraná", "abbreviation": "TJPR", "url": "https://www.tjpr.jus.br", "category": "Estadual", "state": "PR", "consultation_url": "https://portal.tjpr.jus.br/consultas/consultaProcessual.xhtml"},
    {"name": "Tribunal de Justiça da Bahia", "abbreviation": "TJBA", "url": "https://www.tjba.jus.br", "category": "Estadual", "state": "BA", "consultation_url": "https://esaj.tjba.jus.br/cpopg/open.do"},
    {"name": "Tribunal de Justiça de Santa Catarina", "abbreviation": "TJSC", "url": "https://www.tjsc.jus.br", "category": "Estadual", "state": "SC", "consultation_url": "https://esaj.tjsc.jus.br/cpopg/open.do"},
    {"name": "Tribunal de Justiça do Distrito Federal", "abbreviation": "TJDFT", "url": "https://www.tjdft.jus.br", "category": "Estadual", "state": "DF", "consultation_url": "https://www.tjdft.jus.br/consultas/consulta-processual"},
    {"name": "Tribunal de Justiça de Goiás", "abbreviation": "TJGO", "url": "https://www.tjgo.jus.br", "category": "Estadual", "state": "GO", "consultation_url": "https://projudi.tjgo.jus.br/ProjudiWeb/consulta/consultaPublica"},
    {"name": "Tribunal de Justiça do Ceará", "abbreviation": "TJCE", "url": "https://www.tjce.jus.br", "category": "Estadual", "state": "CE", "consultation_url": "https://esaj.tjce.jus.br/cpopg/open.do"},
]

# Security Functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = await db.users.find_one({"username": username})
    if user is None:
        raise credentials_exception
    
    if "_id" in user:
        del user["_id"]
    
    return User(**user)

# Secure Container Functions
def generate_container_hash(certificate_id: str, user_id: str) -> str:
    """Generate secure container hash for certificate"""
    data = f"{certificate_id}:{user_id}:{datetime.utcnow().isoformat()}"
    return hashlib.sha256(data.encode()).hexdigest()

def create_secure_container(certificate_id: str, user_id: str, private_key_pem: str) -> str:
    """Create secure container with encrypted private key"""
    # Simulate HSM encryption
    key = os.urandom(32)  # 256-bit key
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    
    # In production, this would use actual HSM
    encrypted_key = base64.b64encode(key + nonce + private_key_pem.encode()).decode()
    
    container_hash = generate_container_hash(certificate_id, user_id)
    
    return container_hash

# Blockchain Functions
def calculate_hash(data: str, previous_hash: str = "") -> str:
    """Calculate SHA-256 hash for blockchain simulation"""
    content = f"{previous_hash}{data}{time.time()}"
    return hashlib.sha256(content.encode()).hexdigest()

async def create_blockchain_entry(user_id: str, action_type: str, details: Dict[str, Any]) -> str:
    """Create blockchain entry in audit database"""
    last_entry = await audit_db.blockchain_entries.find_one(
        {}, sort=[("timestamp", -1)]
    )
    
    previous_hash = last_entry.get("hash", "0") if last_entry else "0"
    
    blockchain_data = {
        "user_id": user_id,
        "action_type": action_type,
        "details": details,
        "timestamp": datetime.utcnow().isoformat(),
        "previous_hash": previous_hash
    }
    
    current_hash = calculate_hash(json.dumps(blockchain_data, sort_keys=True), previous_hash)
    
    blockchain_entry = {
        "hash": current_hash,
        "previous_hash": previous_hash,
        "data": blockchain_data,
        "timestamp": datetime.utcnow()
    }
    
    await audit_db.blockchain_entries.insert_one(blockchain_entry)
    return current_hash

# AI Security Analysis Functions
async def analyze_user_behavior(user_id: str, current_action: Dict[str, Any]) -> Dict[str, Any]:
    """AI analysis of user behavior patterns"""
    # Get recent user activities
    recent_activities = await audit_db.user_activities.find(
        {"user_id": user_id}
    ).sort("timestamp", -1).limit(100).to_list(100)
    
    # Analyze patterns
    risk_factors = []
    risk_score = 0.0
    
    # Check for unusual time patterns
    current_hour = datetime.utcnow().hour
    if current_hour < 6 or current_hour > 22:
        risk_factors.append("Off-hours access")
        risk_score += 0.2
    
    # Check for location anomalies
    if current_action.get("location") and recent_activities:
        locations = [act.get("location") for act in recent_activities[-10:] if act.get("location")]
        if locations and current_action["location"] not in locations:
            risk_factors.append("Unusual location")
            risk_score += 0.3
    
    # Check for rapid successive actions
    if len(recent_activities) >= 5:
        time_diffs = []
        for i in range(min(4, len(recent_activities) - 1)):
            current_activity = recent_activities[i]
            next_activity = recent_activities[i+1]
            
            # Handle both datetime objects and ISO strings
            if isinstance(current_activity["timestamp"], datetime):
                current_time = current_activity["timestamp"]
            else:
                current_time = datetime.fromisoformat(str(current_activity["timestamp"]).replace("Z", "+00:00"))
                
            if isinstance(next_activity["timestamp"], datetime):
                next_time = next_activity["timestamp"]
            else:
                next_time = datetime.fromisoformat(str(next_activity["timestamp"]).replace("Z", "+00:00"))
                
            time_diffs.append(abs((current_time - next_time).seconds))
        
        if time_diffs and all(diff < 5 for diff in time_diffs):  # Less than 5 seconds between actions
            risk_factors.append("Rapid successive actions")
            risk_score += 0.4
    
    # AI prompt for advanced analysis
    prompt = f"""
    Análise de Segurança - CertGuard AI
    
    Usuário: {user_id}
    Ação atual: {json.dumps(current_action, indent=2)}
    
    Histórico recente (últimas {len(recent_activities)} atividades):
    {json.dumps([{
        'action': act['action_type'],
        'timestamp': act['timestamp'].isoformat() if isinstance(act['timestamp'], datetime) else str(act['timestamp']),
        'ip': act.get('ip_address'),
        'success': act.get('success', True)
    } for act in recent_activities[-10:]], indent=2)}
    
    Fatores de risco identificados: {risk_factors}
    Score de risco atual: {risk_score}
    
    Analise e determine:
    1. Nível de risco (LOW/MEDIUM/HIGH/CRITICAL)
    2. Anomalias detectadas
    3. Ações recomendadas
    4. Score de confiança (0-1)
    
    Responda em JSON:
    {{
        "risk_level": "MEDIUM",
        "anomalies": ["rapid_actions", "unusual_location"],
        "recommended_actions": ["require_mfa", "limit_access"],
        "confidence_score": 0.85,
        "analysis_details": "Detailed explanation"
    }}
    """
    
    # Call NVIDIA API for advanced analysis
    result = await call_nvidia_api(prompt)
    
    if "error" not in result:
        try:
            ai_response = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            import re
            json_match = re.search(r'\{[\s\S]*\}', ai_response)
            if json_match:
                ai_analysis = json.loads(json_match.group())
                return {
                    "risk_score": risk_score,
                    "risk_factors": risk_factors,
                    "ai_analysis": ai_analysis
                }
        except:
            pass
    
    return {
        "risk_score": risk_score,
        "risk_factors": risk_factors,
        "ai_analysis": {
            "risk_level": "MEDIUM" if risk_score > 0.3 else "LOW",
            "anomalies": risk_factors,
            "recommended_actions": ["monitor"] if risk_score < 0.3 else ["require_mfa"],
            "confidence_score": 0.7
        }
    }

async def call_nvidia_api(prompt: str) -> Dict[str, Any]:
    """Call NVIDIA API for AI analysis"""
    headers = {
        "Authorization": f"Bearer {NVIDIA_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": NVIDIA_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "top_p": 0.7,
        "max_tokens": 1024
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{NVIDIA_BASE_URL}/chat/completions",
                headers=headers,
                json=payload,
                timeout=30.0
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"NVIDIA API error: {e}")
            return {"error": str(e)}

# Audit Logging Function
async def log_user_activity(
    user_id: str,
    action_type: ActionType,
    request: Request,
    certificate_id: Optional[str] = None,
    site_id: Optional[str] = None,
    action_details: Optional[Dict[str, Any]] = None,
    success: bool = True
):
    """Log user activity to audit database"""
    
    # Analyze behavior for security
    current_action = {
        "action_type": action_type.value,
        "timestamp": datetime.utcnow().isoformat(),
        "ip_address": request.client.host,
        "user_agent": request.headers.get("user-agent", ""),
        "success": success
    }
    
    behavior_analysis = await analyze_user_behavior(user_id, current_action)
    
    # Create audit log entry
    audit_log = AuditLog(
        user_id=user_id,
        certificate_id=certificate_id,
        site_id=site_id,
        action_type=action_type,
        action_details=action_details or {},
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent", ""),
        success=success,
        risk_score=behavior_analysis["risk_score"],
        anomaly_flags=behavior_analysis["risk_factors"]
    )
    
    # Create blockchain entry
    blockchain_hash = await create_blockchain_entry(
        user_id,
        action_type.value,
        {
            "certificate_id": certificate_id,
            "site_id": site_id,
            "details": action_details,
            "risk_score": behavior_analysis["risk_score"]
        }
    )
    
    audit_log.blockchain_hash = blockchain_hash
    
    # Save to audit database
    await audit_db.user_activities.insert_one(audit_log.dict())
    
    # Check for high-risk activities
    if behavior_analysis["risk_score"] > 0.5:
        alert = SecurityAlert(
            user_id=user_id,
            alert_type="HIGH_RISK_ACTIVITY",
            severity=RiskLevel.HIGH,
            message=f"High-risk activity detected: {action_type.value}",
            details=behavior_analysis
        )
        await audit_db.security_alerts.insert_one(alert.dict())
    
    return audit_log

# API Routes

# Authentication Routes
@api_router.post("/auth/login")
async def login(login_data: UserLogin, request: Request):
    """User login"""
    user = await db.users.find_one({"username": login_data.username})
    if not user or not verify_password(login_data.password, user["password"]):
        # Log failed login attempt
        if user:
            await log_user_activity(
                user["id"],
                ActionType.LOGIN,
                request,
                success=False,
                action_details={"reason": "invalid_password"}
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled"
        )
    
    # Update last login
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"last_login": datetime.utcnow()}}
    )
    
    # Log successful login
    await log_user_activity(
        user["id"],
        ActionType.LOGIN,
        request,
        action_details={"login_method": "password"}
    )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"]
        }
    }

@api_router.post("/auth/logout")
async def logout(request: Request, current_user: User = Depends(get_current_user)):
    """User logout"""
    await log_user_activity(
        current_user.id,
        ActionType.LOGOUT,
        request
    )
    return {"message": "Logged out successfully"}

# User Management Routes
@api_router.post("/users", response_model=User)
async def create_user(
    user_data: UserCreate,
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Create new user (Super Admin creates Admin, Admin creates Users)"""
    
    # Check permissions
    if current_user.role == UserRole.SUPER_ADMIN and user_data.role not in [UserRole.ADMIN, UserRole.USER]:
        raise HTTPException(status_code=403, detail="Super Admin can only create Admin or User accounts")
    elif current_user.role == UserRole.ADMIN and user_data.role != UserRole.USER:
        raise HTTPException(status_code=403, detail="Admin can only create User accounts")
    elif current_user.role == UserRole.USER:
        raise HTTPException(status_code=403, detail="Users cannot create other accounts")
    
    # Check if user already exists
    existing_user = await db.users.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Create user
    user_dict = user_data.dict()
    user_dict["password"] = hash_password(user_data.password)
    user_dict["created_by"] = current_user.id
    
    user_obj = User(**user_dict)
    await db.users.insert_one(user_obj.dict())
    
    # Log user creation
    await log_user_activity(
        current_user.id,
        ActionType.LOGIN,  # Using LOGIN as placeholder for user creation
        request,
        action_details={"created_user": user_obj.id, "user_role": user_data.role}
    )
    
    return user_obj

@api_router.get("/users", response_model=List[User])
async def get_users(
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 100
):
    """Get users based on role hierarchy"""
    
    # Super Admin sees all, Admin sees users they created, User sees none
    if current_user.role == UserRole.SUPER_ADMIN:
        users = await db.users.find().skip(skip).limit(limit).to_list(limit)
    elif current_user.role == UserRole.ADMIN:
        users = await db.users.find({"created_by": current_user.id}).skip(skip).limit(limit).to_list(limit)
    else:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # Clean up MongoDB ObjectIds
    for user in users:
        if "_id" in user:
            del user["_id"]
    
    return [User(**user) for user in users]

# Certificate Management Routes
@api_router.post("/certificates", response_model=Certificate)
async def create_certificate(
    cert_data: Dict[str, Any],
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Create certificate (Admin only)"""
    
    if current_user.role not in [UserRole.SUPER_ADMIN, UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Only Admins can create certificates")
    
    # Generate certificate details
    cert_dict = {
        "name": cert_data.get("name"),
        "common_name": cert_data.get("common_name"),
        "organization": cert_data.get("organization"),
        "department": cert_data.get("department"),
        "email": cert_data.get("email"),
        "valid_from": datetime.fromisoformat(cert_data.get("valid_from")),
        "valid_to": datetime.fromisoformat(cert_data.get("valid_to")),
        "algorithm": cert_data.get("algorithm", "RSA-2048"),
        "key_usage": cert_data.get("key_usage", []),
        "san_dns": cert_data.get("san_dns", []),
        "serial_number": str(uuid.uuid4()),
        "issuer": f"CN=CertGuard AI CA, O={cert_data.get('organization')}",
        "subject": f"CN={cert_data.get('common_name')}, O={cert_data.get('organization')}, OU={cert_data.get('department')}"
    }
    
    cert_obj = Certificate(**cert_dict)
    
    # Create secure container
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    ).decode()
    
    cert_obj.container_hash = create_secure_container(cert_obj.id, current_user.id, private_key_pem)
    
    # Save certificate
    await db.certificates.insert_one(cert_obj.dict())
    
    # Log certificate creation
    await log_user_activity(
        current_user.id,
        ActionType.CERTIFICATE_ACCESS,
        request,
        certificate_id=cert_obj.id,
        action_details={"action": "create", "certificate_name": cert_obj.name}
    )
    
    return cert_obj

@api_router.post("/certificates/{cert_id}/assign")
async def assign_certificate_to_user(
    cert_id: str,
    assignment_data: Dict[str, Any],
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Assign certificate to user (Admin only)"""
    
    if current_user.role not in [UserRole.SUPER_ADMIN, UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Only Admins can assign certificates")
    
    # Get certificate
    cert = await db.certificates.find_one({"id": cert_id})
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    
    # Get user
    user_id = assignment_data.get("user_id")
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update certificate assignment
    await db.certificates.update_one(
        {"id": cert_id},
        {"$set": {
            "assigned_to": user_id,
            "assigned_by": current_user.id,
            "updated_at": datetime.utcnow()
        }}
    )
    
    # Log assignment
    await log_user_activity(
        current_user.id,
        ActionType.CERTIFICATE_ACCESS,
        request,
        certificate_id=cert_id,
        action_details={
            "action": "assign",
            "assigned_to": user_id,
            "assigned_user": user["username"]
        }
    )
    
    return {"message": "Certificate assigned successfully"}

@api_router.post("/certificates/{cert_id}/sites")
async def assign_certificate_to_sites(
    cert_id: str,
    site_assignments: Dict[str, Any],
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Assign certificate to sites for a user (Admin only)"""
    
    if current_user.role not in [UserRole.SUPER_ADMIN, UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Only Admins can assign certificate to sites")
    
    user_id = site_assignments.get("user_id")
    site_ids = site_assignments.get("site_ids", [])
    
    # Create site access entries
    for site_id in site_ids:
        access = UserSiteAccess(
            user_id=user_id,
            site_id=site_id,
            certificate_id=cert_id,
            assigned_by=current_user.id,
            access_type=site_assignments.get("access_type", "full"),
            allowed_hours=site_assignments.get("allowed_hours"),
            allowed_days=site_assignments.get("allowed_days"),
            ip_restrictions=site_assignments.get("ip_restrictions"),
            expires_at=datetime.fromisoformat(site_assignments["expires_at"]) if site_assignments.get("expires_at") else None
        )
        
        await db.user_site_access.insert_one(access.dict())
    
    # Log site assignment
    await log_user_activity(
        current_user.id,
        ActionType.SITE_ACCESS,
        request,
        certificate_id=cert_id,
        action_details={
            "action": "assign_sites",
            "user_id": user_id,
            "site_ids": site_ids,
            "access_type": site_assignments.get("access_type", "full")
        }
    )
    
    return {"message": "Certificate assigned to sites successfully"}

# Tribunal Sites Routes
@api_router.get("/tribunal-sites", response_model=List[TribunalSite])
async def get_tribunal_sites(
    current_user: User = Depends(get_current_user),
    category: Optional[str] = None
):
    """Get tribunal sites"""
    
    query = {}
    if category:
        query["category"] = category
    
    sites = await db.tribunal_sites.find(query).to_list(1000)
    
    # Clean up MongoDB ObjectIds
    for site in sites:
        if "_id" in site:
            del site["_id"]
    
    return [TribunalSite(**site) for site in sites]

@api_router.get("/user/accessible-sites")
async def get_user_accessible_sites(
    current_user: User = Depends(get_current_user)
):
    """Get sites accessible to current user"""
    
    # Get user's site access
    access_entries = await db.user_site_access.find({
        "user_id": current_user.id,
        "is_active": True
    }).to_list(1000)
    
    # Get site details
    accessible_sites = []
    for access in access_entries:
        site = await db.tribunal_sites.find_one({"id": access["site_id"]})
        if site:
            if "_id" in site:
                del site["_id"]
            accessible_sites.append({
                "site": TribunalSite(**site),
                "access": access
            })
    
    return accessible_sites

# Container Access Routes
@api_router.post("/container/access")
async def request_container_access(
    access_request: Dict[str, Any],
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Request secure container access for site"""
    
    certificate_id = access_request.get("certificate_id")
    site_url = access_request.get("site_url")
    
    # Verify user has access to certificate and site
    cert = await db.certificates.find_one({
        "id": certificate_id,
        "assigned_to": current_user.id,
        "status": "active"
    })
    
    if not cert:
        raise HTTPException(status_code=403, detail="Certificate not accessible")
    
    # Check site access
    site_access = await db.user_site_access.find_one({
        "user_id": current_user.id,
        "certificate_id": certificate_id,
        "is_active": True
    })
    
    if not site_access:
        raise HTTPException(status_code=403, detail="Site not accessible")
    
    # Generate secure access token
    access_token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=1)
    
    container_access = ContainerAccess(
        user_id=current_user.id,
        certificate_id=certificate_id,
        site_url=site_url,
        access_token=access_token,
        expires_at=expires_at,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent", "")
    )
    
    await db.container_access.insert_one(container_access.dict())
    
    # Log container access
    await log_user_activity(
        current_user.id,
        ActionType.SITE_ACCESS,
        request,
        certificate_id=certificate_id,
        action_details={
            "action": "request_container_access",
            "site_url": site_url,
            "access_token": access_token[:8] + "..."
        }
    )
    
    return {
        "access_token": access_token,
        "expires_at": expires_at.isoformat(),
        "container_hash": cert["container_hash"]
    }

# Security and Audit Routes
@api_router.get("/audit/user/{user_id}")
async def get_user_audit_trail(
    user_id: str,
    current_user: User = Depends(get_current_user),
    limit: int = 100
):
    """Get user audit trail (Admin only)"""
    
    if current_user.role not in [UserRole.SUPER_ADMIN, UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Only Admins can view audit trails")
    
    # Get audit logs from audit database
    audit_logs = await audit_db.user_activities.find(
        {"user_id": user_id}
    ).sort("timestamp", -1).limit(limit).to_list(limit)
    
    # Clean up MongoDB ObjectIds
    for log in audit_logs:
        if "_id" in log:
            del log["_id"]
    
    return audit_logs

@api_router.get("/security/alerts")
async def get_security_alerts(
    current_user: User = Depends(get_current_user),
    limit: int = 50
):
    """Get security alerts (Admin only)"""
    
    if current_user.role not in [UserRole.SUPER_ADMIN, UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Only Admins can view security alerts")
    
    alerts = await audit_db.security_alerts.find(
        {"resolved": False}
    ).sort("timestamp", -1).limit(limit).to_list(limit)
    
    # Clean up MongoDB ObjectIds
    for alert in alerts:
        if "_id" in alert:
            del alert["_id"]
    
    return alerts

@api_router.get("/dashboard/admin")
async def get_admin_dashboard(
    current_user: User = Depends(get_current_user)
):
    """Get admin dashboard data"""
    
    if current_user.role not in [UserRole.SUPER_ADMIN, UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Only Admins can view admin dashboard")
    
    # Get statistics
    total_users = await db.users.count_documents({})
    total_certificates = await db.certificates.count_documents({})
    active_certificates = await db.certificates.count_documents({"status": "active"})
    
    # Get recent activities
    recent_activities = await audit_db.user_activities.find().sort("timestamp", -1).limit(10).to_list(10)
    
    # Get security alerts
    unresolved_alerts = await audit_db.security_alerts.count_documents({"resolved": False})
    
    # Clean up MongoDB ObjectIds
    for activity in recent_activities:
        if "_id" in activity:
            del activity["_id"]
        if "timestamp" in activity and isinstance(activity["timestamp"], datetime):
            activity["timestamp"] = activity["timestamp"].isoformat()
    
    return {
        "total_users": total_users,
        "total_certificates": total_certificates,
        "active_certificates": active_certificates,
        "unresolved_alerts": unresolved_alerts,
        "recent_activities": recent_activities,
        "timestamp": datetime.utcnow().isoformat()
    }

# Initialize tribunal sites
@api_router.post("/init/tribunal-sites")
async def initialize_tribunal_sites(
    current_user: User = Depends(get_current_user)
):
    """Initialize tribunal sites (Super Admin only)"""
    
    if current_user.role != UserRole.SUPER_ADMIN:
        raise HTTPException(status_code=403, detail="Only Super Admin can initialize tribunal sites")
    
    # Check if sites already exist
    existing_count = await db.tribunal_sites.count_documents({})
    if existing_count > 0:
        return {"message": f"Tribunal sites already initialized ({existing_count} sites)"}
    
    # Insert tribunal sites
    for site_data in TRIBUNAL_SITES:
        site = TribunalSite(**site_data)
        await db.tribunal_sites.insert_one(site.dict())
    
    return {"message": f"Initialized {len(TRIBUNAL_SITES)} tribunal sites"}

# Root endpoint
@api_router.get("/")
async def root():
    return {
        "message": "CertGuard AI - Advanced Certificate Management System",
        "version": "2.0.0",
        "features": [
            "Hierarchical User Management",
            "Secure Container Technology",
            "AI-Powered Security Analysis",
            "Blockchain Audit Trail",
            "Multi-Browser Extension Support",
            "Tribunal Sites Integration"
        ]
    }

# Include router
app.include_router(api_router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_event():
    """Initialize system on startup"""
    logger.info("CertGuard AI System starting up...")
    
    # Create super admin if not exists
    super_admin = await db.users.find_one({"role": "super_admin"})
    if not super_admin:
        super_admin_data = {
            "username": "superadmin",
            "email": "admin@certguard.ai",
            "full_name": "Super Administrator",
            "role": UserRole.SUPER_ADMIN,
            "password": hash_password("CertGuard@2025!"),
            "is_active": True,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "failed_login_attempts": 0
        }
        super_admin_user = User(**super_admin_data)
        await db.users.insert_one(super_admin_user.dict())
        logger.info("Super Admin created with default credentials")
    
    # Initialize tribunal sites
    existing_sites = await db.tribunal_sites.count_documents({})
    if existing_sites == 0:
        for site_data in TRIBUNAL_SITES:
            site = TribunalSite(**site_data)
            await db.tribunal_sites.insert_one(site.dict())
        logger.info(f"Initialized {len(TRIBUNAL_SITES)} tribunal sites")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()