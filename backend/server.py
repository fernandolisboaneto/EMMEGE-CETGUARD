from fastapi import FastAPI, APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
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

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="CertGuard AI API", version="1.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# NVIDIA API Configuration
NVIDIA_API_KEY = os.environ.get('NVIDIA_API_KEY', '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')
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
NVIDIA_MODEL = "meta/llama-3.3-70b-instruct"

# Certificate Status Enum
class CertificateStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    EXPIRING_SOON = "expiring_soon"
    REVOKED = "revoked"
    SUSPENDED = "suspended"

# Risk Level Enum
class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Models
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
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_used: Optional[datetime] = None
    usage_count: int = 0
    risk_level: RiskLevel = RiskLevel.LOW
    prediction_score: float = 0.0

class CertificateCreate(BaseModel):
    name: str
    common_name: str
    organization: str
    department: str
    email: str
    valid_from: datetime
    valid_to: datetime
    algorithm: str = "RSA-2048"
    key_usage: List[str] = []
    san_dns: List[str] = []

class AuditLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    certificate_id: str
    action: str
    user_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    details: Dict[str, Any] = {}
    ip_address: str
    user_agent: str
    location: Optional[str] = None
    blockchain_hash: Optional[str] = None
    previous_hash: Optional[str] = None

class PredictionRequest(BaseModel):
    certificate_id: Optional[str] = None
    context: str
    time_horizon: int = 30  # days

class ChatMessage(BaseModel):
    message: str
    context: Optional[Dict[str, Any]] = {}

class ZeroTrustContext(BaseModel):
    user_id: str
    ip_address: str
    user_agent: str
    location: Optional[str] = None
    device_fingerprint: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    trust_score: float = 0.0
    risk_factors: List[str] = []

# Blockchain Simulation Functions
def calculate_hash(data: str, previous_hash: str = "") -> str:
    """Calculate SHA-256 hash for blockchain simulation"""
    content = f"{previous_hash}{data}"
    return hashlib.sha256(content.encode()).hexdigest()

async def create_blockchain_entry(certificate_id: str, action: str, user_id: str, details: Dict[str, Any]) -> str:
    """Create a new blockchain entry for audit trail"""
    # Get last blockchain entry
    last_entry = await db.audit_logs.find_one(
        {"certificate_id": certificate_id}, 
        sort=[("timestamp", -1)]
    )
    
    previous_hash = last_entry.get("blockchain_hash", "0") if last_entry else "0"
    
    # Create blockchain data
    blockchain_data = {
        "certificate_id": certificate_id,
        "action": action,
        "user_id": user_id,
        "timestamp": datetime.utcnow().isoformat(),
        "details": details
    }
    
    current_hash = calculate_hash(json.dumps(blockchain_data, sort_keys=True), previous_hash)
    
    return current_hash

# AI Integration Functions
async def call_nvidia_api(prompt: str) -> Dict[str, Any]:
    """Call NVIDIA API for AI predictions"""
    headers = {
        "Authorization": f"Bearer {NVIDIA_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": NVIDIA_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
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

async def predict_certificate_needs(certificate_id: str, context: str, time_horizon: int = 30) -> Dict[str, Any]:
    """AI-powered certificate prediction"""
    # Get certificate data
    cert = await db.certificates.find_one({"id": certificate_id})
    if not cert:
        return {"error": "Certificate not found"}
    
    # Get usage history
    usage_history = await db.audit_logs.find(
        {"certificate_id": certificate_id}
    ).to_list(100)
    
    # Create AI prompt
    prompt = f"""
    Análise de Certificado Digital - CertGuard AI
    
    Certificado: {cert['name']}
    Organização: {cert['organization']}
    Válido até: {cert['valid_to']}
    Status atual: {cert['status']}
    Uso atual: {cert['usage_count']} vezes
    
    Histórico de uso (últimas {len(usage_history)} operações):
    {json.dumps([{
        'action': log['action'],
        'timestamp': log['timestamp'].isoformat() if isinstance(log['timestamp'], datetime) else log['timestamp'],
        'details': log.get('details', {})
    } for log in usage_history[-10:]], indent=2)}
    
    Contexto: {context}
    Horizonte de tempo: {time_horizon} dias
    
    Por favor, analise e forneça:
    1. Probabilidade de renovação necessária (0-100%)
    2. Risco de expiração não planejada (LOW/MEDIUM/HIGH/CRITICAL)
    3. Padrões de uso suspeitos (sim/não)
    4. Recomendações específicas
    5. Ações preventivas sugeridas
    
    Responda em formato JSON:
    {{
        "renewal_probability": 85,
        "risk_level": "MEDIUM",
        "suspicious_patterns": false,
        "recommendations": ["renovar em 15 dias", "verificar integração com sistema X"],
        "preventive_actions": ["configurar alerta", "backup de chave"],
        "confidence_score": 0.95
    }}
    """
    
    result = await call_nvidia_api(prompt)
    
    if "error" in result:
        return result
    
    try:
        # Extract JSON from AI response
        ai_response = result.get("choices", [{}])[0].get("message", {}).get("content", "")
        
        # Try to parse JSON from response
        import re
        json_match = re.search(r'\{[\s\S]*\}', ai_response)
        if json_match:
            prediction = json.loads(json_match.group())
            
            # Update certificate with prediction
            await db.certificates.update_one(
                {"id": certificate_id},
                {"$set": {
                    "prediction_score": prediction.get("confidence_score", 0.0),
                    "risk_level": prediction.get("risk_level", "low").lower(),
                    "updated_at": datetime.utcnow()
                }}
            )
            
            return prediction
        else:
            return {"error": "Could not parse AI response", "raw_response": ai_response}
            
    except Exception as e:
        logger.error(f"Error processing AI prediction: {e}")
        return {"error": str(e), "raw_response": result}

# Zero Trust Functions
async def calculate_trust_score(context: ZeroTrustContext) -> float:
    """Calculate trust score based on context"""
    score = 1.0
    
    # Check IP reputation (simplified)
    recent_logins = await db.audit_logs.find({
        "ip_address": context.ip_address,
        "timestamp": {"$gte": datetime.utcnow() - timedelta(hours=24)}
    }).to_list(100)
    
    if len(recent_logins) > 10:
        score -= 0.2  # Frequent access from same IP
    
    # Check user agent consistency
    user_agent_history = await db.audit_logs.find({
        "user_id": context.user_id,
        "timestamp": {"$gte": datetime.utcnow() - timedelta(days=7)}
    }).to_list(100)
    
    unique_agents = set(log.get("user_agent", "") for log in user_agent_history)
    if len(unique_agents) > 5:
        score -= 0.1  # Multiple user agents
    
    # Time-based scoring
    current_hour = datetime.utcnow().hour
    if current_hour < 6 or current_hour > 22:
        score -= 0.1  # Off-hours access
    
    return max(0.0, min(1.0, score))

# API Routes
@api_router.get("/")
async def root():
    return {"message": "CertGuard AI - Next Generation Certificate Management", "version": "1.0.0"}

@api_router.post("/certificates", response_model=Certificate)
async def create_certificate(cert_data: CertificateCreate, request: Request):
    """Create a new certificate"""
    # Generate certificate details
    cert_dict = cert_data.dict()
    cert_dict["serial_number"] = str(uuid.uuid4())
    cert_dict["issuer"] = f"CN=CertGuard AI CA, O={cert_data.organization}"
    cert_dict["subject"] = f"CN={cert_data.common_name}, O={cert_data.organization}, OU={cert_data.department}"
    
    cert_obj = Certificate(**cert_dict)
    
    # Save to database
    await db.certificates.insert_one(cert_obj.dict())
    
    # Create blockchain audit entry
    blockchain_hash = await create_blockchain_entry(
        cert_obj.id,
        "CREATE_CERTIFICATE",
        "system",
        {"certificate_name": cert_obj.name, "organization": cert_obj.organization}
    )
    
    # Create audit log
    audit_log = AuditLog(
        certificate_id=cert_obj.id,
        action="CREATE_CERTIFICATE",
        user_id="system",
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent", ""),
        blockchain_hash=blockchain_hash,
        details={"certificate_name": cert_obj.name}
    )
    
    await db.audit_logs.insert_one(audit_log.dict())
    
    return cert_obj

@api_router.get("/certificates", response_model=List[Certificate])
async def get_certificates(skip: int = 0, limit: int = 100):
    """Get all certificates with pagination"""
    certificates = await db.certificates.find().skip(skip).limit(limit).to_list(limit)
    # Convert ObjectId to string for JSON serialization
    for cert in certificates:
        if "_id" in cert:
            del cert["_id"]
        # Convert risk_level to lowercase if it exists
        if "risk_level" in cert:
            cert["risk_level"] = cert["risk_level"].lower()
    return [Certificate(**cert) for cert in certificates]

@api_router.get("/certificates/{certificate_id}", response_model=Certificate)
async def get_certificate(certificate_id: str):
    """Get specific certificate"""
    cert = await db.certificates.find_one({"id": certificate_id})
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    # Convert ObjectId to string for JSON serialization
    if "_id" in cert:
        del cert["_id"]
    # Convert risk_level to lowercase if it exists
    if "risk_level" in cert:
        cert["risk_level"] = cert["risk_level"].lower()
    return Certificate(**cert)

@api_router.post("/certificates/{certificate_id}/predict")
async def predict_certificate(certificate_id: str, prediction_request: PredictionRequest):
    """AI-powered certificate prediction"""
    prediction = await predict_certificate_needs(
        certificate_id,
        prediction_request.context,
        prediction_request.time_horizon
    )
    return prediction

@api_router.get("/certificates/expiring/{days}")
async def get_expiring_certificates(days: int = 30):
    """Get certificates expiring within specified days"""
    expiry_date = datetime.utcnow() + timedelta(days=days)
    certificates = await db.certificates.find({
        "valid_to": {"$lte": expiry_date},
        "status": "active"
    }).to_list(1000)
    
    # Convert ObjectId to string for JSON serialization
    for cert in certificates:
        if "_id" in cert:
            del cert["_id"]
        # Convert risk_level to lowercase if it exists
        if "risk_level" in cert:
            cert["risk_level"] = cert["risk_level"].lower()
    
    return [Certificate(**cert) for cert in certificates]

@api_router.post("/chat")
async def chat_with_ai(chat_message: ChatMessage):
    """Conversational AI interface"""
    # Create context-aware prompt
    prompt = f"""
    Você é o CertGuard AI, um assistente especializado em gestão de certificados digitais.
    
    Mensagem do usuário: {chat_message.message}
    
    Contexto atual: {json.dumps(chat_message.context, indent=2)}
    
    Responda de forma útil e específica sobre certificados digitais, renovações, segurança, e compliance.
    Se o usuário solicitar ações específicas, explique como fazê-las no sistema CertGuard AI.
    
    Seja conciso mas completo. Responda em português brasileiro.
    """
    
    result = await call_nvidia_api(prompt)
    
    if "error" in result:
        return {"error": result["error"]}
    
    ai_response = result.get("choices", [{}])[0].get("message", {}).get("content", "")
    
    return {
        "response": ai_response,
        "timestamp": datetime.utcnow(),
        "context": chat_message.context
    }

@api_router.get("/audit/{certificate_id}")
async def get_audit_trail(certificate_id: str):
    """Get immutable audit trail for certificate"""
    audit_logs = await db.audit_logs.find(
        {"certificate_id": certificate_id}
    ).sort("timestamp", 1).to_list(1000)
    
    # Convert ObjectId to string for JSON serialization
    for log in audit_logs:
        if "_id" in log:
            del log["_id"]
    
    return [AuditLog(**log) for log in audit_logs]

@api_router.post("/zero-trust/verify")
async def verify_zero_trust(context: ZeroTrustContext):
    """Zero Trust verification"""
    trust_score = await calculate_trust_score(context)
    
    risk_factors = []
    if trust_score < 0.5:
        risk_factors.append("Low trust score")
    
    if context.location and "BR" not in context.location:
        risk_factors.append("International access")
    
    current_hour = datetime.utcnow().hour
    if current_hour < 6 or current_hour > 22:
        risk_factors.append("Off-hours access")
    
    return {
        "trust_score": trust_score,
        "risk_factors": risk_factors,
        "access_granted": trust_score > 0.3,
        "requires_mfa": trust_score < 0.7,
        "timestamp": datetime.utcnow()
    }

@api_router.get("/dashboard/stats")
async def get_dashboard_stats():
    """Get dashboard statistics"""
    total_certs = await db.certificates.count_documents({})
    active_certs = await db.certificates.count_documents({"status": "active"})
    expiring_soon = await db.certificates.count_documents({
        "valid_to": {"$lte": datetime.utcnow() + timedelta(days=30)},
        "status": "active"
    })
    
    # Get recent activities
    recent_activities = await db.audit_logs.find().sort("timestamp", -1).limit(10).to_list(10)
    
    # Convert ObjectId to string for JSON serialization
    for activity in recent_activities:
        if "_id" in activity:
            del activity["_id"]
        # Convert datetime to string for JSON serialization
        if "timestamp" in activity and isinstance(activity["timestamp"], datetime):
            activity["timestamp"] = activity["timestamp"].isoformat()
    
    return {
        "total_certificates": total_certs,
        "active_certificates": active_certs,
        "expiring_soon": expiring_soon,
        "recent_activities": recent_activities,
        "timestamp": datetime.utcnow().isoformat()
    }

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()