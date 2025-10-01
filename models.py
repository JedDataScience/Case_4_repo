from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, EmailStr, validator
import hashlib
import secrets

class SurveySubmission(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    email: EmailStr
    age: int = Field(..., ge=13, le=120)
    consent: bool = Field(..., description="Must be true to accept")
    rating: int = Field(..., ge=1, le=5)
    comments: Optional[str] = Field(None, max_length=1000)
    user_agent: Optional[str] = Field(None, max_length=500, description="Browser or client identifier")
    submission_id: Optional[str] = Field(None, max_length=64, description="Unique submission identifier")
  
    @staticmethod
    def _hash_pii(value: str, salt: str = None) -> str:
        """Hash PII using SHA-256 with salt for additional security."""
        if salt is None:
            salt = secrets.token_hex(16)  # Generate random salt
        salted_value = f"{value}:{salt}"
        return hashlib.sha256(salted_value.encode('utf-8')).hexdigest()
    
    @staticmethod
    def _generate_submission_id(email: str, timestamp: datetime = None) -> str:
        """Generate submission_id by hashing email + YYYYMMDDHH."""
        if timestamp is None:
            timestamp = datetime.now()
        
        # Format as YYYYMMDDHH (year, month, day, hour)
        date_hour = timestamp.strftime("%Y%m%d%H")
        
        # Hash email + date_hour
        combined = f"{email}{date_hour}"
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()

    @validator("comments")
    def _strip_comments(cls, v):
        return v.strip() if isinstance(v, str) else v

    @validator("consent")
    def _must_consent(cls, v):
        if v is not True:
            raise ValueError("consent must be true")
        return v
        
#Good example of inheritance
class StoredSurveyRecord(SurveySubmission):
    received_at: datetime
    ip: str
    # Hashed PII fields - these replace the original email and age in storage
    email_hash: str = Field(..., description="SHA-256 hash of email with salt")
    age_hash: str = Field(..., description="SHA-256 hash of age with salt")
    email_salt: str = Field(..., description="Salt used for email hashing")
    age_salt: str = Field(..., description="Salt used for age hashing")
    
    @classmethod
    def from_submission(cls, submission: SurveySubmission, received_at: datetime, ip: str):
        """Create a StoredSurveyRecord with hashed PII from a SurveySubmission."""
        # Generate unique salts for each PII field
        email_salt = secrets.token_hex(16)
        age_salt = secrets.token_hex(16)
        
        # Hash the PII fields
        email_hash = submission._hash_pii(submission.email, email_salt)
        age_hash = submission._hash_pii(str(submission.age), age_salt)
        
        # Handle submission_id: use provided value or generate one
        submission_id = submission.submission_id
        if submission_id is None:
            submission_id = submission._generate_submission_id(submission.email, received_at)
        
        # Create the record with hashed PII
        return cls(
            name=submission.name,
            email=submission.email,  # Keep for validation, but won't be stored
            age=submission.age,      # Keep for validation, but won't be stored
            consent=submission.consent,
            rating=submission.rating,
            comments=submission.comments,
            user_agent=submission.user_agent,
            submission_id=submission_id,
            received_at=received_at,
            ip=ip,
            email_hash=email_hash,
            age_hash=age_hash,
            email_salt=email_salt,
            age_salt=age_salt
        )
    
    def to_storage_dict(self) -> dict:
        """Convert to dictionary for storage, excluding original PII."""
        return {
            "name": self.name,
            "consent": self.consent,
            "rating": self.rating,
            "comments": self.comments,
            "user_agent": self.user_agent,
            "submission_id": self.submission_id,
            "received_at": self.received_at,
            "ip": self.ip,
            "email_hash": self.email_hash,
            "age_hash": self.age_hash,
            "email_salt": self.email_salt,
            "age_salt": self.age_salt
        }
