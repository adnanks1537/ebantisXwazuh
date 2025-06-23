import os
import logging
import json
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="Wazuh Alerts API",
    description="Receive and query Wazuh alerts",
    version="1.0.0"
)

# CORS configuration
origins = [
    "http://localhost:3000",
    "https://your-frontend.com",  # Replace with your front-end domain
    "https://98.70.144.86:55000",
    "*"  # Remove in production
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# SQLite database setup
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///wazuh_alerts.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database model for alerts
class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime)
    rule_id = Column(String)
    rule_description = Column(String)
    rule_level = Column(Integer)
    agent_id = Column(String)
    agent_name = Column(String)
    event = Column(Text)  # Full JSON alert as text

# Create database tables
Base.metadata.create_all(bind=engine)

# Dependency for database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic models for API
class AlertQuery(BaseModel):
    limit: Optional[int] = 10
    offset: Optional[int] = 0
    rule_level: Optional[int] = None
    agent_id: Optional[str] = None

class SummaryQuery(BaseModel):
    timeframe: Optional[str] = None  # e.g., "24h"

class AgentQuery(BaseModel):
    limit: Optional[int] = 10
    offset: Optional[int] = 0
    status: Optional[str] = None

# Endpoint: Receive Wazuh alerts
@app.post(
    "/wazuh-alerts",
    summary="Receive alerts from Wazuh"
)
async def receive_alert(alert: Dict[Any, Any], db: Session = Depends(get_db)):
    try:
        # Log raw alert for debugging
        logger.debug(f"Received raw alert: {alert}")

        # Extract required fields
        timestamp_str = alert.get("timestamp")
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})

        # Parse timestamp (handle +0000 format)
        try:
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+0000")
        except (ValueError, TypeError) as e:
            logger.error(f"Invalid timestamp format: {timestamp_str}, error: {str(e)}")
            raise HTTPException(status_code=400, detail=f"Invalid timestamp format: {timestamp_str}")

        # Create database entry
        db_alert = Alert(
            timestamp=timestamp,
            rule_id=rule.get("id", ""),
            rule_description=rule.get("description", ""),
            rule_level=rule.get("level", 0),
            agent_id=agent.get("id", ""),
            agent_name=agent.get("name", ""),
            event=json.dumps(alert)  # Store full alert as JSON string
        )
        db.add(db_alert)
        db.commit()
        logger.info(f"Stored alert: rule_id={rule.get('id')}, timestamp={timestamp_str}")
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error processing alert: {str(e)}, alert={alert}")
        raise HTTPException(status_code=500, detail=f"Error processing alert: {str(e)}")

# Endpoint: Fetch alerts
@app.get(
    "/alerts",
    summary="Fetch stored Wazuh alerts"
)
async def get_alerts(query: AlertQuery = Depends(), db: Session = Depends(get_db)):
    try:
        db_query = db.query(Alert)
        if query.rule_level:
            db_query = db_query.filter(Alert.rule_level >= query.rule_level)
        if query.agent_id:
            db_query = db_query.filter(Alert.agent_id == query.agent_id)
        
        total = db_query.count()
        alerts = db_query.offset(query.offset).limit(query.limit).all()
        
        return {
            "alerts": [
                {
                    "timestamp": a.timestamp.isoformat(),
                    "rule": {"id": a.rule_id, "description": a.rule_description, "level": a.rule_level},
                    "agent": {"id": a.agent_id, "name": a.agent_name},
                    "event": a.event
                } for a in alerts
            ],
            "total": total
        }
    except Exception as e:
        logger.error(f"Error fetching alerts: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error fetching alerts: {str(e)}")

# Endpoint: Fetch alerts summary
@app.get(
    "/alerts/summary",
    summary="Fetch alerts summary"
)
async def get_alerts_summary(query: SummaryQuery = Depends(), db: Session = Depends(get_db)):
    try:
        db_query = db.query(Alert)
        if query.timeframe:
            hours = int(query.timeframe.replace("h", ""))
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            db_query = db_query.filter(Alert.timestamp >= time_threshold)
        
        from sqlalchemy.sql import func
        summary = db_query.group_by(Alert.rule_level).with_entities(
            Alert.rule_level, func.count(Alert.id).label("count")
        ).all()
        
        return {
            "summary": [{"rule_level": r.rule_level, "count": r.count} for r in summary],
            "total": len(summary)
        }
    except Exception as e:
        logger.error(f"Error fetching summary: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error fetching summary: {str(e)}")

# Endpoint: Fetch agent information
@app.get(
    "/agents",
    summary="Fetch agent information from alerts"
)
async def get_agents(query: AgentQuery = Depends(), db: Session = Depends(get_db)):
    try:
        db_query = db.query(Alert.agent_id, Alert.agent_name).distinct()
        if query.status:
            logger.warning("Agent status filter not supported in this implementation")
        
        total = db_query.count()
        agents = db_query.offset(query.offset).limit(query.limit).all()
        
        return {
            "agents": [
                {"id": a.agent_id, "name": a.agent_name} for a in agents
            ],
            "total": total
        }
    except Exception as e:
        logger.error(f"Error fetching agents: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error fetching agents: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
