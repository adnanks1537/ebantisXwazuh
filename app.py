import os
import logging
import json
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from datetime import datetime, timedelta
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import certifi
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
    "https://your-frontend.com",
    "https://98.172.144.86:55000",
    "*"  # Remove in production
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# MongoDB setup
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    logger.error("MONGO_URI environment variable not set")
    raise RuntimeError("MONGO_URI not set")

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((ConnectionFailure, ServerSelectionTimeoutError)),
    before_sleep=lambda retry_state: logger.warning(f"Retrying MongoDB connection: attempt {retry_state.attempt_number}")
)
def get_mongo_client():
    try:
        client = MongoClient(
            MONGO_URI,
            tls=True,
            tlsCAFile=certifi.where(),
            serverSelectionTimeoutMS=30000,
            socketTimeoutMS=30000,
            connectTimeoutMS=30000
        )
        # Test connection
        client.admin.command("ping")
        logger.info("Successfully connected to MongoDB")
        return client
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {str(e)}")
        raise

try:
    client = get_mongo_client()
    db = client["wazuh_alerts"]  # Database: wazuh_alerts
    alerts_collection = db["alerts"]  # Collection: alerts
except Exception as e:
    logger.critical(f"Cannot initialize MongoDB client: {str(e)}")
    raise

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
async def receive_alert(alert: Dict[Any, Any]):
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

        # Create document
        db_alert = {
            "timestamp": timestamp,
            "rule_id": rule.get("id", ""),
            "rule_description": rule.get("description", ""),
            "rule_level": rule.get("level", 0),
            "agent_id": agent.get("id", ""),
            "agent_name": agent.get("name", ""),
            "event": json.dumps(alert)  # Store full alert as JSON string
        }
        alerts_collection.insert_one(db_alert)
        logger.info(f"Stored alert: rule_id={rule.get('id')}, timestamp={timestamp_str}, agent_id={agent.get('id')}")
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error processing alert: {str(e)}, alert={alert}")
        raise HTTPException(status_code=500, detail=f"Error processing alert: {str(e)}")

# Endpoint: Fetch alerts
@app.get(
    "/alerts",
    summary="Fetch stored Wazuh alerts"
)
async def get_alerts(query: AlertQuery = AlertQuery()):
    try:
        # Build query
        mongo_query = {}
        if query.rule_level is not None:
            mongo_query["rule_level"] = {"$gte": query.rule_level}
        if query.agent_id:
            mongo_query["agent_id"] = query.agent_id

        # Fetch alerts
        cursor = alerts_collection.find(mongo_query).skip(query.offset).limit(query.limit)
        alerts = list(cursor)
        total = alerts_collection.count_documents(mongo_query)

        # Format response
        return {
            "alerts": [
                {
                    "timestamp": a["timestamp"].isoformat(),
                    "rule": {
                        "id": a["rule_id"],
                        "description": a["rule_description"],
                        "level": a["rule_level"]
                    },
                    "agent": {
                        "id": a["agent_id"],
                        "name": a["agent_name"]
                    },
                    "event": a["event"]
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
async def get_alerts_summary(query: SummaryQuery = SummaryQuery()):
    try:
        # Build query
        mongo_query = {}
        if query.timeframe:
            hours = int(query.timeframe.replace("h", ""))
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            mongo_query["timestamp"] = {"$gte": time_threshold}

        # Aggregate by rule_level
        pipeline = [
            {"$match": mongo_query},
            {
                "$group": {
                    "_id": "$rule_level",
                    "count": {"$sum": 1}
                }
            },
            {
                "$project": {
                    "rule_level": "$_id",
                    "count": 1,
                    "_id": 0
                }
            }
        ]
        summary = list(alerts_collection.aggregate(pipeline))
        return {
            "summary": summary,
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
async def get_agents(query: AgentQuery = AgentQuery()):
    try:
        # Aggregate distinct agents
        pipeline = [
            {
                "$group": {
                    "_id": {
                        "agent_id": "$agent_id",
                        "agent_name": "$agent_name"
                    }
                }
            },
            {
                "$project": {
                    "agent_id": "$_id.agent_id",
                    "agent_name": "$_id.agent_name",
                    "_id": 0
                }
            },
            {"$skip": query.offset},
            {"$limit": query.limit}
        ]
        agents = list(alerts_collection.aggregate(pipeline))
        total = alerts_collection.count_documents({})

        if query.status:
            logger.warning("Agent status filter not supported in this implementation")

        return {
            "agents": [
                {"id": a["agent_id"], "name": a["agent_name"]} for a in agents
            ],
            "total": total
        }
    except Exception as e:
        logger.error(f"Error fetching agents: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error fetching agents: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
