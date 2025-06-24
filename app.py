import logging
import json
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
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

# MongoDB Setup
MONGO_URI = "mongodb+srv://zyra:Adnan%4066202@wazuhxebantisserver.oj0snuz.mongodb.net/?retryWrites=true&w=majority&appName=WazuhXEbantisServer"
client = AsyncIOMotorClient(MONGO_URI)
db = client["wazuh"]
alerts_collection = db["alerts"]

# Pydantic models for input validation
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
    status: Optional[str] = None  # not used

# Endpoint: Receive Wazuh alerts
@app.post("/wazuh-alerts", summary="Receive alerts from Wazuh")
async def receive_alert(alert: Dict[Any, Any]):
    try:
        timestamp_str = alert.get("timestamp")
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})

        try:
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+0000")
        except (ValueError, TypeError) as e:
            logger.error(f"Invalid timestamp: {timestamp_str}, error: {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid timestamp format")

        db_alert = {
            "timestamp": timestamp,
            "rule_id": rule.get("id", ""),
            "rule_description": rule.get("description", ""),
            "rule_level": rule.get("level", 0),
            "agent_id": agent.get("id", ""),
            "agent_name": agent.get("name", ""),
            "event": alert  # store full JSON
        }

        await alerts_collection.insert_one(db_alert)
        logger.info(f"Stored alert: rule_id={rule.get('id')}, timestamp={timestamp_str}")
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error processing alert: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to store alert")

# Endpoint: Fetch stored alerts
@app.get("/alerts", summary="Fetch stored Wazuh alerts")
async def get_alerts(
    limit: int = Query(10, ge=1),
    offset: int = Query(0, ge=0),
    rule_level: Optional[int] = None,
    agent_id: Optional[str] = None
):
    try:
        query = {}
        if rule_level is not None:
            query["rule_level"] = {"$gte": rule_level}
        if agent_id:
            query["agent_id"] = agent_id

        total = await alerts_collection.count_documents(query)
        cursor = alerts_collection.find(query).skip(offset).limit(limit).sort("timestamp", -1)
        results = []
        async for doc in cursor:
            results.append({
                "timestamp": doc["timestamp"].isoformat(),
                "rule": {
                    "id": doc.get("rule_id"),
                    "description": doc.get("rule_description"),
                    "level": doc.get("rule_level")
                },
                "agent": {
                    "id": doc.get("agent_id"),
                    "name": doc.get("agent_name")
                },
                "event": doc.get("event")
            })

        return {"alerts": results, "total": total}
    except Exception as e:
        logger.error(f"Error fetching alerts: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch alerts")

# Endpoint: Alerts summary by rule level
@app.get("/alerts/summary", summary="Fetch alerts summary")
async def get_alerts_summary(timeframe: Optional[str] = None):
    try:
        match_stage = {}
        if timeframe:
            hours = int(timeframe.replace("h", ""))
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            match_stage = {"timestamp": {"$gte": time_threshold}}

        pipeline = [
            {"$match": match_stage},
            {"$group": {
                "_id": "$rule_level",
                "count": {"$sum": 1}
            }}
        ]

        summary = await alerts_collection.aggregate(pipeline).to_list(length=None)
        return {
            "summary": [{"rule_level": doc["_id"], "count": doc["count"]} for doc in summary],
            "total": len(summary)
        }
    except Exception as e:
        logger.error(f"Error fetching summary: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch summary")

# Endpoint: Fetch agents list
@app.get("/agents", summary="Fetch agent information from alerts")
async def get_agents(limit: int = 10, offset: int = 0):
    try:
        pipeline = [
            {"$group": {
                "_id": {"agent_id": "$agent_id", "agent_name": "$agent_name"}
            }},
            {"$skip": offset},
            {"$limit": limit}
        ]

        agents = await alerts_collection.aggregate(pipeline).to_list(length=None)
        return {
            "agents": [{"id": a["_id"]["agent_id"], "name": a["_id"]["agent_name"]} for a in agents],
            "total": len(agents)
        }
    except Exception as e:
        logger.error(f"Error fetching agents: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch agents")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
