import logging
import json
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import motor.motor_asyncio
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# MongoDB connection
MONGO_URI = "mongodb+srv://zyra:Adnan%4066202@wazuhxebantisserver.oj0snuz.mongodb.net/?retryWrites=true&w=majority&appName=WazuhXEbantisServer"
mongo_client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI, tls=True, tlsAllowInvalidCertificates=True)
db = mongo_client["wazuh"]
alerts_collection = db["alerts"]

# FastAPI app
app = FastAPI(
    title="Wazuh Alerts API",
    description="Receive and query Wazuh alerts",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*", "http://localhost:3000", "https://your-frontend.com", "https://98.70.144.86:55000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# POST: Receive Wazuh alert
@app.post("/wazuh-alerts")
async def receive_alert(alert: Dict[Any, Any]):
    try:
        timestamp_str = alert.get("timestamp")
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})
        rule_level = rule.get("level", 0)

        # Skip storing alerts with level < 4
        if rule_level < 4:
            logger.info(f"Ignored alert with level {rule_level}")
            return {"status": "ignored", "reason": "low-level alert"}

        try:
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f+0000")
        except Exception:
            logger.error(f"Invalid timestamp: {timestamp_str}")
            raise HTTPException(status_code=400, detail="Invalid timestamp format")

        alert_doc = {
            "timestamp": timestamp,
            "rule": {
                "id": rule.get("id", ""),
                "description": rule.get("description", ""),
                "level": rule_level
            },
            "agent": {
                "id": agent.get("id", ""),
                "name": agent.get("name", "")
            },
            "event": alert
        }

        await alerts_collection.insert_one(alert_doc)
        logger.info(f"Stored alert: Rule ID {rule.get('id')} with level {rule_level}")
        return {"status": "success"}

    except Exception as e:
        logger.error(f"Error processing alert: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# GET: Fetch alerts
@app.get("/alerts")
async def get_alerts(limit: int = 10, offset: int = 0, rule_level: Optional[int] = None, agent_id: Optional[str] = None):
    try:
        query = {}
        if rule_level is not None:
            query["rule.level"] = {"$gte": rule_level}
        if agent_id:
            query["agent.id"] = agent_id

        total = await alerts_collection.count_documents(query)
        cursor = alerts_collection.find(query).sort("timestamp", -1).skip(offset).limit(limit)
        alerts = []
        async for doc in cursor:
            alerts.append({
                "timestamp": doc["timestamp"].isoformat(),
                "rule": doc["rule"],
                "agent": doc["agent"],
                "event": doc["event"]
            })

        return {"alerts": alerts, "total": total}

    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# GET: Alerts summary
@app.get("/alerts/summary")
async def get_alerts_summary(timeframe: Optional[str] = Query(None)):
    try:
        query = {}
        if timeframe:
            hours = int(timeframe.replace("h", ""))
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            query["timestamp"] = {"$gte": time_threshold}

        pipeline = [
            {"$match": query},
            {"$group": {"_id": "$rule.level", "count": {"$sum": 1}}}
        ]
        summary = await alerts_collection.aggregate(pipeline).to_list(length=None)

        return {
            "summary": [{"rule_level": doc["_id"], "count": doc["count"]} for doc in summary],
            "total": len(summary)
        }

    except Exception as e:
        logger.error(f"Error fetching summary: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# GET: Agent info
@app.get("/agents")
async def get_agents(limit: int = 10, offset: int = 0):
    try:
        pipeline = [
            {
                "$group": {
                    "_id": {"id": "$agent.id", "name": "$agent.name"}
                }
            },
            {"$skip": offset},
            {"$limit": limit}
        ]
        agents = await alerts_collection.aggregate(pipeline).to_list(length=None)
        return {
            "agents": [{"id": agent["_id"]["id"], "name": agent["_id"]["name"]} for agent in agents],
            "total": len(agents)
        }

    except Exception as e:
        logger.error(f"Error fetching agents: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000)
