from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict
from typing import List, Dict, Any, Optional
import numpy as np
from datetime import datetime
import json
import asyncio
import time
from loguru import logger  

from ..services.network_monitor import NetworkMonitor
from ..services.anomaly_detector import AnomalyDetector
from ..services.alerting_system import AlertingSystem, AlertConfig



router = APIRouter()

# Global instances (initialized on startup)
network_monitor: Optional[NetworkMonitor] = None
anomaly_detector: Optional[AnomalyDetector] = None
alerting_system: Optional[AlertingSystem] = None

class NetworkPacket(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    
    features: List[float]
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None

class DetectionResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    
    is_anomaly: bool
    confidence: float
    timestamp: datetime
    model_predictions: Dict[str, Any]
    processing_time_ms: float

class MonitoringConfig(BaseModel):
    interface: Optional[str] = None
    threshold: Optional[float] = None
    enable_alerts: bool = True

class AlertConfiguration(BaseModel):
    email_enabled: bool = True
    slack_enabled: bool = False
    webhook_enabled: bool = False
    min_severity: str = "MEDIUM"
    email_recipients: Optional[List[str]] = None
    slack_webhook_url: Optional[str] = None
    webhook_urls: Optional[List[str]] = None

@router.get("/")
async def root():
    return {
        "message": "Network Anomaly Detection System", 
        "status": "running",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }

@router.get("/health")
async def health_check():
    """Comprehensive health check"""
    global network_monitor, anomaly_detector
    
    health_status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "network_monitor": network_monitor is not None and network_monitor.is_monitoring,
            "anomaly_detector": anomaly_detector is not None,
            "models_loaded": False
        }
    }
    
    if anomaly_detector:
        performance = anomaly_detector.get_model_performance()
        health_status["components"]["models_loaded"] = any(performance["models_loaded"].values())
        health_status["performance"] = performance
    
    return health_status

@router.post("/detect", response_model=DetectionResponse)
async def detect_anomaly(packet: NetworkPacket):
    """Endpoint pentru detectia anomaliilor pe un singur pachet"""
    global anomaly_detector
    
    if not anomaly_detector:
        raise HTTPException(status_code=503, detail="Anomaly detector not initialized")
    
    start_time = time.time()
    
    try:
        # Detect anomaly
        results = await anomaly_detector.predict_anomaly_async([packet.features])
        
        if not results:
            raise HTTPException(status_code=500, detail="Prediction failed")
        
        is_anomaly, confidence = results[0]
        processing_time = (time.time() - start_time) * 1000
        
        return DetectionResponse(
            is_anomaly=is_anomaly,
            confidence=confidence,
            timestamp=packet.timestamp or datetime.now(),
            model_predictions={
                "ensemble_confidence": confidence,
                "threshold": anomaly_detector.adaptive_threshold
            },
            processing_time_ms=processing_time
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detection error: {str(e)}")

@router.post("/detect/batch")
async def detect_batch_anomalies(packets: List[NetworkPacket]):
    """Detectie pe batch de pachete"""
    global anomaly_detector
    
    if not anomaly_detector:
        raise HTTPException(status_code=503, detail="Anomaly detector not initialized")
    
    if len(packets) > 1000:
        raise HTTPException(status_code=400, detail="Batch size too large (max 1000)")
    
    start_time = time.time()
    
    try:
        features_list = [packet.features for packet in packets]
        results = await anomaly_detector.predict_anomaly_async(features_list)
        
        processing_time = (time.time() - start_time) * 1000
        
        responses = []
        for i, (is_anomaly, confidence) in enumerate(results):
            responses.append({
                "index": i,
                "is_anomaly": is_anomaly,
                "confidence": confidence,
                "timestamp": packets[i].timestamp or datetime.now()
            })
        
        return {
            "results": responses,
            "total_processed": len(packets),
            "anomalies_detected": sum(1 for r in results if r[0]),
            "processing_time_ms": processing_time
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch detection error: {str(e)}")

@router.get("/monitoring/status")
async def get_monitoring_status():
    """Status monitorizare real-time"""
    global network_monitor
    
    if not network_monitor:
        return {"monitoring": False, "message": "Network monitor not initialized"}
    
    stats = network_monitor.get_real_time_stats()
    recent_anomalies = network_monitor.get_recent_anomalies(limit=10)
    
    return {
        "monitoring": network_monitor.is_monitoring,
        "stats": stats,
        "recent_anomalies": recent_anomalies
    }

@router.post("/monitoring/start")
async def start_monitoring(config: MonitoringConfig, background_tasks: BackgroundTasks):
    """Porneste monitorizarea real-time"""
    global network_monitor, anomaly_detector
    
    if not anomaly_detector:
        raise HTTPException(status_code=503, detail="Anomaly detector not initialized")
    
    if not network_monitor:
        network_monitor = NetworkMonitor(interface=config.interface)
    
    if network_monitor.is_monitoring:
        raise HTTPException(status_code=400, detail="Monitoring already running")
    
    # Update threshold if provided
    if config.threshold:
        anomaly_detector.force_threshold_update(config.threshold)
    
    # Start monitoring in background
    background_tasks.add_task(network_monitor.start_monitoring)
    
    return {
        "message": "Network monitoring started",
        "interface": network_monitor.interface,
        "threshold": anomaly_detector.adaptive_threshold
    }

@router.post("/monitoring/stop")
async def stop_monitoring():
    """Opreste monitorizarea real-time"""
    global network_monitor
    
    if not network_monitor or not network_monitor.is_monitoring:
        raise HTTPException(status_code=400, detail="Monitoring not running")
    
    await network_monitor.stop_monitoring()
    
    final_stats = network_monitor.get_real_time_stats()
    
    return {
        "message": "Network monitoring stopped",
        "final_stats": final_stats
    }

@router.get("/stats")
async def get_statistics():
    """Statistici generale sistem"""
    global network_monitor, anomaly_detector, alerting_system
    
    stats = {
        "system_status": "operational",
        "timestamp": datetime.now().isoformat()
    }
    
    # Network monitoring stats
    if network_monitor:
        stats["network_monitoring"] = network_monitor.get_real_time_stats()
    
    # Model performance stats
    if anomaly_detector:
        stats["model_performance"] = anomaly_detector.get_model_performance()
    
    # Alerting stats
    if alerting_system:
        stats["alerting"] = alerting_system.get_alert_statistics()
    
    return stats

@router.get("/anomalies/recent")
async def get_recent_anomalies(limit: int = 50):
    """Returneaza anomaliile recente"""
    global network_monitor
    
    if not network_monitor:
        return {"anomalies": [], "message": "Network monitor not initialized"}
    
    anomalies = network_monitor.get_recent_anomalies(limit=limit)
    
    return {
        "anomalies": anomalies,
        "count": len(anomalies),
        "timestamp": datetime.now().isoformat()
    }

@router.post("/threshold/update")
async def update_threshold(threshold: float):
    """Actualizeaza threshold-ul de detectie"""
    global anomaly_detector, network_monitor
    
    if not anomaly_detector:
        raise HTTPException(status_code=503, detail="Anomaly detector not initialized")
    
    try:
        anomaly_detector.force_threshold_update(threshold)
        
        # Also update network monitor if running
        if network_monitor:
            await network_monitor.force_threshold_update(threshold)
        
        return {
            "message": "Threshold updated successfully",
            "new_threshold": threshold,
            "timestamp": datetime.now().isoformat()
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/alerts/configure")
async def configure_alerts(config: AlertConfiguration):
    """Configureaza sistemul de alerting"""
    global alerting_system
    
    try:
        alert_config = AlertConfig(
            email_enabled=config.email_enabled,
            slack_enabled=config.slack_enabled,
            webhook_enabled=config.webhook_enabled,
            min_severity=config.min_severity,
            email_recipients=config.email_recipients or [],
            slack_webhook_url=config.slack_webhook_url or "",
            webhook_urls=config.webhook_urls or []
        )
        
        alerting_system = AlertingSystem(alert_config)
        
        return {
            "message": "Alert configuration updated",
            "config": {
                "email_enabled": alert_config.email_enabled,
                "slack_enabled": alert_config.slack_enabled,
                "webhook_enabled": alert_config.webhook_enabled,
                "min_severity": alert_config.min_severity
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Configuration error: {str(e)}")

@router.get("/alerts/test")
async def test_alert():
    """Trimite o alerta de test"""
    global alerting_system
    
    if not alerting_system:
        raise HTTPException(status_code=503, detail="Alerting system not configured")
    
    # Create test anomaly
    test_anomaly = {
        'timestamp': datetime.now().isoformat(),
        'confidence': 0.85,
        'severity': 'MEDIUM',
        'type': 'test_alert',
        'flow_data': {
            'packet_info': {
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'src_port': 12345,
                'dst_port': 80,
                'protocol': 6
            }
        }
    }
    
    try:
        await alerting_system.send_alert(test_anomaly)
        return {"message": "Test alert sent successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Alert test failed: {str(e)}")

@router.get("/stream/anomalies")
async def stream_anomalies():
    """Real-time stream de anomalii"""
    global network_monitor
    
    if not network_monitor:
        raise HTTPException(status_code=503, detail="Network monitor not initialized")
    
    async def generate_anomaly_stream():
        """Generator pentru streaming anomalii"""
        while True:
            recent_anomalies = network_monitor.get_recent_anomalies(limit=1)
            
            if recent_anomalies:
                anomaly_data = {
                    "timestamp": datetime.now().isoformat(),
                    "anomaly": recent_anomalies[0]
                }
                yield f"data: {json.dumps(anomaly_data)}\n\n"
            
            await asyncio.sleep(1)  # Check every second
    
    return StreamingResponse(
        generate_anomaly_stream(),
        media_type="text/plain",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"}
    )

# Initialize components on startup
async def initialize_components():
    """Initializeaza componentele la startup"""
    global anomaly_detector, alerting_system
    
    # Initialize anomaly detector
    anomaly_detector = AnomalyDetector()
    anomaly_detector.load_models()
    
    # Initialize alerting system with default config
    alerting_system = AlertingSystem()
    
    logger.info("API components initialized")

# Add startup event
@router.on_event("startup")
async def startup_event():
    await initialize_components()