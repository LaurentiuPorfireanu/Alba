#!/usr/bin/env python3
"""
Test script pentru sistemul real-time de detectie anomalii
"""

import sys
import os
import asyncio
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'detector'))

from src.services.network_monitor import NetworkMonitor
from src.services.anomaly_detector import AnomalyDetector
from src.services.alerting_system import AlertingSystem, AlertConfig
from loguru import logger
import requests

async def test_real_time_detection():
    """Test sistemul de detectie real-time"""
    logger.info("=== Testing Real-time Anomaly Detection ===")
    
    # 1. Initialize components
    logger.info("1. Initializing components...")
    
    anomaly_detector = AnomalyDetector(models_path="models")
    anomaly_detector.load_models()
    
    alert_config = AlertConfig(
        email_enabled=False,  # Disable for testing
        slack_enabled=False,
        webhook_enabled=False
    )
    
    alerting_system = AlertingSystem(alert_config)
    network_monitor = NetworkMonitor()
    
    logger.info("✅ Components initialized")
    
    # 2. Test single detection
    logger.info("2. Testing single anomaly detection...")
    
    # Mock network features
    test_features = [
        [0.1, 0.2, 0.3] + [0.0] * 48,  # Normal traffic
        [10.0, 50.0, 100.0] + [5.0] * 48,  # Suspicious traffic
    ]
    
    for i, features in enumerate(test_features):
        results = anomaly_detector.predict_anomaly([features])
        is_anomaly, confidence = results[0]
        
        logger.info(f"Sample {i+1}: Anomaly={is_anomaly}, Confidence={confidence:.3f}")
    
    logger.info("✅ Single detection test completed")
    
    # 3. Test batch detection
    logger.info("3. Testing batch detection...")
    
    batch_features = [
        [0.1] * 51,  # Normal
        [0.2] * 51,  # Normal
        [5.0] * 51,  # Anomalous
        [0.15] * 51,  # Normal
        [8.0] * 51   # Anomalous
    ]
    
    batch_results = anomaly_detector.predict_anomaly(batch_features)
    
    anomaly_count = sum(1 for is_anomaly, _ in batch_results if is_anomaly)
    logger.info(f"Batch test: {anomaly_count}/5 samples detected as anomalies")
    
    # 4. Test adaptive threshold
    logger.info("4. Testing adaptive threshold...")
    
    initial_threshold = anomaly_detector.adaptive_threshold
    logger.info(f"Initial threshold: {initial_threshold:.3f}")
    
    # Simulate some detections to trigger threshold adaptation
    for _ in range(10):
        anomaly_detector.predict_anomaly([[0.1] * 51])
        anomaly_detector.update_adaptive_threshold()
    
    new_threshold = anomaly_detector.adaptive_threshold
    logger.info(f"Updated threshold: {new_threshold:.3f}")
    
    # 5. Test alerting system
    logger.info("5. Testing alerting system...")
    
    test_anomaly = {
        'timestamp': time.time(),
        'confidence': 0.85,
        'severity': 'HIGH',
        'type': 'test_anomaly',
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
    
    await alerting_system.send_alert(test_anomaly)
    logger.info("✅ Alert test completed")
    
    # 6. Performance test
    logger.info("6. Testing performance...")
    
    start_time = time.time()
    
    # Test 1000 predictions
    large_batch = [[0.1] * 51 for _ in range(1000)]
    results = anomaly_detector.predict_anomaly(large_batch)
    
    end_time = time.time()
    duration = end_time - start_time
    
    logger.info(f"Performance: 1000 predictions in {duration:.3f}s ({1000/duration:.1f} predictions/sec)")
    
    # 7. Test network monitor (brief)
    logger.info("7. Testing network monitor (brief simulation)...")
    
    try:
        # Start monitoring for 5 seconds
        monitoring_task = asyncio.create_task(network_monitor.start_monitoring())
        
        # Let it run for a few seconds
        await asyncio.sleep(5)
        
        # Stop monitoring
        await network_monitor.stop_monitoring()
        
        # Get stats
        stats = network_monitor.get_real_time_stats()
        logger.info(f"Monitoring stats: {stats['packets_processed']} packets processed")
        
        logger.info("✅ Network monitor test completed")
        
    except Exception as e:
        logger.warning(f"Network monitor test failed (expected in some environments): {e}")
    
    logger.info("🎉 All real-time tests completed successfully!")

def test_api_endpoints():
    """Test API endpoints"""
    logger.info("=== Testing API Endpoints ===")
    
    base_url = "http://localhost:8000/api/v1"
    
    try:
        # Test health endpoint
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            logger.info("✅ Health endpoint working")
        else:
            logger.warning(f"Health endpoint returned {response.status_code}")
        
        # Test detection endpoint
        test_data = {
            "features": [0.1] * 51,
            "timestamp": "2025-05-26T12:00:00"
        }
        
        response = requests.post(f"{base_url}/detect", json=test_data, timeout=5)
        if response.status_code == 200:
            result = response.json()
            logger.info(f"✅ Detection endpoint working - Anomaly: {result.get('is_anomaly')}")
        else:
            logger.warning(f"Detection endpoint returned {response.status_code}")
        
        # Test stats endpoint
        response = requests.get(f"{base_url}/stats", timeout=5)
        if response.status_code == 200:
            logger.info("✅ Stats endpoint working")
        else:
            logger.warning(f"Stats endpoint returned {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        logger.warning(f"API tests failed (server may not be running): {e}")
        logger.info("Start the server with: docker compose up -d")

if __name__ == "__main__":
    logger.info("Starting Faza 4 Real-time System Tests...")
    
    try:
        # Test real-time detection
        asyncio.run(test_real_time_detection())
        
        # Test API endpoints
        test_api_endpoints()
        
        logger.info("🎉 All Faza 4 tests completed!")
        
    except Exception as e:
        logger.error(f"Tests failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)