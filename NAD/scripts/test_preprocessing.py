"""
Test script pentru preprocessing pipeline
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'detector'))

from src.services.data_processor import DataProcessor
from src.services.feature_extractor import NetworkFeatureExtractor
from loguru import logger
import pandas as pd
import numpy as np

def test_data_preprocessing():
    """Test complete preprocessing pipeline"""
    logger.info("=== Testing Data Preprocessing Pipeline ===")
    
    # Initialize processor
    processor = DataProcessor()
    
    # Test synthetic dataset creation
    logger.info("1. Testing synthetic dataset creation...")
    df = processor.load_cicids2017_dataset("nonexistent_file.csv")
    
    if df is not None:
        logger.info(f"✅ Dataset created: {df.shape}")
        logger.info(f"✅ Columns: {list(df.columns)}")
        logger.info(f"✅ Label distribution:\n{df['Label'].value_counts()}")
    else:
        logger.error("❌ Failed to create dataset")
        return False
    
    # Test preprocessing
    logger.info("2. Testing data preprocessing...")
    try:
        X, y = processor.preprocess_data(df)
        logger.info(f"✅ Preprocessing successful: X shape {X.shape}, y shape {y.shape}")
        logger.info(f"✅ Feature columns: {len(processor.feature_columns)}")
    except Exception as e:
        logger.error(f"❌ Preprocessing failed: {e}")
        return False
    
    # Test DataLoader creation
    logger.info("3. Testing DataLoader creation...")
    try:
        train_loader, val_loader, test_loader = processor.create_dataloaders(X, y)
        logger.info(f"✅ DataLoaders created successfully")
        logger.info(f"✅ Train batches: {len(train_loader)}")
        logger.info(f"✅ Val batches: {len(val_loader)}")
        logger.info(f"✅ Test batches: {len(test_loader)}")
    except Exception as e:
        logger.error(f"❌ DataLoader creation failed: {e}")
        return False
    
    # Test feature importance analysis
    logger.info("4. Testing feature importance analysis...")
    try:
        feature_importance = processor.get_feature_importance_analysis(X, y)
        logger.info(f"✅ Feature importance analysis completed")
    except Exception as e:
        logger.error(f"❌ Feature importance analysis failed: {e}")
        return False
    
    logger.info("✅ All preprocessing tests passed!")
    return True

def test_feature_extraction():
    """Test network feature extraction"""
    logger.info("=== Testing Network Feature Extraction ===")
    
    try:
        from scapy.all import IP, TCP, UDP, Ether
        
        # Initialize extractor
        extractor = NetworkFeatureExtractor()
        logger.info(f"✅ Feature extractor initialized with {len(extractor.feature_names)} features")
        
        # Create test packets
        logger.info("1. Testing packet feature extraction...")
        
        # TCP packet
        tcp_packet = Ether()/IP(src="192.168.1.10", dst="192.168.1.1")/TCP(sport=12345, dport=80, flags="S")
        tcp_features = extractor.extract_packet_features(tcp_packet)
        logger.info(f"✅ TCP packet features extracted: {len(tcp_features)} features")
        
        # UDP packet
        udp_packet = Ether()/IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=53, dport=53)
        udp_features = extractor.extract_packet_features(udp_packet)
        logger.info(f"✅ UDP packet features extracted: {len(udp_features)} features")
        
        # Test flow creation
        logger.info("2. Testing flow feature calculation...")
        
        # Simulate a flow with multiple packets
        packets = [
            Ether()/IP(src="192.168.1.10", dst="192.168.1.1")/TCP(sport=12345, dport=80, flags="S"),
            Ether()/IP(src="192.168.1.1", dst="192.168.1.10")/TCP(sport=80, dport=12345, flags="SA"),
            Ether()/IP(src="192.168.1.10", dst="192.168.1.1")/TCP(sport=12345, dport=80, flags="A"),
            Ether()/IP(src="192.168.1.10", dst="192.168.1.1")/TCP(sport=12345, dport=80, flags="PA"),
        ]
        
        flow_features = None
        for packet in packets:
            flow_features = extractor.process_packet(packet)
        
        if flow_features:
            logger.info(f"✅ Flow features calculated: {len(flow_features)} features")
            logger.info(f"✅ Sample features: flow_duration={flow_features.get('flow_duration', 0):.2f}")
        else:
            logger.error("❌ Flow feature calculation failed")
            return False
        
        logger.info("✅ All feature extraction tests passed!")
        return True
        
    except ImportError:
        logger.warning("⚠️ Scapy not available in this environment, skipping packet tests")
        return True
    except Exception as e:
        logger.error(f"❌ Feature extraction test failed: {e}")
        return False

if __name__ == "__main__":
    logger.info("Starting Faza 2 tests...")
    
    # Test data preprocessing
    if not test_data_preprocessing():
        logger.error("Data preprocessing tests failed!")
        sys.exit(1)
    
    # Test feature extraction
    if not test_feature_extraction():
        logger.error("Feature extraction tests failed!")
        sys.exit(1)
    
    logger.info("🎉 All Faza 2 tests passed successfully!")