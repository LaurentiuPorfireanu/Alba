import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
import torch
from torch.utils.data import Dataset, DataLoader
import os
from loguru import logger
from typing import Tuple, Optional, Dict, Any
import joblib

class NetworkDataset(Dataset):
    def __init__(self, data, labels=None):
        self.data = torch.FloatTensor(data)
        self.labels = torch.FloatTensor(labels) if labels is not None else None
        
    def __len__(self):
        return len(self.data)
    
    def __getitem__(self, idx):
        if self.labels is not None:
            return self.data[idx], self.labels[idx]
        return self.data[idx]

class DataProcessor:
    def __init__(self, config=None):
        self.scaler = StandardScaler()
        self.min_max_scaler = MinMaxScaler()
        self.label_encoder = LabelEncoder()
        self.imputer = SimpleImputer(strategy='mean')
        self.feature_columns = []
        self.is_fitted = False
        self.config = config or {}
        
        # Features importante pentru detectia anomaliilor
        self.critical_features = [
            'flow_duration', 'flow_bytes_s', 'flow_packets_s',
            'total_fwd_packets', 'total_bwd_packets',
            'fwd_iat_mean', 'bwd_iat_mean', 'flow_iat_std',
            'fwd_psh_flags', 'bwd_psh_flags', 'protocol'
        ]
        
    def load_cicids2017_dataset(self, file_path: str) -> Optional[pd.DataFrame]:
        """Incarca dataset CICIDS2017 cu features de retea"""
        try:
            logger.info(f"Loading CICIDS2017 dataset from {file_path}")
            
            if not os.path.exists(file_path):
                logger.warning(f"Dataset file not found: {file_path}")
                return self._create_synthetic_network_dataset()
            
            # Citire cu handling pentru fisiere mari
            df = pd.read_csv(file_path, low_memory=False)
            logger.info(f"Dataset loaded successfully: {df.shape}")
            
            # Cleanup pentru date de retea
            df = self._clean_network_data(df)
            return df
            
        except Exception as e:
            logger.error(f"Error loading dataset: {e}")
            return self._create_synthetic_network_dataset()
    
    def _create_synthetic_network_dataset(self) -> pd.DataFrame:
        """Creaza dataset sintetic cu caracteristici de retea reale"""
        logger.info("Creating synthetic network traffic dataset")
        
        n_samples = 50000
        
        # Distribuții realiste pentru trafic de retea
        np.random.seed(42)
        
        # Normal traffic patterns
        normal_samples = int(n_samples * 0.85)
        
        # Flow duration: majoritatea scurte, cateva lungi
        flow_duration = np.concatenate([
            np.random.exponential(50000, normal_samples//2),  # Short flows
            np.random.exponential(500000, normal_samples//2)  # Longer flows
        ])
        
        # Packet counts: realistic distributions
        fwd_packets = np.random.poisson(10, normal_samples)
        bwd_packets = np.random.poisson(8, normal_samples)
        
        # Bytes: dependent on packet count
        fwd_bytes = fwd_packets * np.random.normal(800, 200, normal_samples)
        bwd_bytes = bwd_packets * np.random.normal(600, 150, normal_samples)
        
        # Inter-arrival times
        fwd_iat_mean = np.random.exponential(10000, normal_samples)
        bwd_iat_mean = np.random.exponential(12000, normal_samples)
        
        # Protocol distribution (TCP=6, UDP=17, ICMP=1)
        protocols = np.random.choice([6, 17, 1], normal_samples, p=[0.7, 0.25, 0.05])
        
        # TCP flags pentru normal traffic
        fwd_psh_flags = np.random.poisson(2, normal_samples)
        bwd_psh_flags = np.random.poisson(1, normal_samples)
        
        # Port numbers
        src_ports = np.random.choice(range(1024, 65536), normal_samples)
        dst_ports = np.random.choice([80, 443, 22, 21, 25, 53], normal_samples, 
                                   p=[0.4, 0.3, 0.1, 0.05, 0.05, 0.1])
        
        # Create normal traffic DataFrame
        normal_data = pd.DataFrame({
            'flow_duration': flow_duration,
            'total_fwd_packets': fwd_packets,
            'total_bwd_packets': bwd_packets,
            'total_length_fwd_packets': fwd_bytes,
            'total_length_bwd_packets': bwd_bytes,
            'fwd_iat_mean': fwd_iat_mean,
            'bwd_iat_mean': bwd_iat_mean,
            'flow_iat_std': np.random.exponential(5000, normal_samples),
            'protocol': protocols,
            'fwd_psh_flags': fwd_psh_flags,
            'bwd_psh_flags': bwd_psh_flags,
            'src_port': src_ports,
            'dst_port': dst_ports,
            'flow_bytes_s': (fwd_bytes + bwd_bytes) / (flow_duration / 1000000),
            'flow_packets_s': (fwd_packets + bwd_packets) / (flow_duration / 1000000),
            'Label': 'BENIGN'
        })
        
        # Create attack traffic
        attack_samples = n_samples - normal_samples
        attack_types = ['DDoS', 'PortScan', 'Infiltration', 'Bot']
        
        attack_data_list = []
        
        for attack_type in attack_types:
            n_attack = attack_samples // len(attack_types)
            
            if attack_type == 'DDoS':
                # DDoS: high packet rate, short duration
                attack_df = pd.DataFrame({
                    'flow_duration': np.random.exponential(1000, n_attack),
                    'total_fwd_packets': np.random.poisson(100, n_attack),
                    'total_bwd_packets': np.random.poisson(5, n_attack),
                    'total_length_fwd_packets': np.random.normal(500, 100, n_attack),
                    'total_length_bwd_packets': np.random.normal(100, 50, n_attack),
                    'fwd_iat_mean': np.random.exponential(100, n_attack),
                    'bwd_iat_mean': np.random.exponential(1000, n_attack),
                    'flow_iat_std': np.random.exponential(50, n_attack),
                    'protocol': np.random.choice([6, 17], n_attack, p=[0.8, 0.2]),
                    'fwd_psh_flags': np.random.poisson(10, n_attack),
                    'bwd_psh_flags': np.random.poisson(0, n_attack),
                    'src_port': np.random.choice(range(1024, 65536), n_attack),
                    'dst_port': np.random.choice([80, 443], n_attack),
                    'Label': attack_type
                })
                
            elif attack_type == 'PortScan':
                # Port scan: many different ports, small packets
                attack_df = pd.DataFrame({
                    'flow_duration': np.random.exponential(100, n_attack),
                    'total_fwd_packets': np.random.poisson(2, n_attack),
                    'total_bwd_packets': np.random.poisson(1, n_attack),
                    'total_length_fwd_packets': np.random.normal(60, 10, n_attack),
                    'total_length_bwd_packets': np.random.normal(40, 10, n_attack),
                    'fwd_iat_mean': np.random.exponential(50, n_attack),
                    'bwd_iat_mean': np.random.exponential(100, n_attack),
                    'flow_iat_std': np.random.exponential(25, n_attack),
                    'protocol': np.full(n_attack, 6),  # TCP
                    'fwd_psh_flags': np.zeros(n_attack),
                    'bwd_psh_flags': np.zeros(n_attack),
                    'src_port': np.random.choice(range(1024, 65536), n_attack),
                    'dst_port': np.random.choice(range(1, 1024), n_attack),
                    'Label': attack_type
                })
            else:
                # Other attacks: varied patterns
                attack_df = pd.DataFrame({
                    'flow_duration': np.random.exponential(25000, n_attack),
                    'total_fwd_packets': np.random.poisson(20, n_attack),
                    'total_bwd_packets': np.random.poisson(15, n_attack),
                    'total_length_fwd_packets': np.random.normal(1200, 300, n_attack),
                    'total_length_bwd_packets': np.random.normal(800, 200, n_attack),
                    'fwd_iat_mean': np.random.exponential(5000, n_attack),
                    'bwd_iat_mean': np.random.exponential(6000, n_attack),
                    'flow_iat_std': np.random.exponential(3000, n_attack),
                    'protocol': np.random.choice([6, 17], n_attack, p=[0.9, 0.1]),
                    'fwd_psh_flags': np.random.poisson(5, n_attack),
                    'bwd_psh_flags': np.random.poisson(3, n_attack),
                    'src_port': np.random.choice(range(1024, 65536), n_attack),
                    'dst_port': np.random.choice([80, 443, 22], n_attack),
                    'Label': attack_type
                })
            
            # Calculate derived features for attack data
            attack_df['flow_bytes_s'] = (attack_df['total_length_fwd_packets'] + 
                                       attack_df['total_length_bwd_packets']) / (attack_df['flow_duration'] / 1000000)
            attack_df['flow_packets_s'] = (attack_df['total_fwd_packets'] + 
                                         attack_df['total_bwd_packets']) / (attack_df['flow_duration'] / 1000000)
            
            attack_data_list.append(attack_df)
        
        # Combine all data
        all_attack_data = pd.concat(attack_data_list, ignore_index=True)
        df = pd.concat([normal_data, all_attack_data], ignore_index=True)
        
        # Add more features to match CICIDS2017 structure
        df = self._add_additional_features(df)
        
        # Shuffle the data
        df = df.sample(frac=1).reset_index(drop=True)
        
        logger.info(f"Synthetic dataset created: {df.shape}")
        logger.info(f"Label distribution:\n{df['Label'].value_counts()}")
        
        return df
    
    def _add_additional_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add additional network features to match CICIDS2017 structure"""
        
        # Packet length statistics
        df['fwd_packet_length_max'] = df['total_length_fwd_packets'] / np.maximum(df['total_fwd_packets'], 1)
        df['fwd_packet_length_min'] = df['fwd_packet_length_max'] * 0.8
        df['fwd_packet_length_mean'] = (df['fwd_packet_length_max'] + df['fwd_packet_length_min']) / 2
        
        df['bwd_packet_length_max'] = df['total_length_bwd_packets'] / np.maximum(df['total_bwd_packets'], 1)
        df['bwd_packet_length_min'] = df['bwd_packet_length_max'] * 0.8
        df['bwd_packet_length_mean'] = (df['bwd_packet_length_max'] + df['bwd_packet_length_min']) / 2
        
        # More timing features
        df['fwd_iat_total'] = df['fwd_iat_mean'] * df['total_fwd_packets']
        df['fwd_iat_std'] = df['fwd_iat_mean'] * 0.3
        df['fwd_iat_max'] = df['fwd_iat_mean'] * 2
        df['fwd_iat_min'] = df['fwd_iat_mean'] * 0.1
        
        df['bwd_iat_total'] = df['bwd_iat_mean'] * df['total_bwd_packets']
        df['bwd_iat_std'] = df['bwd_iat_mean'] * 0.3
        df['bwd_iat_max'] = df['bwd_iat_mean'] * 2
        df['bwd_iat_min'] = df['bwd_iat_mean'] * 0.1
        
        df['flow_iat_max'] = np.maximum(df['fwd_iat_max'], df['bwd_iat_max'])
        df['flow_iat_min'] = np.minimum(df['fwd_iat_min'], df['bwd_iat_min'])
        df['flow_iat_mean'] = (df['fwd_iat_mean'] + df['bwd_iat_mean']) / 2
        
        # Packet statistics
        total_length = df['total_length_fwd_packets'] + df['total_length_bwd_packets']
        total_packets = df['total_fwd_packets'] + df['total_bwd_packets']
        
        df['min_packet_length'] = np.minimum(df['fwd_packet_length_min'], df['bwd_packet_length_min'])
        df['max_packet_length'] = np.maximum(df['fwd_packet_length_max'], df['bwd_packet_length_max'])
        df['packet_length_mean'] = total_length / np.maximum(total_packets, 1)
        df['packet_length_std'] = df['packet_length_mean'] * 0.2
        df['packet_length_variance'] = df['packet_length_std'] ** 2
        
        # Additional features
        df['fwd_urg_flags'] = np.random.poisson(0.1, len(df))
        df['bwd_urg_flags'] = np.random.poisson(0.1, len(df))
        df['fwd_header_length'] = np.where(df['protocol'] == 6, 20, 8)  # TCP=20, UDP=8
        df['bwd_header_length'] = df['fwd_header_length']
        
        df['down_up_ratio'] = np.where(df['total_length_bwd_packets'] > 0,
                                      df['total_length_fwd_packets'] / df['total_length_bwd_packets'],
                                      0)
        
        df['average_packet_size'] = total_length / np.maximum(total_packets, 1)
        df['fwd_segment_size_avg'] = df['total_length_fwd_packets'] / np.maximum(df['total_fwd_packets'], 1)
        df['bwd_segment_size_avg'] = df['total_length_bwd_packets'] / np.maximum(df['total_bwd_packets'], 1)
        
        df['subflow_fwd_packets'] = df['total_fwd_packets']
        df['subflow_bwd_packets'] = df['total_bwd_packets']
        
        # TCP specific features
        df['init_win_bytes_forward'] = np.random.normal(8192, 1000, len(df))
        df['init_win_bytes_backward'] = np.random.normal(8192, 1000, len(df))
        df['act_data_pkt_fwd'] = df['total_fwd_packets'] * 0.8
        df['min_seg_size_forward'] = df['fwd_packet_length_min']
        
        return df
    
    def _clean_network_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean network data specific issues"""
        logger.info("Cleaning network data")
        
        # Remove rows with missing critical network features
        critical_cols = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets']
        available_critical = [col for col in critical_cols if col in df.columns]
        
        if available_critical:
            df = df.dropna(subset=available_critical)
        
        # Handle infinite values common in network data
        df = df.replace([np.inf, -np.inf], np.nan)
        
        # Remove duplicate flows
        if 'Flow ID' in df.columns:
            df = df.drop_duplicates(subset=['Flow ID'])
        
        # Standardize column names
        df.columns = df.columns.str.strip().str.replace(' ', '_').str.lower()
        
        # Handle Label column variations
        label_cols = ['label', 'Label', ' Label']
        for col in label_cols:
            if col in df.columns:
                df['Label'] = df[col]
                break
        
        logger.info(f"Data cleaned: {df.shape}")
        return df
    
    def preprocess_data(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Comprehensive preprocessing for network data"""
        logger.info("Starting network data preprocessing")
        
        # Separate features and labels
        if 'Label' in df.columns:
            labels = df['Label'].copy()
            features_df = df.drop(['Label'], axis=1)
        else:
            labels = None
            features_df = df.copy()
        
        # Remove non-numeric columns that aren't useful for ML
        non_numeric_cols = ['flow_id', 'src_ip', 'dst_ip', 'timestamp']
        features_df = features_df.select_dtypes(include=[np.number])
        
        # Handle missing values
        logger.info("Handling missing values")
        features_df = pd.DataFrame(self.imputer.fit_transform(features_df), 
                                  columns=features_df.columns)
        
        # Remove features with zero variance
        zero_var_cols = features_df.columns[features_df.var() == 0]
        if len(zero_var_cols) > 0:
            logger.info(f"Removing {len(zero_var_cols)} zero-variance features")
            features_df = features_df.drop(columns=zero_var_cols)
        
        # Store feature names
        self.feature_columns = list(features_df.columns)
        logger.info(f"Final feature set: {len(self.feature_columns)} features")
        
        # Convert to numpy arrays
        X = features_df.values.astype(np.float32)
        
        # Process labels for anomaly detection
        if labels is not None:
            # Binary classification: BENIGN = 0, everything else = 1
            y = (labels != 'BENIGN').astype(int).values
            logger.info(f"Label distribution - Normal: {sum(y==0)}, Anomaly: {sum(y==1)}")
        else:
            y = None
        
        # Normalize features
        logger.info("Normalizing features")
        X_scaled = self.scaler.fit_transform(X)
        
        # Additional scaling for critical features
        X_scaled = self._scale_critical_features(X_scaled, features_df.columns)
        
        self.is_fitted = True
        logger.info(f"Preprocessing completed: {X_scaled.shape}")
        
        return X_scaled, y
    
    def _scale_critical_features(self, X: np.ndarray, feature_names: list) -> np.ndarray:
        """Additional scaling for network-specific critical features"""
        
        # Features that need special handling due to network characteristics
        timing_features = [name for name in feature_names if 'iat' in name or 'duration' in name]
        byte_features = [name for name in feature_names if 'bytes' in name or 'length' in name]
        rate_features = [name for name in feature_names if '_s' in name]  # per second features
        
        # Apply log transformation to highly skewed network features
        for i, feature_name in enumerate(feature_names):
            if feature_name in timing_features + byte_features + rate_features:
                # Log transformation for skewed features (add 1 to handle zeros)
                X[:, i] = np.log1p(np.abs(X[:, i]))
        
        return X
    
    def create_dataloaders(self, X: np.ndarray, y: Optional[np.ndarray] = None, 
                          batch_size: int = 32, test_size: float = 0.2, 
                          validation_size: float = 0.1) -> Tuple[DataLoader, DataLoader, DataLoader]:
        """Create DataLoaders with train/validation/test splits optimized for network data"""
        
        if y is not None:
            # Stratified split to maintain class distribution
            X_temp, X_test, y_temp, y_test = train_test_split(
                X, y, test_size=test_size, random_state=42, stratify=y
            )
            
            X_train, X_val, y_train, y_val = train_test_split(
                X_temp, y_temp, test_size=validation_size/(1-test_size), 
                random_state=42, stratify=y_temp
            )
        else:
            # No labels - just split data
            X_temp, X_test = train_test_split(X, test_size=test_size, random_state=42)
            X_train, X_val = train_test_split(X_temp, test_size=validation_size/(1-test_size), random_state=42)
            y_train = y_val = y_test = None
        
        # Create datasets
        train_dataset = NetworkDataset(X_train, y_train)
        val_dataset = NetworkDataset(X_val, y_val)
        test_dataset = NetworkDataset(X_test, y_test)
        
        # Create data loaders with network-optimized settings
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, 
                                 num_workers=0, pin_memory=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False, 
                               num_workers=0, pin_memory=True)
        test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False, 
                                num_workers=0, pin_memory=True)
        
        logger.info(f"DataLoaders created - Train: {len(train_dataset)}, "
                   f"Val: {len(val_dataset)}, Test: {len(test_dataset)}")
        
        return train_loader, val_loader, test_loader
    
    def prepare_realtime_data(self, network_features: Dict[str, float]) -> np.ndarray:
        """Prepare real-time network data for prediction"""
        if not self.is_fitted:
            raise ValueError("DataProcessor must be fitted before processing real-time data")
        
        # Convert to DataFrame with expected features
        df = pd.DataFrame([network_features])
        
        # Ensure all expected features are present
        for feature in self.feature_columns:
            if feature not in df.columns:
                df[feature] = 0.0
        
        # Select only the features used in training
        df = df[self.feature_columns]
        
        # Apply same preprocessing steps
        X = df.values.astype(np.float32)
        X_scaled = self.scaler.transform(X)
        
        return X_scaled
    
    def save_preprocessor(self, filepath: str):
        """Save preprocessing objects"""
        preprocessor_data = {
            'scaler': self.scaler,
            'min_max_scaler': self.min_max_scaler,
            'imputer': self.imputer,
            'feature_columns': self.feature_columns,
            'is_fitted': self.is_fitted
        }
        
        joblib.dump(preprocessor_data, filepath)
        logger.info(f"Preprocessor saved to {filepath}")
    
    def load_preprocessor(self, filepath: str):
        """Load preprocessing objects"""
        preprocessor_data = joblib.load(filepath)
        
        self.scaler = preprocessor_data['scaler']
        self.min_max_scaler = preprocessor_data['min_max_scaler']
        self.imputer = preprocessor_data['imputer']
        self.feature_columns = preprocessor_data['feature_columns']
        self.is_fitted = preprocessor_data['is_fitted']
        
        logger.info(f"Preprocessor loaded from {filepath}")
    
    def get_feature_importance_analysis(self, X: np.ndarray, y: np.ndarray) -> Dict[str, float]:
        """Analyze feature importance for network anomaly detection"""
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.feature_selection import mutual_info_classif
        
        # Random Forest feature importance
        rf = RandomForestClassifier(n_estimators=100, random_state=42)
        rf.fit(X, y)
        
        # Mutual information
        mi_scores = mutual_info_classif(X, y, random_state=42)
        
        # Combine both metrics
        feature_importance = {}
        for i, feature_name in enumerate(self.feature_columns):
            feature_importance[feature_name] = {
                'rf_importance': rf.feature_importances_[i],
                'mutual_info': mi_scores[i]
            }
        
        # Sort by combined score
        for feature in feature_importance:
            combined_score = (feature_importance[feature]['rf_importance'] + 
                            feature_importance[feature]['mutual_info']) / 2
            feature_importance[feature]['combined_score'] = combined_score
        
        sorted_features = sorted(feature_importance.items(), 
                               key=lambda x: x[1]['combined_score'], reverse=True)
        
        logger.info("Top 10 most important features for anomaly detection:")
        for feature, scores in sorted_features[:10]:
            logger.info(f"{feature}: {scores['combined_score']:.4f}")
        
        return feature_importance