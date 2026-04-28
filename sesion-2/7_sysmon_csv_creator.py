#!/usr/bin/env python3
"""
Sysmon JSONL to CSV Converter - Multi-Threaded Processing

Converted from notebook: 2_elastic_sysmon-ds_csv_creator.ipynb
Transforms Windows Sysmon events from JSONL format into structured CSV datasets for ML analysis.
Features multi-threading support for high-capacity servers with dozens of CPUs and hundreds of GB RAM.

USAGE EXAMPLES:
    # Use with input/output only (no config required)
    python3 2_sysmon_csv_creator.py --input sysmon.jsonl --output sysmon.csv

    # Process specific APT run directory with auto-detection
    python3 2_sysmon_csv_creator.py --apt-dir apt-1/apt-1-run-04

    # Use config.yaml settings (if file exists)
    python3 2_sysmon_csv_creator.py

    # Use custom config file
    python3 2_sysmon_csv_creator.py --config config_restructured.yaml

    # Skip validation for faster processing
    python3 2_sysmon_csv_creator.py --input sysmon.jsonl --output sysmon.csv --no-validate

    # High-performance server example (config.yaml):
    script_02_sysmon_csv_creator:
      max_workers: auto        # Uses all CPU cores
      chunk_size: 50000        # Large chunks for high-memory servers

MULTI-THREADING CONFIGURATION:
    max_workers: auto          # Auto-detect CPU cores, or specify number
    chunk_size: 10000          # Events per chunk (increase for more RAM)

Dependencies: pandas, beautifulsoup4, pyyaml
"""

import argparse
import json
import logging
import os
import shutil
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import multiprocessing as mp
from queue import Queue
import threading

try:
    from bs4 import BeautifulSoup
    import pandas as pd
    import yaml
except ImportError as e:
    print(f"❌ Error: Required library not installed: {e}")
    print("   Install with: pip install pandas beautifulsoup4 pyyaml")
    sys.exit(1)


class SysmonCSVCreator:
    """
    Professional Sysmon JSONL to CSV converter for cybersecurity datasets.
    
    Features:
    - Schema-based parsing for 18+ Sysmon event types
    - Robust XML handling with error recovery
    - Data type optimization for ML pipelines
    - Timestamp standardization: UtcTime → timestamp (epoch format) for ML compatibility
    - Comprehensive validation and testing support
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize with optional configuration."""
        self.config = self._load_config(config_file) if config_file and os.path.exists(config_file) else {}
        self.logger = self._setup_logging()
        
        # Multi-threading configuration (support both old and new config formats)
        sysmon_config = self.config.get('sysmon_processor', {}) or self.config.get('script_02_sysmon_csv_creator', {})
        max_workers_config = sysmon_config.get('max_workers', 'auto')
        self.max_workers = mp.cpu_count() if max_workers_config == 'auto' else int(max_workers_config)
        self.chunk_size = sysmon_config.get('chunk_size', 10000)
        self.progress_lock = Lock()
        self.stats_lock = Lock()
        
        # Shared statistics across threads
        self.shared_stats = {
            'total_processed': 0,
            'total_errors': 0,
            'eventid_counts': {},
            'missing_fields_tracker': {}
        }
        
        # Event schema mapping (from notebook)
        self.fields_per_eventid = {
            1: ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'CommandLine', 'CurrentDirectory', 'User', 'Hashes', 'ParentProcessGuid', 'ParentProcessId', 'ParentImage', 'ParentCommandLine'],
            2: ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetFilename', 'CreationUtcTime', 'PreviousCreationUtcTime', 'User'],
            3: ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'User', 'Protocol', 'SourceIsIpv6', 'SourceIp', 'SourceHostname', 'SourcePort', 'SourcePortName', 'DestinationIsIpv6', 'DestinationIp', 'DestinationHostname', 'DestinationPort', 'DestinationPortName'],
            5: ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'User'],
            6: ['UtcTime', 'ImageLoaded', 'Hashes'],
            7: ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'ImageLoaded', 'OriginalFileName', 'Hashes', 'User'],
            8: ['UtcTime', 'SourceProcessGuid', 'SourceProcessId', 'SourceImage', 'TargetProcessGuid', 'TargetProcessId', 'TargetImage', 'NewThreadId', 'SourceUser', 'TargetUser'],
            9: ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'Device', 'User'],
            10: ['UtcTime', 'SourceProcessGUID', 'SourceProcessId', 'SourceImage', 'TargetProcessGUID', 'TargetProcessId', 'TargetImage', 'SourceThreadId', 'SourceUser', 'TargetUser'],
            11: ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetFilename', 'CreationUtcTime', 'User'],
            12: ['EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetObject', 'User'],
            13: ['EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetObject', 'User'],
            14: ['EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetObject', 'User'],
            15: ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetFilename', 'CreationUtcTime', 'Hash', 'User'],
            16: ['UtcTime', 'Configuration', 'ConfigurationFileHash', 'User'],
            17: ['EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'PipeName', 'Image', 'User'],
            18: ['EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'PipeName', 'Image', 'User'],
            22: ['UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'QueryName', 'QueryStatus', 'QueryResults', 'User'],
            23: ['UtcTime', 'ProcessGuid', 'ProcessId', 'User', 'Image', 'TargetFilename', 'Hashes'],
            24: ['UtcTime', 'ProcessGuid', 'ProcessId', 'User', 'Image', 'Hashes'],
            25: ['UtcTime', 'ProcessGuid', 'ProcessId', 'User', 'Image']
        }
        
        # Data type definitions
        self.integer_columns = {
            'ProcessId', 'SourcePort', 'DestinationPort', 'SourceProcessId', 
            'ParentProcessId', 'SourceThreadId', 'TargetProcessId'
        }
        
        self.guid_columns = {
            'ProcessGuid', 'SourceProcessGUID', 'TargetProcessGUID', 'ParentProcessGuid'
        }
        
    def _load_config(self, config_file: str) -> dict:
        """Load configuration from YAML file."""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"⚠️  Warning: Could not load config file {config_file}: {e}")
            print("🔧 Using default configuration...")
            return {}
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger(__name__)
        
        sysmon_config = self.config.get('sysmon_processor', {}) or self.config.get('script_02_sysmon_csv_creator', {})
        if sysmon_config.get('enable_logging', True):
            logger.setLevel(logging.INFO)
            
            # Console handler
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def sanitize_xml(self, xml_str: str) -> str:
        """Clean invalid characters and repair XML structure."""
        # Remove non-printable characters
        cleaned = ''.join(c for c in xml_str if 31 < ord(c) < 127 or c in '\\t\\n\\r')
        # Fix common XML issues using BeautifulSoup's parser
        return BeautifulSoup(cleaned, "xml").prettify()
    
    def parse_sysmon_event(self, xml_str: str) -> Tuple[Optional[int], Optional[str], Dict]:
        """Parse Windows Event Log XML to extract EventID, Computer, and fields."""
        try:
            # Clean XML first
            clean_xml = self.sanitize_xml(xml_str)
            
            # Parse with explicit namespace
            namespaces = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            root = ET.fromstring(clean_xml)
            
            # System section - with null checks
            system = root.find('ns:System', namespaces)
            if not system:
                return None, None, {}

            event_id_elem = system.find('ns:EventID', namespaces)
            computer_elem = system.find('ns:Computer', namespaces)
            
            event_id = int(event_id_elem.text) if event_id_elem is not None else None
            computer = computer_elem.text.lower() if computer_elem is not None else None

            # EventData section
            event_data = root.find('ns:EventData', namespaces)
            fields = {}
            if event_data:
                for data in event_data.findall('ns:Data', namespaces):
                    name = data.get('Name')
                    fields[name] = data.text if data.text else None

            return event_id, computer, fields

        except Exception as e:
            # Log problematic XML samples for debugging
            sysmon_config = self.config.get('sysmon_processor', {}) or self.config.get('script_02_sysmon_csv_creator', {})
            if sysmon_config.get('enable_logging', True):
                with open('bad_xml_samples.txt', 'a') as bad_xml:
                    bad_xml.write(f"Error: {str(e)}\\n")
                    bad_xml.write(f"XML: {xml_str[:500]}...\\n")
                    bad_xml.write("-" * 50 + "\\n")
            self.logger.error(f"XML parsing failed: {str(e)}")
            return None, None, {}
    
    def safe_int_conversion(self, value) -> Optional[int]:
        """Safely convert value to integer, handling whitespace, NaN and invalid values."""
        if value is None or pd.isna(value):
            return None
        try:
            cleaned_value = str(value).strip()
            if not cleaned_value:
                return None
            return int(float(cleaned_value))
        except (ValueError, TypeError):
            return None

    def clean_guid(self, value) -> Optional[str]:
        """Remove whitespace and brackets from GUID values and ensure string type."""
        if value is None or pd.isna(value):
            return None
        try:
            cleaned = str(value).strip()
            if not cleaned:
                return None
            # Remove curly brackets
            cleaned = cleaned.strip('{}')
            return cleaned if cleaned else None
        except (ValueError, TypeError):
            return None
    
    def _calculate_timestamp_statistics(self, df: pd.DataFrame) -> Dict:
        """Calculate detailed timestamp statistics for the dataset"""
        timestamp_stats = {}
        
        if 'timestamp' in df.columns:
            # Convert epoch timestamps back to datetime for human-readable format
            valid_timestamps = df['timestamp'].dropna()
            
            if len(valid_timestamps) > 0:
                # Convert epoch milliseconds to datetime objects (since we now store as milliseconds)
                datetime_timestamps = pd.to_datetime(valid_timestamps, unit='ms')
                
                min_time = datetime_timestamps.min()
                max_time = datetime_timestamps.max()
                duration = max_time - min_time
                
                timestamp_stats = {
                    "minimum_timestamp_epoch": int(valid_timestamps.min()),
                    "maximum_timestamp_epoch": int(valid_timestamps.max()),
                    "minimum_timestamp_human_readable": min_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "maximum_timestamp_human_readable": max_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "dataset_time_span": {
                        "total_seconds": duration.total_seconds(),
                        "total_minutes": duration.total_seconds() / 60,
                        "total_hours": duration.total_seconds() / 3600,
                        "formatted_duration": str(duration)
                    },
                    "temporal_coverage": {
                        "events_chronologically_sorted": True,  # Always sorted in clean_dataframe
                        "total_events_with_timestamps": len(valid_timestamps),
                        "events_per_minute_avg": len(valid_timestamps) / (duration.total_seconds() / 60) if duration.total_seconds() > 0 else 0
                    }
                }
        
        return timestamp_stats

    def _save_complete_processing_log(self, input_file: str, df: pd.DataFrame):
        """Save complete processing log with timestamp statistics after DataFrame cleaning"""
        try:
            # Get existing log data first
            run_number = self._extract_run_number(input_file)
            json_log_file = Path(input_file).parent / f"02_log-sysmon-jsonl-to-csv-run-{run_number}.json"

            # Load existing log data
            if json_log_file.exists():
                with open(json_log_file, 'r') as f:
                    log_data = json.load(f)
            else:
                log_data = {}
            
            # Add timestamp statistics
            log_data["timestamp_statistics"] = self._calculate_timestamp_statistics(df)
            
            # Save updated log
            with open(json_log_file, 'w') as f:
                json.dump(log_data, f, indent=2, default=str)
                
            self.logger.info(f"📊 Complete processing log with timestamp statistics saved: {json_log_file}")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to save complete processing log: {e}")

    def _save_processing_log(self, jsonl_path: str, start_time: datetime, end_time: datetime,
                           processing_duration, total_events: int, events_per_second: float,
                           records_created: int, df: pd.DataFrame = None):
        """Save structured JSON processing log"""
        try:
            # Create log data structure
            log_data = {
                "processing_metadata": {
                    "timestamp": end_time.isoformat(),
                    "operation_type": "sysmon_jsonl_to_csv_conversion",
                    "script_version": "2.0_multithreaded",
                    "input_file": jsonl_path,
                    "input_file_size_bytes": Path(jsonl_path).stat().st_size if Path(jsonl_path).exists() else None
                },
                "processing_configuration": {
                    "max_workers": self.max_workers,
                    "chunk_size": self.chunk_size,
                    "temporal_sorting_enabled": self.config.get('sysmon_processor', {}).get('enable_temporal_sorting', True),
                    "timestamp_format": "epoch_milliseconds_integer",
                    "data_optimization_enabled": self.config.get('sysmon_processor', {}).get('enable_data_optimization', True)
                },
                "processing_timing": {
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                    "duration_seconds": processing_duration.total_seconds(),
                    "duration_formatted": str(processing_duration),
                    "processing_speed_events_per_second": events_per_second
                },
                "processing_statistics": {
                    "total_xml_events_processed": total_events,
                    "successfully_converted_to_csv_rows": records_created,
                    "processing_errors": self.shared_stats['total_errors'],
                    "success_rate_percent": (records_created / total_events) * 100 if total_events > 0 else 0
                },
                "dataset_statistics": {
                    "total_events_in_dataset": records_created,
                    "events_per_eventid": self.shared_stats['eventid_counts'],
                    "total_unique_eventids": len(self.shared_stats['eventid_counts']),
                    "most_common_eventid": max(self.shared_stats['eventid_counts'], key=self.shared_stats['eventid_counts'].get) if self.shared_stats['eventid_counts'] else None,
                    "least_common_eventid": min(self.shared_stats['eventid_counts'], key=self.shared_stats['eventid_counts'].get) if self.shared_stats['eventid_counts'] else None
                },
                "eventid_distribution": self.shared_stats['eventid_counts'],
                "missing_fields_analysis": self.shared_stats['missing_fields_tracker'],
                "performance_metrics": {
                    "memory_usage_optimized": self.config.get('sysmon_processor', {}).get('enable_data_optimization', True),
                    "multi_threading_efficiency": {
                        "workers_used": self.max_workers,
                        "chunk_size": self.chunk_size,
                        "chunks_processed": len(self.shared_stats['eventid_counts']) # Approximation
                    }
                },
                "session_info": {
                    "hostname": os.uname().nodename if hasattr(os, 'uname') else "unknown",
                    "working_directory": str(Path.cwd()),
                    "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                }
            }
            
            # Add timestamp statistics if DataFrame is provided
            if df is not None and 'timestamp' in df.columns:
                log_data["timestamp_statistics"] = self._calculate_timestamp_statistics(df)
            
            # Generate output filename following naming convention: log-sysmon-JSONL-to-csv-run-X.json
            # Extract run number from input filename or directory
            run_number = self._extract_run_number(jsonl_path)
            json_log_file = Path(jsonl_path).parent / f"02_log-sysmon-jsonl-to-csv-run-{run_number}.json"
            
            # Save JSON log
            with open(json_log_file, 'w') as f:
                json.dump(log_data, f, indent=2, default=str)
            
            self.logger.info(f"📄 Structured processing log saved: {json_log_file.name}")
            
        except Exception as e:
            self.logger.error(f"❌ Error saving processing log: {str(e)}")
    
    def _extract_run_number(self, jsonl_path: str) -> str:
        """Extract run number from jsonl filename or directory path"""
        import re
        
        # Try to extract from filename first
        filename = Path(jsonl_path).name
        run_match = re.search(r'run-(\d+)', filename)
        if run_match:
            return run_match.group(1)
        
        # Try to extract from directory path
        path_str = str(jsonl_path)
        run_match = re.search(r'run-(\d+)', path_str)
        if run_match:
            return run_match.group(1)
        
        # Fallback to timestamp if no run number found
        return datetime.now().strftime('%Y%m%d_%H%M%S')
    
    def read_jsonl_in_chunks(self, jsonl_path: str) -> List[List[str]]:
        """Read JSONL file and split into chunks for multi-threading."""
        self.logger.info(f"📖 Reading and chunking JSONL file: {jsonl_path}")
        
        chunks = []
        current_chunk = []
        
        with open(jsonl_path, 'r') as f:
            for line_number, line in enumerate(f, 1):
                current_chunk.append(line.strip())
                
                if len(current_chunk) >= self.chunk_size:
                    chunks.append(current_chunk)
                    current_chunk = []
                    
                # Progress reporting
                if line_number % 100000 == 0:
                    self.logger.info(f"📊 Read {line_number:,} lines, created {len(chunks)} chunks")
            
            # Add remaining lines
            if current_chunk:
                chunks.append(current_chunk)
        
        self.logger.info(f"📦 Created {len(chunks)} chunks of max size {self.chunk_size}")
        return chunks
    
    def process_chunk(self, chunk_lines: List[str], chunk_id: int) -> Tuple[List[Dict], Dict]:
        """Process a chunk of JSONL lines in a separate thread."""
        records = []
        chunk_stats = {
            'processed': 0,
            'errors': 0,
            'eventid_counts': {},
            'missing_fields_tracker': {}
        }
        
        for line_idx, line in enumerate(chunk_lines):
            try:
                if not line.strip():
                    continue
                    
                event = json.loads(line)
                xml_str = event['event']['original']
                
                event_id, computer, fields = self.parse_sysmon_event(xml_str)
                
                # Skip if essential fields missing
                if not event_id or not computer:
                    chunk_stats['errors'] += 1
                    continue
                
                # Count events per EventID
                chunk_stats['eventid_counts'][event_id] = chunk_stats['eventid_counts'].get(event_id, 0) + 1
                
                # Build record (same logic as before)
                record = self._build_event_record(event_id, computer, fields, chunk_stats)
                if record:
                    records.append(record)
                    chunk_stats['processed'] += 1
                
            except Exception as e:
                chunk_stats['errors'] += 1
                # Thread-safe error logging
                with self.progress_lock:
                    self.logger.error(f"Chunk {chunk_id}, Line {line_idx}: {str(e)}")
        
        # Thread-safe progress reporting
        with self.progress_lock:
            self.logger.info(f"✅ Chunk {chunk_id}: {chunk_stats['processed']} processed, {chunk_stats['errors']} errors")
        
        return records, chunk_stats
    
    def _build_event_record(self, event_id: int, computer: str, fields: Dict, chunk_stats: Dict) -> Optional[Dict]:
        """Build event record with proper field mapping and data types."""
        record = {
            'EventID': event_id,
            'Computer': computer
        }
        
        # Add fields from mapping with data type optimization
        expected_fields = self.fields_per_eventid.get(event_id, [])
        for field in expected_fields:
            # Special handling for EventID 8: map lowercase guid fields to uppercase GUID columns
            if event_id == 8:
                if field == 'SourceProcessGuid':
                    column_name = 'SourceProcessGUID'
                    if field not in fields:
                        self._track_missing_field(event_id, field, chunk_stats)
                    raw_value = fields.get(field, None)
                    record[column_name] = self.clean_guid(raw_value)
                    continue
                elif field == 'TargetProcessGuid':
                    column_name = 'TargetProcessGUID'
                    if field not in fields:
                        self._track_missing_field(event_id, field, chunk_stats)
                    raw_value = fields.get(field, None)
                    record[column_name] = self.clean_guid(raw_value)
                    continue
            
            # Normal field processing
            if field not in fields:
                self._track_missing_field(event_id, field, chunk_stats)
            
            raw_value = fields.get(field, None)
            
            # Apply data type conversions
            if field in self.integer_columns:
                record[field] = self.safe_int_conversion(raw_value)
            elif field in self.guid_columns:
                record[field] = self.clean_guid(raw_value)
            else:
                if raw_value is not None:
                    cleaned_value = str(raw_value).strip()
                    record[field] = cleaned_value if cleaned_value else None
                else:
                    record[field] = raw_value
        
        return record
    
    def _track_missing_field(self, event_id: int, field: str, chunk_stats: Dict):
        """Track missing fields in chunk statistics."""
        if event_id not in chunk_stats['missing_fields_tracker']:
            chunk_stats['missing_fields_tracker'][event_id] = {}
        if field not in chunk_stats['missing_fields_tracker'][event_id]:
            chunk_stats['missing_fields_tracker'][event_id][field] = 0
        chunk_stats['missing_fields_tracker'][event_id][field] += 1
    
    def merge_chunk_stats(self, chunk_stats_list: List[Dict]):
        """Merge statistics from all chunks into shared stats."""
        with self.stats_lock:
            for chunk_stats in chunk_stats_list:
                self.shared_stats['total_processed'] += chunk_stats['processed']
                self.shared_stats['total_errors'] += chunk_stats['errors']
                
                # Merge EventID counts
                for event_id, count in chunk_stats['eventid_counts'].items():
                    self.shared_stats['eventid_counts'][event_id] = \
                        self.shared_stats['eventid_counts'].get(event_id, 0) + count
                
                # Merge missing fields tracking
                for event_id, missing_fields in chunk_stats['missing_fields_tracker'].items():
                    if event_id not in self.shared_stats['missing_fields_tracker']:
                        self.shared_stats['missing_fields_tracker'][event_id] = {}
                    
                    for field, count in missing_fields.items():
                        self.shared_stats['missing_fields_tracker'][event_id][field] = \
                            self.shared_stats['missing_fields_tracker'][event_id].get(field, 0) + count
    
    def process_events(self, jsonl_path: str) -> pd.DataFrame:
        """Multi-threaded processing of JSONL file and convert Sysmon events to structured DataFrame."""
        start_time = datetime.now()
        self.logger.info(f"🔄 Starting multi-threaded processing from {jsonl_path}")
        self.logger.info(f"⚙️ Using {self.max_workers} worker threads, chunk size: {self.chunk_size:,}")
        self.logger.info(f"🕐 Start time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Read and chunk the file
        chunks = self.read_jsonl_in_chunks(jsonl_path)
        
        if not chunks:
            self.logger.error("No data chunks created - file may be empty")
            return pd.DataFrame()
        
        all_records = []
        chunk_stats_list = []
        
        # Process chunks in parallel
        self.logger.info(f"🚀 Processing {len(chunks)} chunks with {self.max_workers} threads")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all chunks for processing
            future_to_chunk = {
                executor.submit(self.process_chunk, chunk, chunk_id): chunk_id 
                for chunk_id, chunk in enumerate(chunks)
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_chunk):
                chunk_id = future_to_chunk[future]
                try:
                    chunk_records, chunk_stats = future.result()
                    all_records.extend(chunk_records)
                    chunk_stats_list.append(chunk_stats)
                    
                    # Progress update
                    completed_chunks = len(chunk_stats_list)
                    progress_pct = (completed_chunks / len(chunks)) * 100
                    self.logger.info(f"📈 Progress: {completed_chunks}/{len(chunks)} chunks ({progress_pct:.1f}%)")
                    
                except Exception as e:
                    self.logger.error(f"❌ Chunk {chunk_id} failed: {str(e)}")
        
        # Merge statistics from all chunks
        self.merge_chunk_stats(chunk_stats_list)
        
        # Calculate processing time and performance metrics
        end_time = datetime.now()
        processing_duration = end_time - start_time
        total_events = self.shared_stats['total_processed'] + self.shared_stats['total_errors']
        events_per_second = total_events / processing_duration.total_seconds() if processing_duration.total_seconds() > 0 else 0
        
        # Log final statistics with timing
        self.logger.info(f"✅ Multi-threaded processing complete:")
        self.logger.info(f"   🕐 Start time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.logger.info(f"   🕐 End time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.logger.info(f"   ⏱️ Processing duration: {processing_duration}")
        self.logger.info(f"   📊 Total XML events processed: {total_events:,}")
        self.logger.info(f"   ✅ Successfully converted to CSV rows: {self.shared_stats['total_processed']:,}")
        self.logger.info(f"   ❌ Processing errors: {self.shared_stats['total_errors']:,}")
        self.logger.info(f"   📈 Success rate: {(self.shared_stats['total_processed']/total_events)*100:.1f}%" if total_events > 0 else "   📈 Success rate: N/A")
        self.logger.info(f"   🚀 Processing speed: {events_per_second:.1f} events/second")
        
        # Log missing fields analysis
        if self.shared_stats['missing_fields_tracker']:
            self.logger.info("📊 Missing fields analysis:")
            for event_id, missing_fields in self.shared_stats['missing_fields_tracker'].items():
                total_events = self.shared_stats['eventid_counts'][event_id]
                self.logger.info(f"   EventID {event_id}: {total_events:,} total events")
                for field, missing_count in missing_fields.items():
                    percentage = (missing_count / total_events) * 100
                    self.logger.info(f"     • Field '{field}': {missing_count:,}/{total_events:,} missing ({percentage:.1f}%)")
        
        # Log EventID distribution
        self.logger.info("📈 EventID distribution:")
        for event_id in sorted(self.shared_stats['eventid_counts'].keys()):
            self.logger.info(f"   EventID {event_id}: {self.shared_stats['eventid_counts'][event_id]:,} events")
        
        self.logger.info(f"🏗️ Creating DataFrame from {len(all_records):,} records")
        
        # Create DataFrame first
        df = pd.DataFrame(all_records)
        
        # Save structured JSON log (without DataFrame timestamp stats - will be added later)
        self._save_processing_log(jsonl_path, start_time, end_time, processing_duration, 
                                 total_events, events_per_second, len(all_records))
        
        return df
    
    def clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean DataFrame and optimize data types."""
        self.logger.info("🧽 Cleaning and optimizing DataFrame")
        
        # Trim whitespace for string columns
        str_cols = df.select_dtypes(['object']).columns
        df[str_cols] = df[str_cols].apply(lambda x: x.str.strip())
        
        # Replace empty strings with None
        df.replace({'': None}, inplace=True)
        
        # TIMESTAMP STANDARDIZATION: Convert UtcTime to epoch format for ML compatibility
        sysmon_config = self.config.get('sysmon_processor', {}) or self.config.get('script_02_sysmon_csv_creator', {})
        enable_temporal_sorting = sysmon_config.get('enable_temporal_sorting', True)
        
        if 'UtcTime' in df.columns:
            self.logger.info("🕒 Converting timestamps to ML-compatible epoch format")
            try:
                # Convert UtcTime to datetime for processing
                df['UtcTime'] = pd.to_datetime(df['UtcTime'], errors='coerce')
                
                # Count and log invalid timestamps
                invalid_timestamps = df['UtcTime'].isnull().sum()
                if invalid_timestamps > 0:
                    self.logger.warning(f"⚠️ Found {invalid_timestamps} invalid timestamps")
                
                # Apply temporal sorting if enabled
                if enable_temporal_sorting:
                    self.logger.info("🔄 Sorting events chronologically")
                    df = df.sort_values('UtcTime', na_position='last').reset_index(drop=True)
                
                # Log timestamp range for verification
                valid_timestamps = df['UtcTime'].dropna()
                if len(valid_timestamps) > 0:
                    min_time = valid_timestamps.min()
                    max_time = valid_timestamps.max()
                    duration = max_time - min_time
                    self.logger.info(f"📅 Timeline: {min_time} → {max_time}")
                    self.logger.info(f"⏱️ Duration: {duration.total_seconds()/3600:.2f} hours")
                
                # CONVERT TO EPOCH TIMESTAMP FOR ML COMPATIBILITY
                self.logger.info("🔄 Converting to epoch format (Unix timestamp)")
                
                # Convert to epoch with millisecond precision preserved as INTEGER
                df['timestamp'] = (df['UtcTime'].astype('int64') // 10**6).astype('int64')  # nanoseconds to milliseconds (integer)
                
                self.logger.info("⚡ Timestamp precision: Milliseconds preserved as integer for exact correlation matching")
                
                # Drop the original UtcTime column
                df = df.drop(columns=['UtcTime'])
                
                # Log conversion statistics
                valid_epochs = df['timestamp'].dropna()
                if len(valid_epochs) > 0:
                    self.logger.info(f"✅ Converted {len(valid_epochs):,} timestamps to epoch format")
                    self.logger.info(f"📊 Epoch range: {valid_epochs.min()} to {valid_epochs.max()}")
                    
                    # Convert back to human-readable for verification (using milliseconds)
                    earliest_human = pd.to_datetime(valid_epochs.min(), unit='ms')
                    latest_human = pd.to_datetime(valid_epochs.max(), unit='ms')
                    self.logger.info(f"🕐 Verification: {earliest_human} to {latest_human}")
                
            except Exception as e:
                self.logger.error(f"❌ Error during timestamp processing: {e}")
                self.logger.warning("⚠️ Continuing without timestamp standardization")
        else:
            self.logger.warning("⚠️ No UtcTime column found - timestamps will not be processed")
        
        if sysmon_config.get('enable_data_optimization', True):
            # Convert integer columns to nullable integer type
            for col in self.integer_columns:
                if col in df.columns:
                    df[col] = df[col].astype('Int64')
                    self.logger.info(f"Converted {col} to Int64 type")
            
            # Convert GUID columns to string type
            for col in self.guid_columns:
                if col in df.columns:
                    df[col] = df[col].astype('string')
                    self.logger.info(f"Converted {col} to string type")
            
            # Convert categorical columns
            categorical_columns = ['Computer', 'Protocol', 'EventType']
            for col in categorical_columns:
                if col in df.columns and df[col].nunique() < df.shape[0] * 0.5:
                    df[col] = df[col].astype('category')
                    self.logger.info(f"Converted {col} to category type")
            
            memory_mb = df.memory_usage(deep=True).sum() / 1024**2
            self.logger.info(f"Memory usage after optimization: {memory_mb:.2f} MB")
        
        return df
    
    def backup_existing_file(self, output_path: str) -> Optional[str]:
        """Create backup of existing output file if it exists."""
        if not os.path.exists(output_path):
            return None
        
        sysmon_config = self.config.get('sysmon_processor', {}) or self.config.get('script_02_sysmon_csv_creator', {})
        backup_dir = Path(sysmon_config.get('backup_dir', './backups'))
        backup_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"{Path(output_path).stem}_backup_{timestamp}.csv"
        backup_path = backup_dir / backup_filename
        
        shutil.copy2(output_path, backup_path)
        self.logger.info(f"📁 Backup created: {backup_path}")
        
        return str(backup_path)
    
    def compare_outputs(self, original_path: str, new_path: str) -> bool:
        """Compare original and new CSV files for validation."""
        if not original_path or not os.path.exists(original_path):
            self.logger.info("No original file to compare with")
            return True
        
        self.logger.info(f"🔍 Comparing outputs...")
        
        try:
            # Load both files
            original_df = pd.read_csv(original_path)
            new_df = pd.read_csv(new_path)
            
            # Basic comparison
            if original_df.shape != new_df.shape:
                self.logger.warning(f"Shape mismatch: Original {original_df.shape} vs New {new_df.shape}")
                return False
            
            # Sort both by EventID and Computer for consistent comparison
            original_sorted = original_df.sort_values(['EventID', 'Computer']).reset_index(drop=True)
            new_sorted = new_df.sort_values(['EventID', 'Computer']).reset_index(drop=True)
            
            # Compare data
            differences = 0
            for col in original_sorted.columns:
                if col in new_sorted.columns:
                    # Handle potential data type differences
                    if not original_sorted[col].equals(new_sorted[col]):
                        differences += 1
                        self.logger.warning(f"Column '{col}' differs between files")
            
            if differences == 0:
                self.logger.info("✅ Files are identical!")
                return True
            else:
                self.logger.warning(f"❌ Found {differences} differing columns")
                return False
        
        except Exception as e:
            self.logger.error(f"Error comparing files: {e}")
            return False
    
    def run(self, input_file: Optional[str] = None, output_file: Optional[str] = None, 
            validate: bool = True) -> bool:
        """Run the complete CSV creation process."""
        # Use config values if not provided (support both old and new config formats)
        sysmon_config = self.config.get('sysmon_processor', {}) or self.config.get('script_02_sysmon_csv_creator', {})
        if not input_file:
            input_file = sysmon_config['input_file']
        if not output_file:
            output_file = sysmon_config['output_file']
        
        self.logger.info("🚀 Starting Sysmon CSV creation process")
        self.logger.info(f"Input: {input_file}")
        self.logger.info(f"Output: {output_file}")
        
        # Check input file exists
        if not os.path.exists(input_file):
            self.logger.error(f"❌ Input file not found: {input_file}")
            return False
        
        try:
            # Backup existing output file
            backup_path = None
            if validate:
                backup_path = self.backup_existing_file(output_file)
            
            # Process events
            df = self.process_events(input_file)
            
            # Clean DataFrame
            df = self.clean_dataframe(df)
            
            # Save complete processing log with timestamp statistics
            self._save_complete_processing_log(input_file, df)
            
            # Export to CSV
            self.logger.info(f"💾 Exporting to CSV: {output_file}")
            df.to_csv(output_file, index=False)
            
            # Validate output
            if validate and backup_path:
                identical = self.compare_outputs(backup_path, output_file)
                if identical:
                    self.logger.info("🎉 Validation successful - outputs are identical!")
                else:
                    self.logger.warning("⚠️ Validation found differences - manual review recommended")
            
            self.logger.info("✅ CSV creation completed successfully!")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Processing failed: {e}")
            return False


def auto_detect_files(apt_dir: str, base_dir: str = '.') -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Auto-detect input JSONL, output CSV, and config files in APT directory.
    
    Args:
        apt_dir: APT run directory (e.g., 'apt-1/apt-1-05-04-run-05')
        base_dir: Base directory for APT runs
    
    Returns:
        Tuple of (input_jsonl_path, output_csv_path, config_file_path)
    """
    import glob
    
    # Construct full path
    full_apt_path = os.path.join(base_dir, apt_dir)
    
    if not os.path.exists(full_apt_path):
        raise FileNotFoundError(f"APT directory not found: {full_apt_path}")
    
    print(f"🔍 Auto-detecting files in: {full_apt_path}")
    
    # Detect Sysmon JSONL file
    sysmon_patterns = [
        "*sysmon*.jsonl",
        "*windows-sysmon*.jsonl", 
        "*ds-logs-windows-sysmon*.jsonl"
    ]
    
    input_file = None
    for pattern in sysmon_patterns:
        matches = glob.glob(os.path.join(full_apt_path, pattern))
        if matches:
            input_file = matches[0]  # Take first match
            break
    
    if not input_file:
        print("⚠️  No Sysmon JSONL file found")
        return None, None, None
    
    # Detect config file first
    config_patterns = ["config.yaml", "config.yml"]
    config_file = None
    for pattern in config_patterns:
        config_path = os.path.join(full_apt_path, pattern)
        if os.path.exists(config_path):
            config_file = config_path
            break
    
    # Generate output CSV filename - prioritize config.yaml, then fallback to auto-generation
    output_file = None
    if config_file:
        try:
            import yaml
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            # Get output filename from config (support both old and new config formats)
            sysmon_config = config.get('sysmon_processor', {}) or config.get('script_02_sysmon_csv_creator', {})
            if 'output_file' in sysmon_config:
                config_output = sysmon_config['output_file']
                output_file = os.path.join(full_apt_path, config_output)
                print(f"📋 Using config-specified output: {config_output}")
        except Exception as e:
            print(f"⚠️  Error reading config file: {e}")
    
    # Fallback to auto-generation if config reading failed
    if not output_file:
        input_basename = os.path.basename(input_file)
        if "sysmon" in input_basename:
            # Extract date pattern from input file
            import re
            date_match = re.search(r'(\d{4}-\d{2}-\d{2})', input_basename)
            if date_match:
                date_str = date_match.group(1)
                output_file = os.path.join(full_apt_path, f"02_sysmon-{date_str}-000001.csv")
            else:
                # Fallback naming
                output_file = os.path.join(full_apt_path, "02_sysmon-output.csv")
        else:
            csv_name = "02_" + os.path.basename(input_file).replace('.jsonl', '.csv')
            output_file = os.path.join(os.path.dirname(input_file), csv_name)
        print(f"📝 Using auto-generated output: {os.path.basename(output_file)}")
    
    print(f"📥 Detected input: {os.path.relpath(input_file)}")
    print(f"📤 Target output: {os.path.relpath(output_file)}")
    if config_file:
        print(f"⚙️  Detected config: {os.path.relpath(config_file)}")
    else:
        print("⚙️  No config file detected in APT directory")
    
    return input_file, output_file, config_file


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        description="Sysmon JSONL to CSV Converter - Batch Processing Ready",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Use config.yaml settings (default)
  python 2_sysmon_csv_creator.py
  
  # Process specific APT run directory
  python 2_sysmon_csv_creator.py --apt-dir apt-1/apt-1-05-04-run-05
  
  # Specify custom input/output files
  python 2_sysmon_csv_creator.py --input custom.jsonl --output custom.csv
  
  # Skip validation (faster)
  python 2_sysmon_csv_creator.py --no-validate
  
  # Use custom config file
  python 2_sysmon_csv_creator.py --config my_config.yaml
        """
    )
    
    # Batch processing parameters
    parser.add_argument('--apt-dir', 
                       help='APT run directory (e.g., apt-1/apt-1-05-04-run-05) - enables auto-detection')
    parser.add_argument('--base-dir', default='.',
                       help='Base directory for APT runs (default: current directory)')
    
    # Traditional parameters
    parser.add_argument('--config', '-c', default='config.yaml',
                       help='Configuration file path (optional, uses defaults if not found)')
    parser.add_argument('--input', '-i',
                       help='Input JSONL file path (overrides config and auto-detection)')
    parser.add_argument('--output', '-o', 
                       help='Output CSV file path (overrides config and auto-detection)')
    parser.add_argument('--no-validate', action='store_true',
                       help='Skip validation against existing output')
    
    args = parser.parse_args()
    
    try:
        # Handle batch processing mode
        if args.apt_dir:
            input_file, output_file, config_file = auto_detect_files(args.apt_dir, args.base_dir)
            
            # Check if auto-detection failed
            if input_file is None:
                print(f"❌ Error: No Sysmon JSONL file found in directory: {args.apt_dir}")
                print(f"   Searched patterns: *sysmon*.jsonl, *windows-sysmon*.jsonl, *ds-logs-windows-sysmon*.jsonl")
                print(f"   You can specify a file manually with --input <file.jsonl>")
                sys.exit(1)
            
            # Use detected config if available, otherwise fall back to provided config
            if config_file and os.path.exists(config_file):
                converter = SysmonCSVCreator(config_file)
                print(f"🔧 Using detected config: {config_file}")
            else:
                converter = SysmonCSVCreator(args.config)
                print(f"🔧 Using default config: {args.config}")
            
            print(f"📂 Processing APT directory: {args.apt_dir}")
            print(f"📥 Auto-detected input: {input_file}")
            print(f"📤 Auto-detected output: {output_file}")
            
            # Override with explicit parameters if provided
            final_input = args.input if args.input else input_file
            final_output = args.output if args.output else output_file
            
        else:
            # Traditional mode - only use config if it exists and --input/--output are not provided
            config_to_use = args.config if os.path.exists(args.config) and not (args.input and args.output) else None
            converter = SysmonCSVCreator(config_to_use)
            final_input = args.input
            final_output = args.output
            if config_to_use:
                print(f"🔧 Traditional mode using config: {args.config}")
            else:
                print(f"🔧 Traditional mode using defaults (no config file)")
        
        # Run conversion
        success = converter.run(
            input_file=final_input,
            output_file=final_output,
            validate=not args.no_validate
        )
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\\n⏹️  Processing cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
