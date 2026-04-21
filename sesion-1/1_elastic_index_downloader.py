#!/usr/bin/env python3
"""
Elasticsearch Index Downloader

Converted from notebook: 1_elastic-index-downloader.ipynb
Extracts cybersecurity data from Elasticsearch clusters containing Windows event logs and network traffic.

Dependencies: elasticsearch
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import scan
except ImportError:
    print("❌ Error: elasticsearch library not installed")
    print("   Install with: pip install elasticsearch")
    sys.exit(1)


# Global configuration (matches notebook exactly)
es_host = "<ES_HOST>"               # Example: "https://10.2.0.20:9200"
username = "<ES_USER>"              # Elasticsearch username
password = "<ES_PASSWORD>"          # Elasticsearch password
keywords = ['sysmon', 'network_traffic']
output_dir = "./"
TIMESTAMP_FORMAT = "%b %d, %Y @ %H:%M:%S.%f"


def connect_elasticsearch():
    """
    Create secure connection to Elasticsearch cluster.
    
    Returns:
        Elasticsearch: Configured client instance with authentication
    """
    return Elasticsearch(
        hosts=[es_host],                         # Cluster endpoint
        basic_auth=(username, password),         # Username/password authentication  
        verify_certs=False,                      # Disable SSL cert verification (lab environment)
        ssl_show_warn=False                      # Suppress SSL warnings
    )


def test_connection(es):
    """
    Validate Elasticsearch connection with ping test.
    
    Args:
        es (Elasticsearch): Elasticsearch client instance
        
    Returns:
        bool: True if connection successful, False otherwise
    """
    try:
        return es.ping()                         # Test basic connectivity
    except Exception as e:
        print(f"🔥 Connection failed: {e}")      # Display connection error
        return False


def list_relevant_indices(es, keywords):
    """
    Discover indices containing security-related keywords.
    
    Args:
        es (Elasticsearch): Elasticsearch client instance
        keywords (list): Keywords to filter indices (e.g., ['sysmon', 'network_traffic'])
        
    Returns:
        list: List of dictionaries containing index metadata (name, size, creation date)
    """
    try:
        # Query cluster for all indices with metadata
        response = es.cat.indices(format="json", h="index,store.size,creation.date")
        
        # Filter indices containing security keywords and extract metadata
        return [
            {
                "name": idx["index"],                                                    # Index name
                "size": idx.get("store.size", "0b"),                                   # Storage size
                "created": datetime.fromtimestamp(int(idx["creation.date"])/1000, tz=timezone.utc)  # Creation timestamp
            }
            for idx in response
            if any(kw in idx["index"] for kw in keywords)                              # Filter by keywords
        ]
    except Exception as e:
        print(f"🚨 Error listing indices: {e}")
        return []


def display_indices_selector(indices):
    """
    Interactive interface for user to select which indices to process.
    
    Args:
        indices (list): List of index dictionaries from list_relevant_indices()
        
    Returns:
        list: List of selected index names, empty list if user exits
    """
    # Display available indices with metadata
    print(f"\n📂 Found {len(indices)} relevant indices:")
    for i, idx in enumerate(indices, 1):
        print(f"{i:>3}. {idx['name']} ({idx['size']}) [Created: {idx['created'].strftime('%Y-%m-%d')}]")

    # Interactive selection loop
    while True:
        selection = input("\n🔢 Select indices (comma-separated numbers, 'all', or 'exit'): ").strip().lower()
        
        # Handle exit condition
        if selection == "exit":
            return []
        
        # Handle select all condition  
        if selection == "all":
            return [idx["name"] for idx in indices]
        
        # Parse individual number selections
        try:
            selected_indices = [
                indices[int(num)-1]["name"]                    # Convert 1-based index to 0-based
                for num in selection.split(",")               # Split comma-separated input
                if num.strip().isdigit()                      # Validate numeric input
            ]
            if selected_indices:
                return list(set(selected_indices))            # Remove duplicates and return
            print("⚠️ No valid selection. Please try again.")
        except (IndexError, ValueError):
            print("⛔ Invalid input format. Use numbers separated by commas.")


def parse_utc_time(time_str):
    """
    Parse human-readable time string into UTC datetime object.
    
    Args:
        time_str (str): Time string in format "Jan 29, 2025 @ 04:24:54.863"
        
    Returns:
        datetime: UTC datetime object, None if parsing fails
    """
    try:
        # Remove any trailing timezone indicators (assume UTC)
        time_str = time_str.split(" (UTC)")[0].strip()
        
        # Parse using predefined format and set UTC timezone
        return datetime.strptime(time_str, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError as e:
        print(f"⏰ Time parsing error: {e}")
        print(f"📅 Expected format: {TIMESTAMP_FORMAT} (UTC)")
        return None


def export_index_data(es, index_name, start_time, end_time):
    """
    Export data from specific index within time range to JSONL file.
    
    Args:
        es (Elasticsearch): Elasticsearch client instance
        index_name (str): Name of index to export
        start_time (datetime): Start of time range (UTC)
        end_time (datetime): End of time range (UTC)
        
    Returns:
        bool: True if export successful, False otherwise
    """
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Create safe filename from index name
    safe_name = index_name.replace(":", "_").replace(".", "-")
    filename = os.path.join(output_dir, f"{safe_name}.jsonl")
    
    # Build Elasticsearch query for time range filtering
    query = {
        "query": {
            "range": {
                "@timestamp": {                                # Filter by timestamp field
                    "gte": start_time.isoformat(),            # Greater than or equal to start
                    "lte": end_time.isoformat(),              # Less than or equal to end
                    "format": "strict_date_optional_time"     # ISO 8601 format
                }
            }
        }
    }

    try:
        # Open output file and stream data
        with open(filename, "w") as f:
            count = 0
            # Use scan helper for efficient scrolling through large result sets
            for hit in scan(es, index=index_name, query=query):
                # Write each document as single JSON line
                f.write(json.dumps(hit["_source"]) + "\n")
                count += 1
                
        print(f"✅ Success: {count} documents from {index_name} -> {filename}")
        return True
    except Exception as e:
        print(f"❌ Failed to export {index_name}: {e}")
        return False


def main():
    """
    Main orchestration function that coordinates the data extraction workflow.
    
    Workflow steps:
    1. Connect to Elasticsearch cluster
    2. Discover relevant indices
    3. Present indices for user selection
    4. Get time range from user input
    5. Extract data from selected indices
    """
    # Step 1: Establish connection
    print("\n🔗 Connecting to Elasticsearch...")
    es = connect_elasticsearch()
    
    if not test_connection(es):
        print("🚨 Could not establish connection to Elasticsearch")
        return

    # Step 2: Discover relevant indices
    print("\n🔍 Searching for relevant indices...")
    indices = list_relevant_indices(es, keywords)
    
    if not indices:
        print("🤷 No matching indices found")
        return

    # Step 3: Interactive index selection
    selected_indices = display_indices_selector(indices)
    if not selected_indices:
        print("🚪 Exiting without download")
        return

    # Step 4: Get time range from user
    print("\n🕒 Time Range Selection (UTC)")
    print("💡 Example format: 'Jan 29, 2025 @ 04:24:54.863'")
    start_time = parse_utc_time(input("⏱️  Start time: "))
    end_time = parse_utc_time(input("⏰ End time: "))
    
    # Validate time parameters
    if not all([start_time, end_time]):
        print("⛔ Invalid time parameters")
        return

    # Step 5: Extract data from each selected index
    print("\n⏳ Starting data export...")
    for index in selected_indices:
        export_index_data(es, index, start_time, end_time)

    # Display final time range for confirmation
    print(f'start time: {start_time}')
    print(f'end time: {end_time}')


def main_cli():
    """CLI wrapper for command-line usage with basic argument support."""
    parser = argparse.ArgumentParser(
        description="Elasticsearch Index Downloader for Cybersecurity Data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (default)
  python 1_elastic_index_downloader.py
  
  # Specify custom output directory
  python 1_elastic_index_downloader.py --output-dir ./downloads
        """
    )
    
    parser.add_argument('--output-dir', '-o', 
                       help='Output directory for JSONL files (default: current directory)')
    parser.add_argument('--host',
                       help='Elasticsearch host URL (default: configured host)')
    parser.add_argument('--keywords',
                       help='Comma-separated keywords to filter indices (default: sysmon,network_traffic)')
    
    args = parser.parse_args()
    
    # Override global settings if provided
    global output_dir, es_host, keywords
    
    if args.output_dir:
        output_dir = args.output_dir
        
    if args.host:
        es_host = args.host
        
    if args.keywords:
        keywords = [kw.strip() for kw in args.keywords.split(',')]
    
    # Run main workflow
    try:
        main()
    except KeyboardInterrupt:
        print("\n⏹️  Extraction cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main_cli()