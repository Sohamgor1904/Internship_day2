import asyncio
import httpx
import argparse
import time
from typing import Dict, Any
from config.settings import settings
from src.ingestion.mapper import OCSFDataIngestor

async def producer(queue: asyncio.Queue, dataset: str, limit: int):
    """Producer task: loads records from raw directories, normalizes to OCSF, and adds to queue."""
    print(f"[Producer] Reading logs from dataset '{dataset}'...")
    ingestor = OCSFDataIngestor(
        cic_dir=settings.CIC_DATA_DIR,
        unsw_dir=settings.UNSW_DATA_DIR,
        cse_dir=settings.CSE_DATA_DIR
    )
    
    events_generator = ingestor.stream_dataset(dataset, max_records=limit)
    
    count = 0
    for event in events_generator:
        await queue.put(event)
        count += 1
        if count % 100 == 0:
            print(f"[Producer] Queued {count} events...")
            
    print(f"[Producer] Finished queueing {count} total events.")
    # Add None sentinel to signal shutdown to consumer
    await queue.put(None)

async def consumer(queue: asyncio.Queue, api_url: str, delay: float):
    """Consumer task: retrieves OCSF events from the queue and sends them to FastAPI endpoint."""
    print(f"[Consumer] Initializing stream sender client to target {api_url}...")
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        while True:
            event = await queue.get()
            if event is None:
                # Finished stream signal
                queue.task_done()
                break
                
            try:
                # Post the OCSF record to FastAPI detect endpoint
                response = await client.post(api_url, json=event)
                
                if response.status_code == 200:
                    res_json = response.json()
                    is_threat = res_json.get("threat_detected", False)
                    classification = res_json.get("classification", "Benign")
                    layer_reached = res_json.get("layer_reached", 1)
                    
                    if is_threat:
                        l2_prob = res_json.get("layer2", {}).get("threat_probability", 0.0)
                        l3_prob = res_json.get("layer3", {}).get("threat_probability", 0.0)
                        explanations = res_json.get("layer2", {}).get("explanations", [])
                        
                        feat_names = [exp["feature_name"] for exp in explanations]
                        print(
                            f"[ALERT] [Threat Detected!] Type: {classification} | "
                            f"L2 Prob: {l2_prob:.2f} | L3 Prob: {l3_prob:.2f} | "
                            f"Top SHAP reasons: {feat_names}"
                        )
                    else:
                        # Benign flow (triage check results or classifier results)
                        if layer_reached == 1:
                            l1_score = res_json.get("layer1", {}).get("anomaly_score", 0.0)
                            if time.time() % 1.5 < 0.2: 
                                print(f"[Triage] Benign flow dropped by L1 filter. Anomaly score: {l1_score:.2f}")
                        elif layer_reached == 2:
                            l2_prob = res_json.get("layer2", {}).get("threat_probability", 0.0)
                            if time.time() % 1.5 < 0.2:
                                print(f"[Triage] Benign flow dropped by L2 filter. L2 Prob: {l2_prob:.2f}")
                        else:
                            print(f"[Info] Flow reached L3. Classified normal. L3 Prob: {res_json.get('layer3', {}).get('threat_probability', 0.0):.2f}")
                else:
                    print(f"[Error] Failed request to API: HTTP {response.status_code} - {response.text}")
            except Exception as e:
                print(f"[Error] Client post failure: {e}")
                
            queue.task_done()
            await asyncio.sleep(delay)
            
    print("[Consumer] Sent all queued events. Stream sender shutdown.")

async def run_simulation(dataset: str, limit: int, api_url: str, delay: float):
    queue = asyncio.Queue(maxsize=1000)
    
    # Run producer and consumer concurrently
    await asyncio.gather(
        producer(queue, dataset, limit),
        consumer(queue, api_url, delay)
    )

def main():
    parser = argparse.ArgumentParser(description="Async OCSF Log Stream Simulator Client")
    parser.add_argument(
        "--dataset", 
        type=str, 
        default="unsw", 
        choices=["cic", "unsw", "cse"],
        help="Select local dataset to stream (default: unsw)"
    )
    parser.add_argument(
        "--limit", 
        type=int, 
        default=200, 
        help="Number of log records to stream (default: 200)"
    )
    parser.add_argument(
        "--url", 
        type=str, 
        default="http://localhost:8000/api/v1/detect", 
        help="Target FastAPI API endpoint URL (default: http://localhost:8000/api/v1/detect)"
    )
    parser.add_argument(
        "--delay", 
        type=float, 
        default=0.05, 
        help="Delay in seconds between flows to simulate stream (default: 0.05)"
    )
    
    args = parser.parse_args()
    
    print("==============================================")
    print("      OCSF LOG STREAM SIMULATION CLIENT       ")
    print("==============================================")
    
    try:
        asyncio.run(run_simulation(args.dataset, args.limit, args.url, args.delay))
    except KeyboardInterrupt:
        print("\nSimulation aborted by user.")

if __name__ == "__main__":
    main()
