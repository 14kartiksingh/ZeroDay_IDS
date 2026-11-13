import asyncio
import threading
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.services.ids_pipeline import IDSPipelineService

# Global pipeline instance
pipeline = IDSPipelineService(interface_index=12, model_dir="models/model B")
connected_clients = set()
main_event_loop = None


def broadcast_from_thread(payload: dict):
    """Safely schedules a WebSocket broadcast from the background Scapy sniffer thread."""
    if main_event_loop and connected_clients:
        asyncio.run_coroutine_threadsafe(broadcast_json(payload), main_event_loop)


async def broadcast_json(payload: dict):
    disconnected = []
    for ws in list(connected_clients):
        try:
            await ws.send_json(payload)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        connected_clients.discard(ws)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_event_loop
    main_event_loop = asyncio.get_running_loop()
    pipeline.on_event_callback = broadcast_from_thread

    # Start live packet capture in a daemon background thread
    capture_thread = threading.Thread(target=pipeline.run_capture_loop, daemon=True)
    capture_thread.start()
    print("FastAPI + Live ML Detection Engine started on port 8000!")

    yield

    pipeline.stop()
    print("IDS Pipeline stopped.")


app = FastAPI(
    title="ZeroDay IDS — Hybrid ML Detection API",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health_check():
    return {"status": "online", "capturing": pipeline.is_running}


@app.get("/api/stats")
def get_stats():
    return pipeline.get_stats()


@app.get("/api/flows")
def get_flows(limit: int = 50):
    return list(pipeline.recent_flows)[:limit]


@app.get("/api/alerts")
def get_alerts(limit: int = 50):
    return list(pipeline.alerts)[:limit]


@app.get("/api/clusters")
def get_clusters():
    return pipeline.clustering_engine.get_clusters()


@app.post("/api/reset")
def reset_dashboard_state():
    epoch = pipeline.reset()

    # Broadcast a RESET event to ALL connected WebSocket clients so they
    # immediately clear their UI and start filtering by the new epoch,
    # even if the HTTP response hasn't reached the requesting client yet.
    broadcast_from_thread({
        "type": "RESET",
        "epoch": epoch,
        "stats": pipeline.get_stats(),
        "clusters": pipeline.clustering_engine.get_clusters()
    })
    return {"status": "reset_complete", "epoch": epoch}


@app.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)

    # Send initial state snapshot immediately on connect
    await websocket.send_json({
        "type": "INITIAL_STATE",
        "epoch": pipeline.get_stats().get("epoch", 0),
        "stats": pipeline.get_stats(),
        "flows": list(pipeline.recent_flows)[:30],
        "alerts": list(pipeline.alerts)[:30],
        "clusters": pipeline.clustering_engine.get_clusters()
    })

    try:
        while True:
            # Keep connection alive and listen for optional client commands
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.discard(websocket)
