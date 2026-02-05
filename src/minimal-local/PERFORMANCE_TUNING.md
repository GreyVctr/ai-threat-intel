# Performance Tuning Guide

## Overview

This guide explains how to optimize AI Shield Intelligence for your deployment environment, with automatic detection and recommendations for containerized vs host Ollama configurations.

## Quick Status Check

Check your current configuration and get recommendations:

```bash
curl http://localhost:8000/api/v1/system/ollama-config | python3 -m json.tool
```

## Environment Types

### 1. Host Ollama with GPU (Recommended for macOS)

**Detection**: `OLLAMA_URL=http://host.docker.internal:11434`

**Characteristics**:
- Uses Apple Silicon GPU/Neural Engine
- 3-6x faster than CPU-only
- Processing speed: 3-10 seconds per threat
- Throughput: 360-720 threats/hour

**Recommended Settings**:
```bash
# In .env.minimal
OLLAMA_URL=http://host.docker.internal:11434
OLLAMA_TIMEOUT=180

# In docker-compose.minimal.yml
command: celery -A tasks worker --loglevel=info --concurrency=12
```

**Why these settings?**
- **12 workers**: Maximizes throughput with GPU acceleration
- **180s timeout**: Accounts for queuing when multiple workers hit Ollama simultaneously
- GPU processes requests sequentially, so higher concurrency = more queuing

### 2. Host Ollama CPU-only

**Detection**: `OLLAMA_URL=http://host.docker.internal:11434` (no GPU detected)

**Characteristics**:
- CPU-only processing on host
- Processing speed: 15-30 seconds per threat
- Throughput: 120-240 threats/hour

**Recommended Settings**:
```bash
# In .env.minimal
OLLAMA_URL=http://host.docker.internal:11434
OLLAMA_TIMEOUT=120

# In docker-compose.minimal.yml
command: celery -A tasks worker --loglevel=info --concurrency=4
```

**Why these settings?**
- **4 workers**: Reduces queuing and timeout issues
- **120s timeout**: Moderate timeout for CPU processing
- Fewer workers = less contention for CPU resources

### 3. Containerized Ollama (CPU-only)

**Detection**: `OLLAMA_URL=http://ollama:11434`

**Characteristics**:
- Slowest option (containerized + CPU-only)
- Processing speed: 15-40 seconds per threat
- Throughput: 90-180 threats/hour
- Docker on macOS cannot access GPU

**Recommended Settings**:
```bash
# In .env.minimal
OLLAMA_URL=http://ollama:11434
OLLAMA_TIMEOUT=120

# In docker-compose.minimal.yml
command: celery -A tasks worker --loglevel=info --concurrency=4

# Start with containerized Ollama
docker compose -f docker-compose.minimal.yml --env-file .env.minimal --profile ollama-container up -d
```

**Why these settings?**
- **4 workers**: Prevents overwhelming containerized Ollama
- **120s timeout**: Accounts for slower containerized processing
- Containerization adds overhead on top of CPU-only processing

## Current Configuration

Your system is currently configured as:
- **Environment**: Host Ollama with GPU
- **Workers**: 12 (optimal for GPU)
- **Timeout**: 180 seconds (optimal for 12 workers)
- **Expected throughput**: 360-720 threats/hour

## Monitoring Performance

### Real-Time Metrics

The Dashboard now shows:

1. **Ingestion Rate** (24h average): How fast threats are being collected
2. **LLM Processing Rate** (1h actual): How fast LLM analysis is completing
3. **Estimated Completion Time**: When current backlog will be processed

### API Endpoints

```bash
# Get system status with real-time LLM processing rate
curl http://localhost:8000/api/v1/system/status

# Get Ollama configuration and recommendations
curl http://localhost:8000/api/v1/system/ollama-config

# Get LLM analysis statistics
curl http://localhost:8000/api/v1/system/llm-analysis-stats
```

## Troubleshooting

### Symptoms: Timeouts and Failed Analyses

**Problem**: Workers timing out before Ollama can process requests

**Solutions**:
1. **Increase timeout**: Set `OLLAMA_TIMEOUT=180` or higher
2. **Reduce workers**: Lower concurrency to reduce queuing
3. **Check Ollama**: Ensure host Ollama is running (`ollama serve`)

### Symptoms: Slow Processing

**Problem**: LLM processing rate is lower than expected

**Solutions**:
1. **Switch to host Ollama**: Use GPU acceleration on macOS
2. **Increase workers**: If using GPU, increase to 12 workers
3. **Check GPU usage**: Monitor Activity Monitor to verify GPU is active

### Symptoms: High CPU Usage

**Problem**: System using too much CPU

**Solutions**:
1. **Reduce workers**: Lower concurrency to 4-8
2. **Use host Ollama**: Offload processing to host with GPU
3. **Adjust collection schedule**: Reduce frequency in `backend/tasks.py`

## Auto-Tuning (Future Enhancement)

The system now detects your environment and provides recommendations. Future enhancements will include:

1. **Automatic configuration**: System adjusts timeout/workers based on detected environment
2. **Dynamic scaling**: Workers scale up/down based on queue depth
3. **Performance learning**: System learns optimal settings over time

## Configuration Files

### Environment Variables (.env.minimal)

```bash
# Ollama Configuration
OLLAMA_URL=http://host.docker.internal:11434  # or http://ollama:11434
OLLAMA_MODEL=qwen2.5:7b
OLLAMA_TIMEOUT=180  # Adjust based on environment

# Other settings...
POSTGRES_PASSWORD=test_password_123
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=test_password_123
```

### Docker Compose (docker-compose.minimal.yml)

```yaml
celery_worker:
  environment:
    OLLAMA_URL: ${OLLAMA_URL:-http://ollama:11434}
    OLLAMA_TIMEOUT: ${OLLAMA_TIMEOUT:-60}
  command: celery -A tasks worker --loglevel=info --concurrency=12
```

## Summary

- **Host Ollama + GPU**: 12 workers, 180s timeout → 360-720 threats/hour
- **Host Ollama + CPU**: 4 workers, 120s timeout → 120-240 threats/hour
- **Container + CPU**: 4 workers, 120s timeout → 90-180 threats/hour

Use the `/api/v1/system/ollama-config` endpoint to check your current configuration and get personalized recommendations.
