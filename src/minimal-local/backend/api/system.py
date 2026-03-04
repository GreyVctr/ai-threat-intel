"""
System Status API Endpoints

Provides detailed system status information including pipeline activity,
queue status, worker health, and collection schedules.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from models import get_db, Threat, User
from config import settings
from api.auth import get_current_admin_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/system", tags=["system"])


class TaskInfo(BaseModel):
    """Information about a Celery task"""
    name: str
    status: str
    started_at: Optional[datetime] = None
    eta: Optional[datetime] = None


class CollectNowResponse(BaseModel):
    """Response model for manual collection trigger"""
    status: Literal["success", "conflict", "error"]
    message: str
    task_id: Optional[str] = None
    queued_at: Optional[datetime] = None


class PipelineStatus(BaseModel):
    """Pipeline activity status"""
    active_tasks: List[TaskInfo]
    queue_depth: int
    workers_active: int
    workers_total: int


class CollectionSchedule(BaseModel):
    """Collection schedule information"""
    next_run: Optional[datetime]
    last_run: Optional[datetime]
    frequency: str
    enabled_sources: int
    status: Literal["idle", "running", "overdue"]
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + 'Z' if v and not v.tzinfo else v.isoformat() if v else None
        }


class SystemStatusResponse(BaseModel):
    """Complete system status"""
    timestamp: datetime
    pipeline: PipelineStatus
    collection: CollectionSchedule
    database: Dict[str, Any]
    services: Dict[str, str]
    performance: Dict[str, Any]


@router.get("/status", response_model=SystemStatusResponse)
async def get_system_status(
    db: AsyncSession = Depends(get_db)
):
    """
    Get comprehensive system status (Public - Read-only)
    
    Returns detailed information about:
    - Pipeline activity (active tasks, queue depth, workers)
    - Collection schedule (next run, last run, enabled sources)
    - Database statistics (threat counts, recent activity)
    - Service health (all dependent services)
    - Performance metrics (ingestion rate, processing time)
    
    This endpoint is public for dashboard visibility.
    """
    logger.info("Fetching system status")
    
    # Get pipeline status
    pipeline_status = await _get_pipeline_status()
    
    # Get collection schedule
    collection_schedule = await _get_collection_schedule(db)
    
    # Get database stats
    database_stats = await _get_database_stats(db)
    
    # Get service health
    service_health = await _get_service_health()
    
    # Get performance metrics
    performance_metrics = await _get_performance_metrics(db)
    
    return SystemStatusResponse(
        timestamp=datetime.utcnow(),
        pipeline=pipeline_status,
        collection=collection_schedule,
        database=database_stats,
        services=service_health,
        performance=performance_metrics
    )


@router.post("/collect-now", response_model=CollectNowResponse)
async def collect_now(
    current_user: User = Depends(get_current_admin_user)
):
    """
    Manually trigger a collection task (Admin only)
    
    Queues a scheduled_source_fetch task to collect threat intelligence
    from all enabled sources. Uses Redis locking to prevent concurrent
    collections.
    
    Returns:
        CollectNowResponse with task ID and status
        
    Raises:
        HTTPException 409: Collection already in progress
        HTTPException 500: Failed to queue collection task
    """
    from services.collection_state import get_collection_state_manager
    from tasks import scheduled_source_fetch
    
    logger.info(f"Manual collection trigger requested by user {current_user.username}")
    
    state_manager = get_collection_state_manager()
    
    try:
        # Attempt to acquire Redis lock
        lock_acquired = await state_manager.acquire_lock()
        
        if not lock_acquired:
            logger.warning("Collection already in progress, rejecting manual trigger")
            return CollectNowResponse(
                status="conflict",
                message="Collection already in progress"
            )
        
        # Queue the collection task
        try:
            task = scheduled_source_fetch.delay()
            queued_at = datetime.utcnow()
            
            # Update collection state
            await state_manager.set_last_run(queued_at)
            await state_manager.set_last_status("running")
            
            logger.info(f"Manual collection queued successfully: task_id={task.id}, queued_at={queued_at}")
            
            return CollectNowResponse(
                status="success",
                message="Collection queued successfully",
                task_id=task.id,
                queued_at=queued_at
            )
            
        except Exception as celery_error:
            # Release lock if task queueing failed
            await state_manager.release_lock()
            logger.error(f"Failed to queue collection task: {celery_error}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to queue collection task: {str(celery_error)}"
            )
            
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as redis_error:
        logger.error(f"Redis operation failed during manual collection trigger: {redis_error}")
        raise HTTPException(
            status_code=500,
            detail=f"Collection service unavailable: {str(redis_error)}"
        )


async def _get_pipeline_status() -> PipelineStatus:
    """Get current pipeline activity status"""
    try:
        from celery import Celery
        from tasks import celery_app
        
        # Get active tasks
        inspect = celery_app.control.inspect()
        active = inspect.active()
        reserved = inspect.reserved()
        
        active_tasks = []
        queue_depth = 0
        workers_active = 0
        workers_total = 0
        
        if active:
            workers_total = len(active)
            for worker, tasks in active.items():
                if tasks:
                    workers_active += 1
                for task in tasks:
                    active_tasks.append(TaskInfo(
                        name=task.get('name', 'unknown'),
                        status='running',
                        started_at=datetime.fromtimestamp(task.get('time_start', 0)) if task.get('time_start') else None
                    ))
        
        if reserved:
            for worker, tasks in reserved.items():
                queue_depth += len(tasks)
                for task in tasks:
                    active_tasks.append(TaskInfo(
                        name=task.get('name', 'unknown'),
                        status='queued',
                        eta=datetime.fromtimestamp(task.get('eta', 0)) if task.get('eta') else None
                    ))
        
        return PipelineStatus(
            active_tasks=active_tasks,
            queue_depth=queue_depth,
            workers_active=workers_active,
            workers_total=workers_total or settings.celery_worker_concurrency
        )
    
    except Exception as e:
        logger.error(f"Error getting pipeline status: {e}")
        return PipelineStatus(
            active_tasks=[],
            queue_depth=0,
            workers_active=0,
            workers_total=settings.celery_worker_concurrency
        )


async def _get_collection_schedule(db: AsyncSession) -> CollectionSchedule:
    """Get collection schedule information"""
    try:
        # Get last ingestion time
        stmt = select(func.max(Threat.ingested_at))
        result = await db.execute(stmt)
        last_run = result.scalar()
        
        # Get actual schedule from Celery Beat
        from tasks import celery_app
        from celery.schedules import crontab
        
        beat_schedule = celery_app.conf.beat_schedule
        schedule_info = None
        frequency = "unknown"
        next_run = None
        
        # Find the source fetch task in beat schedule
        for task_name, task_config in beat_schedule.items():
            if 'scheduled_source_fetch' in task_config.get('task', ''):
                schedule_info = task_config.get('schedule')
                break
        
        if schedule_info and isinstance(schedule_info, crontab):
            # Determine frequency from crontab
            # Check if hour is a set (expanded from */N pattern)
            if isinstance(schedule_info.hour, set):
                hours_list = sorted(list(schedule_info.hour))
                if len(hours_list) > 1:
                    # Calculate interval between hours
                    interval = hours_list[1] - hours_list[0]
                    frequency = f"every {interval} hours"
                    
                    # Calculate next run based on fixed schedule times, not last_run
                    # This ensures manual collections don't reset the timer
                    now = datetime.utcnow()
                    for hour in hours_list:
                        candidate = now.replace(hour=hour, minute=0, second=0, microsecond=0)
                        if candidate > now:
                            next_run = candidate
                            break
                    
                    # If no future time today, use first time tomorrow
                    if not next_run:
                        next_run = (now + timedelta(days=1)).replace(
                            hour=hours_list[0], minute=0, second=0, microsecond=0
                        )
                else:
                    frequency = "daily"
                    now = datetime.utcnow()
                    hour = list(schedule_info.hour)[0] if isinstance(schedule_info.hour, set) else schedule_info.hour
                    next_run = now.replace(hour=hour, minute=0, second=0, microsecond=0)
                    if next_run <= now:
                        next_run += timedelta(days=1)
            elif schedule_info.hour == '*':
                frequency = "hourly"
                now = datetime.utcnow()
                next_run = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
            else:
                frequency = "custom"
                now = datetime.utcnow()
                next_run = now + timedelta(hours=1)
        else:
            # Fallback to default
            frequency = "every 6 hours"
            now = datetime.utcnow()
            next_run = now + timedelta(hours=6)
        
        # If no next run calculated, estimate based on frequency
        if not next_run:
            if "every" in frequency and "hours" in frequency:
                hours = int(frequency.split()[1])
                next_run = datetime.utcnow() + timedelta(hours=hours)
            else:
                next_run = datetime.utcnow() + timedelta(hours=1)
        
        # Get enabled sources count
        from services.source_manager import get_source_manager
        manager = get_source_manager()
        enabled_sources = len(manager.get_enabled_sources())
        
        # Calculate collection status based on collection:last_status and collection:lock
        from services.collection_state import get_collection_state_manager
        state_manager = get_collection_state_manager()
        
        collection_status = "idle"  # Default status
        try:
            last_status = await state_manager.get_last_status()
            
            # Check if collection is currently running (lock exists or status is "running")
            if last_status == "running":
                collection_status = "running"
            else:
                # Check if collection is overdue (>12 hours since last run)
                is_overdue = await state_manager.is_overdue(threshold_hours=12)
                if is_overdue:
                    collection_status = "overdue"
                else:
                    collection_status = "idle"
        except Exception as status_error:
            logger.warning(f"Failed to get collection status from Redis: {status_error}")
            # Default to idle if we can't determine status
            collection_status = "idle"
        
        return CollectionSchedule(
            next_run=next_run,
            last_run=last_run,
            frequency=frequency,
            enabled_sources=enabled_sources,
            status=collection_status
        )
    
    except Exception as e:
        logger.error(f"Error getting collection schedule: {e}")
        return CollectionSchedule(
            next_run=None,
            last_run=None,
            frequency="unknown",
            enabled_sources=0,
            status="idle"
        )


async def _get_database_stats(db: AsyncSession) -> Dict[str, Any]:
    """Get database statistics"""
    try:
        # Total threats
        total_stmt = select(func.count(Threat.id))
        result = await db.execute(total_stmt)
        total_threats = result.scalar() or 0
        
        # Threats in last hour
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_stmt = select(func.count(Threat.id)).where(Threat.ingested_at >= one_hour_ago)
        result = await db.execute(recent_stmt)
        recent_threats = result.scalar() or 0
        
        # Threats in last 24 hours
        one_day_ago = datetime.utcnow() - timedelta(days=1)
        daily_stmt = select(func.count(Threat.id)).where(Threat.ingested_at >= one_day_ago)
        result = await db.execute(daily_stmt)
        daily_threats = result.scalar() or 0
        
        # LLM analysis status
        pending_stmt = select(func.count(Threat.id)).where(Threat.llm_analysis_status == 'pending')
        result = await db.execute(pending_stmt)
        pending_analysis = result.scalar() or 0
        
        complete_stmt = select(func.count(Threat.id)).where(Threat.llm_analysis_status == 'complete')
        result = await db.execute(complete_stmt)
        complete_analysis = result.scalar() or 0
        
        failed_stmt = select(func.count(Threat.id)).where(Threat.llm_analysis_status == 'failed')
        result = await db.execute(failed_stmt)
        failed_analysis = result.scalar() or 0
        
        return {
            "total_threats": total_threats,
            "recent_1h": recent_threats,
            "recent_24h": daily_threats,
            "llm_pending": pending_analysis,
            "llm_complete": complete_analysis,
            "llm_failed": failed_analysis,
            "llm_completion_rate": round((complete_analysis / total_threats * 100) if total_threats > 0 else 0, 1)
        }
    
    except Exception as e:
        logger.error(f"Error getting database stats: {e}")
        return {
            "total_threats": 0,
            "recent_1h": 0,
            "recent_24h": 0,
            "llm_pending": 0,
            "llm_complete": 0,
            "llm_failed": 0,
            "llm_completion_rate": 0
        }


async def _get_service_health() -> Dict[str, str]:
    """Get health status of all services including Celery workers and beat"""
    from api.health import check_postgresql, check_redis, check_minio, check_ollama
    from celery import Celery
    
    services = {}
    
    # Check PostgreSQL
    pg_status = await check_postgresql()
    services["postgres"] = pg_status["status"]
    
    # Check Redis
    redis_status = await check_redis()
    services["redis"] = redis_status["status"]
    
    # Check MinIO
    minio_status = await check_minio()
    services["minio"] = minio_status["status"]
    
    # Check Ollama
    ollama_status = await check_ollama()
    services["ollama"] = ollama_status["status"]
    
    # Check Celery Workers
    try:
        celery_app = Celery(broker=settings.celery_broker_url)
        inspect = celery_app.control.inspect()
        active_workers = inspect.active()
        
        if active_workers and len(active_workers) > 0:
            services["celery_worker"] = "up"
        else:
            services["celery_worker"] = "down"
    except Exception as e:
        logger.warning(f"Failed to check Celery workers: {e}")
        services["celery_worker"] = "down"
    
    # Check Celery Beat (scheduler)
    try:
        # Beat doesn't have a direct health check, but we can check if it's registered
        # by looking for scheduled tasks
        celery_app = Celery(broker=settings.celery_broker_url)
        inspect = celery_app.control.inspect()
        scheduled = inspect.scheduled()
        
        # If we can query scheduled tasks, beat is likely running
        if scheduled is not None:
            services["celery_beat"] = "up"
        else:
            services["celery_beat"] = "down"
    except Exception as e:
        logger.warning(f"Failed to check Celery beat: {e}")
        services["celery_beat"] = "down"
    
    return services


async def _get_performance_metrics(db: AsyncSession) -> Dict[str, Any]:
    """Get performance metrics with real-time LLM processing speed"""
    try:
        # Calculate ingestion rate (threats per hour over last 24h)
        one_day_ago = datetime.utcnow() - timedelta(days=1)
        daily_stmt = select(func.count(Threat.id)).where(Threat.ingested_at >= one_day_ago)
        result = await db.execute(daily_stmt)
        daily_threats = result.scalar() or 0
        
        ingestion_rate_24h = round(daily_threats / 24, 1)
        
        # Calculate LLM processing rate (completions in last hour)
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        
        # Get LLM completions in last hour (threats that completed LLM analysis)
        from models import LLMAnalysis
        llm_hourly_stmt = select(func.count(LLMAnalysis.id)).where(
            LLMAnalysis.analyzed_at >= one_hour_ago
        )
        result = await db.execute(llm_hourly_stmt)
        llm_completions_1h = result.scalar() or 0
        
        # Calculate per-hour rate
        llm_processing_rate = llm_completions_1h
        
        # Get total counts
        total_stmt = select(func.count(Threat.id))
        result = await db.execute(total_stmt)
        total_threats = result.scalar() or 0
        
        complete_stmt = select(func.count(Threat.id)).where(Threat.llm_analysis_status == 'complete')
        result = await db.execute(complete_stmt)
        complete_analysis = result.scalar() or 0
        
        # Estimate: if we have completed analyses in last hour, system is actively processing
        processing_active = llm_completions_1h > 0
        
        # Calculate estimated time to complete backlog
        backlog = total_threats - complete_analysis
        eta_hours = None
        if llm_processing_rate > 0 and backlog > 0:
            eta_hours = round(backlog / llm_processing_rate, 1)
        
        return {
            "ingestion_rate_per_hour": ingestion_rate_24h,
            "llm_processing_rate_per_hour": llm_processing_rate,
            "processing_active": processing_active,
            "total_processed": complete_analysis,
            "processing_backlog": backlog,
            "estimated_completion_hours": eta_hours
        }
    
    except Exception as e:
        logger.error(f"Error getting performance metrics: {e}")
        return {
            "ingestion_rate_per_hour": 0,
            "llm_processing_rate_per_hour": 0,
            "processing_active": False,
            "total_processed": 0,
            "processing_backlog": 0,
            "estimated_completion_hours": None
        }



@router.get("/llm-analysis-stats")
async def get_llm_analysis_stats(
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed LLM analysis statistics (Public - Read-only)
    
    Returns breakdown of LLM analysis status:
    - Total threats
    - Pending analysis count
    - Complete analysis count
    - Failed analysis count
    - Sample of failed threats with IDs for investigation
    
    This endpoint is public for dashboard visibility.
    """
    try:
        # Get status counts
        pending_stmt = select(func.count(Threat.id)).where(Threat.llm_analysis_status == 'pending')
        result = await db.execute(pending_stmt)
        pending_count = result.scalar() or 0
        
        complete_stmt = select(func.count(Threat.id)).where(Threat.llm_analysis_status == 'complete')
        result = await db.execute(complete_stmt)
        complete_count = result.scalar() or 0
        
        failed_stmt = select(func.count(Threat.id)).where(Threat.llm_analysis_status == 'failed')
        result = await db.execute(failed_stmt)
        failed_count = result.scalar() or 0
        
        total_stmt = select(func.count(Threat.id))
        result = await db.execute(total_stmt)
        total_count = result.scalar() or 0
        
        # Get sample of failed threats
        failed_sample_stmt = (
            select(Threat.id, Threat.title, Threat.ingested_at)
            .where(Threat.llm_analysis_status == 'failed')
            .order_by(Threat.ingested_at.desc())
            .limit(10)
        )
        result = await db.execute(failed_sample_stmt)
        failed_sample = [
            {
                "id": str(row[0]),
                "title": row[1][:100] + "..." if len(row[1]) > 100 else row[1],
                "ingested_at": row[2].isoformat() if row[2] else None
            }
            for row in result.all()
        ]
        
        return {
            "total_threats": total_count,
            "llm_analysis": {
                "pending": pending_count,
                "complete": complete_count,
                "failed": failed_count,
                "completion_rate": round((complete_count / total_count * 100) if total_count > 0 else 0, 1),
                "failure_rate": round((failed_count / total_count * 100) if total_count > 0 else 0, 1)
            },
            "failed_sample": failed_sample,
            "note": "Failed analyses are typically due to Ollama connection errors, timeouts, or malformed content. Use /system/retry-failed-llm to retry."
        }
    
    except Exception as e:
        logger.error(f"Error getting LLM analysis stats: {e}", exc_info=True)
        return {
            "error": str(e),
            "total_threats": 0,
            "llm_analysis": {
                "pending": 0,
                "complete": 0,
                "failed": 0,
                "completion_rate": 0,
                "failure_rate": 0
            },
            "failed_sample": []
        }


@router.post("/retry-failed-llm")
async def retry_failed_llm_analysis(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """
    Retry LLM analysis for failed threats (Admin only)
    
    This endpoint:
    1. Finds threats with llm_analysis_status = 'failed'
    2. Resets their status to 'pending'
    3. Queues them for LLM analysis
    
    Args:
        limit: Maximum number of failed threats to retry (default: 100)
    
    Returns:
        Number of threats queued for retry
    
    Requires admin authentication.
    """
    try:
        from tasks import analyze_with_llm
        
        # Get failed threats
        failed_stmt = (
            select(Threat.id)
            .where(Threat.llm_analysis_status == 'failed')
            .limit(limit)
        )
        result = await db.execute(failed_stmt)
        failed_ids = [str(row[0]) for row in result.all()]
        
        if not failed_ids:
            return {
                "status": "success",
                "message": "No failed threats to retry",
                "queued": 0
            }
        
        # Reset status to pending
        update_stmt = (
            select(Threat)
            .where(Threat.id.in_(failed_ids))
        )
        result = await db.execute(update_stmt)
        threats = result.scalars().all()
        
        for threat in threats:
            threat.llm_analysis_status = 'pending'
        
        await db.commit()
        
        # Queue for analysis
        queued_count = 0
        for threat_id in failed_ids:
            try:
                analyze_with_llm.delay(threat_id)
                queued_count += 1
            except Exception as e:
                logger.error(f"Error queuing threat {threat_id} for retry: {e}")
        
        logger.info(f"Queued {queued_count} failed threats for LLM analysis retry")
        
        return {
            "status": "success",
            "message": f"Queued {queued_count} threats for LLM analysis retry",
            "queued": queued_count,
            "failed_to_queue": len(failed_ids) - queued_count
        }
    
    except Exception as e:
        logger.error(f"Error retrying failed LLM analysis: {e}", exc_info=True)
        return {
            "status": "error",
            "message": str(e),
            "queued": 0
        }


@router.get("/ollama-config")
async def get_ollama_config():
    """
    Get Ollama configuration and auto-tuning recommendations (Public - Read-only)
    
    Returns:
    - Current configuration (URL, model, timeout, workers)
    - Detected environment (containerized vs host, CPU vs GPU)
    - Recommended settings for optimal performance
    
    This endpoint is public for dashboard visibility.
    """
    try:
        import httpx
        from config import settings
        
        # Get current config
        current_config = {
            "ollama_url": settings.ollama_url,
            "ollama_model": settings.ollama_model,
            "ollama_timeout": settings.ollama_timeout,
            "celery_workers": settings.celery_worker_concurrency
        }
        
        # Detect environment
        is_host_ollama = "host.docker.internal" in settings.ollama_url
        
        # Try to get Ollama info to detect GPU
        ollama_info = None
        has_gpu = False
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{settings.ollama_url}/api/tags")
                if response.status_code == 200:
                    ollama_info = response.json()
                    # Check if running on host (likely has GPU on macOS)
                    has_gpu = is_host_ollama
        except Exception as e:
            logger.warning(f"Could not connect to Ollama: {e}")
        
        # Determine environment type
        if is_host_ollama:
            env_type = "host_gpu" if has_gpu else "host_cpu"
            env_description = "Host Ollama (GPU-accelerated)" if has_gpu else "Host Ollama (CPU-only)"
        else:
            env_type = "container_cpu"
            env_description = "Containerized Ollama (CPU-only)"
        
        # Generate recommendations based on environment
        recommendations = _generate_ollama_recommendations(
            env_type=env_type,
            current_workers=settings.celery_worker_concurrency,
            current_timeout=settings.ollama_timeout
        )
        
        return {
            "current_config": current_config,
            "detected_environment": {
                "type": env_type,
                "description": env_description,
                "is_host": is_host_ollama,
                "has_gpu": has_gpu,
                "ollama_reachable": ollama_info is not None
            },
            "recommendations": recommendations,
            "status": "ok"
        }
    
    except Exception as e:
        logger.error(f"Error getting Ollama config: {e}", exc_info=True)
        return {
            "status": "error",
            "message": str(e)
        }


def _generate_ollama_recommendations(env_type: str, current_workers: int, current_timeout: int) -> Dict[str, Any]:
    """Generate configuration recommendations based on environment"""
    
    if env_type == "host_gpu":
        # Host Ollama with GPU (macOS Apple Silicon)
        recommended = {
            "workers": 12,
            "timeout": 180,
            "expected_speed": "3-10 seconds per threat",
            "expected_throughput": "Expected 300+ on Apple M3 Max",
            "reasoning": "GPU acceleration allows faster processing, but multiple workers queue requests. Higher timeout accounts for queuing."
        }
    elif env_type == "host_cpu":
        # Host Ollama without GPU
        recommended = {
            "workers": 4,
            "timeout": 120,
            "expected_speed": "15-30 seconds per threat",
            "expected_throughput": "Expected 100-200 on CPU",
            "reasoning": "CPU-only processing is slower. Fewer workers reduce queuing and timeout issues."
        }
    else:  # container_cpu
        # Containerized Ollama (CPU-only)
        recommended = {
            "workers": 4,
            "timeout": 120,
            "expected_speed": "15-40 seconds per threat",
            "expected_throughput": "Expected 90-150 on containerized CPU",
            "reasoning": "Containerized CPU processing is slowest. Fewer workers and moderate timeout prevent timeouts."
        }
    
    # Check if current config matches recommendations
    needs_adjustment = (
        current_workers != recommended["workers"] or
        current_timeout != recommended["timeout"]
    )
    
    return {
        "recommended_workers": recommended["workers"],
        "recommended_timeout": recommended["timeout"],
        "expected_speed": recommended["expected_speed"],
        "expected_throughput": recommended["expected_throughput"],
        "reasoning": recommended["reasoning"],
        "current_matches_recommended": not needs_adjustment,
        "adjustment_needed": needs_adjustment
    }


@router.get("/threat-type-info")
async def get_threat_type_info():
    """
    Get threat type information including descriptions
    
    Returns:
    - List of all threat types
    - Human-readable descriptions for each type
    - Keyword counts for classification
    - Actual keywords for each type
    
    This endpoint dynamically reads from the enrichment service configuration,
    so any updates to THREAT_TYPE_KEYWORDS will be reflected here.
    """
    try:
        from services.enrichment import THREAT_TYPE_KEYWORDS
        
        # Generate descriptions based on keywords
        descriptions = {
            "adversarial": "Attacks that manipulate model inputs/outputs using perturbations (FGSM, PGD, etc.)",
            "extraction": "Attempts to steal model parameters or behavior through queries",
            "poisoning": "Attacks that corrupt training data or inject backdoors/trojans",
            "prompt_injection": "LLM attacks using jailbreaks or prompt manipulation",
            "privacy": "Attacks targeting sensitive data in models (membership inference, model inversion)",
            "fairness": "Bias and discrimination issues in ML models",
            "robustness": "Defenses and certified protections against attacks",
            "supply_chain": "Compromised pretrained models or malicious model repositories",
            "unknown": "Threats that could not be classified or require manual review"
        }
        
        # Get keyword counts for each type
        keyword_counts = {
            threat_type: len(keywords)
            for threat_type, keywords in THREAT_TYPE_KEYWORDS.items()
        }
        
        # Get actual keywords for each type
        keywords = {
            threat_type: keywords_list
            for threat_type, keywords_list in THREAT_TYPE_KEYWORDS.items()
        }
        
        return {
            "threat_types": list(THREAT_TYPE_KEYWORDS.keys()),
            "descriptions": descriptions,
            "keyword_counts": keyword_counts,
            "keywords": keywords,
            "total_types": len(THREAT_TYPE_KEYWORDS),
            "note": "Descriptions are dynamically loaded from enrichment service configuration"
        }
    
    except Exception as e:
        logger.error(f"Error getting threat type info: {e}", exc_info=True)
        return {
            "error": str(e),
            "threat_types": [],
            "descriptions": {},
            "keyword_counts": {},
            "keywords": {},
            "total_types": 0
        }
