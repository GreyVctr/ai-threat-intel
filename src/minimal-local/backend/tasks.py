"""
AI Shield Intelligence - Celery Tasks

Asynchronous task processing for:
- Source fetching and data collection
- Threat ingestion and deduplication
- Enrichment (classification, entity extraction, MITRE mapping)
- LLM analysis
- Alert notifications
"""

import logging
from celery import Celery
from celery.schedules import crontab
from celery.signals import task_prerun, task_postrun, task_failure

from config import settings
from logging_config import setup_logging, get_logger, log_with_context

# Configure structured logging
setup_logging(
    log_level=settings.log_level,
    json_format=settings.environment == "production"
)

logger = get_logger(__name__)

# Create Celery app
celery_app = Celery(
    'ai_shield',
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend
)

# Configure Celery
celery_app.conf.update(
    # Serialization
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    
    # Timezone
    timezone='UTC',
    enable_utc=True,
    
    # Worker configuration
    worker_concurrency=settings.celery_worker_concurrency,
    worker_prefetch_multiplier=1,  # Fetch one task at a time
    worker_max_tasks_per_child=100,  # Restart worker after 100 tasks to prevent memory leaks
    
    # Task configuration
    task_acks_late=True,  # Acknowledge tasks after completion
    task_reject_on_worker_lost=True,  # Reject tasks if worker dies
    task_track_started=True,  # Track when tasks start
    
    # Retry configuration
    task_default_retry_delay=60,  # 1 minute
    task_max_retries=3,
    
    # Result backend configuration
    result_expires=3600,  # Results expire after 1 hour
    result_backend_transport_options={
        'master_name': 'mymaster',
    },
    
    # Beat schedule for periodic tasks
    beat_schedule={
        'fetch-sources-every-12-hours': {
            'task': 'tasks.scheduled_source_fetch',
            'schedule': crontab(minute=0, hour='*/12'),  # Every 12 hours at minute 0
            'options': {'expires': 43000}  # Task expires after 11.9 hours
        },
    },
)

logger.info("Celery app configured successfully")
logger.info(f"Broker: {settings.celery_broker_url}")
logger.info(f"Backend: {settings.celery_result_backend}")
logger.info(f"Worker concurrency: {settings.celery_worker_concurrency}")


# ============================================================================
# CELERY SIGNAL HANDLERS FOR LOGGING
# ============================================================================

@task_prerun.connect
def task_prerun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, **extra):
    """Log when a task starts"""
    log_with_context(
        logger, "info", "Task started",
        task_name=task.name if task else sender,
        task_id=task_id,
        args=str(args)[:100] if args else None,  # Truncate long args
        kwargs=str(kwargs)[:100] if kwargs else None
    )


@task_postrun.connect
def task_postrun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, retval=None, **extra):
    """Log when a task completes"""
    log_with_context(
        logger, "info", "Task completed",
        task_name=task.name if task else sender,
        task_id=task_id,
        result=str(retval)[:100] if retval else None  # Truncate long results
    )


@task_failure.connect
def task_failure_handler(sender=None, task_id=None, exception=None, args=None, kwargs=None, traceback=None, einfo=None, **extra):
    """Log when a task fails"""
    log_with_context(
        logger, "error", "Task failed",
        task_name=sender.name if sender else "unknown",
        task_id=task_id,
        exception_type=type(exception).__name__ if exception else None,
        exception_message=str(exception) if exception else None,
        args=str(args)[:100] if args else None
    )
    if traceback:
        logger.error(f"Task traceback: {traceback}")


# ============================================================================
# SOURCE FETCHING TASKS
# ============================================================================

@celery_app.task(
    name='tasks.fetch_source',
    bind=True,
    max_retries=3,
    default_retry_delay=60
)
def fetch_source(self, source_name: str) -> dict:
    """
    Fetch data from a configured intelligence source
    
    This task loads the source configuration, selects the appropriate
    collector based on source type, and fetches data from the source.
    
    Args:
        source_name: Name of the source to fetch from
        
    Returns:
        Dictionary with fetch results:
        {
            'source_name': str,
            'status': 'success' | 'error',
            'items_fetched': int,
            'error': str (if status is 'error')
        }
        
    Raises:
        Retry: If fetch fails and retries are available
    """
    import asyncio
    from services.source_manager import get_source_manager
    from collectors.rss import RSSCollector
    from collectors.api import ArxivAPICollector, GitHubAPICollector
    from collectors.scraper import WebScraperCollector
    
    log_with_context(logger, "info", "Fetching source", source_name=source_name)
    
    try:
        # Load source configuration
        source_manager = get_source_manager()
        source = source_manager.get_source(source_name)
        
        if not source:
            error_msg = f"Source not found: {source_name}"
            log_with_context(logger, "error", "Source not found", source_name=source_name)
            return {
                'source_name': source_name,
                'status': 'error',
                'items_fetched': 0,
                'error': error_msg
            }
        
        if not source.enabled:
            log_with_context(logger, "info", "Source disabled", source_name=source_name)
            return {
                'source_name': source_name,
                'status': 'skipped',
                'items_fetched': 0,
                'error': 'Source is disabled'
            }
        
        # Prepare source config dict for collector
        source_config = {
            'url': source.url,
            'name': source.name,
            'type': source.type,
            'config': source.config or {}
        }
        
        # Select appropriate collector based on source type
        collector = None
        if source.type == 'rss':
            collector = RSSCollector(source_config)
        elif source.type == 'api':
            # Determine which API collector to use based on URL
            if 'arxiv' in source.url.lower():
                collector = ArxivAPICollector(source_config)
            elif 'github' in source.url.lower():
                collector = GitHubAPICollector(source_config)
            else:
                error_msg = f"Unknown API source: {source.url}"
                log_with_context(logger, "error", "Unknown API source", 
                               source_name=source_name, source_url=source.url)
                return {
                    'source_name': source_name,
                    'status': 'error',
                    'items_fetched': 0,
                    'error': error_msg
                }
        elif source.type == 'web_scrape':
            collector = WebScraperCollector(source_config)
        else:
            error_msg = f"Unknown source type: {source.type}"
            log_with_context(logger, "error", "Unknown source type", 
                           source_name=source_name, source_type=source.type)
            return {
                'source_name': source_name,
                'status': 'error',
                'items_fetched': 0,
                'error': error_msg
            }
        
        # Fetch data from source (async)
        log_with_context(logger, "info", "Using collector", 
                        source_name=source_name, collector_type=source.type)
        
        async def _fetch():
            return await collector.fetch()
        
        items = asyncio.run(_fetch())
        
        log_with_context(logger, "info", "Fetch completed", 
                        source_name=source_name, items_count=len(items))
        
        # Queue ingestion tasks for each item
        for item in items:
            # Convert CollectorResult to dict
            item_dict = {
                'title': item.title,
                'description': item.description,
                'content': item.content,
                'url': item.url,
                'authors': item.authors,
                'published_at': item.published_at.isoformat() if item.published_at else None,
                'metadata': item.metadata,
                'source': source_name,
                'source_type': source.type
            }
            
            # Queue ingestion task
            ingest_threat.delay(item_dict)
            logger.debug(f"Queued ingestion task for item from {source_name}")
        
        return {
            'source_name': source_name,
            'status': 'success',
            'items_fetched': len(items),
            'error': None
        }
        
    except Exception as e:
        error_msg = f"Error fetching source {source_name}: {str(e)}"
        log_with_context(logger, "error", "Fetch error", 
                        source_name=source_name, 
                        exception_type=type(e).__name__,
                        exception_message=str(e))
        logger.error(error_msg, exc_info=True)
        
        # Retry if we have retries left
        if self.request.retries < self.max_retries:
            log_with_context(logger, "info", "Retrying fetch", 
                           source_name=source_name, 
                           retry_attempt=self.request.retries + 1,
                           max_retries=self.max_retries)
            raise self.retry(exc=e)
        
        return {
            'source_name': source_name,
            'status': 'error',
            'items_fetched': 0,
            'error': error_msg
        }


@celery_app.task(
    name='tasks.scheduled_source_fetch',
    bind=True
)
def scheduled_source_fetch(self) -> dict:
    """
    Scheduled task to fetch from all enabled sources
    
    This task is triggered by Celery Beat on a schedule (hourly by default).
    It fetches from all enabled sources and queues individual fetch tasks.
    
    Manages collection state in Redis:
    - Updates collection:last_run at task start
    - Sets collection:last_status to "running" at start
    - Sets collection:last_status to "success" on completion
    - Sets collection:last_status to "failed" on error
    - Releases collection lock in all cases
    
    Returns:
        Dictionary with fetch results:
        {
            'status': 'success' | 'error',
            'sources_queued': int,
            'sources_skipped': int,
            'errors': list
        }
    """
    import asyncio
    from datetime import datetime
    from services.source_manager import get_source_manager
    from services.collection_state import CollectionStateManager
    
    logger.info("Starting scheduled source fetch")
    
    # Main async function to handle all async operations in a single event loop
    async def run_collection():
        # Create a fresh instance each time to avoid stale event loop references
        # (asyncio.run() closes the loop, invalidating cached Redis clients)
        state_manager = CollectionStateManager()
        
        try:
            # Update collection state at task start
            await state_manager.set_last_run(datetime.utcnow())
            await state_manager.set_last_status("running")
            logger.info("Updated collection state to running")
            
            # Load source configuration (sync operation)
            source_manager = get_source_manager()
            enabled_sources = source_manager.get_enabled_sources()
            
            logger.info(f"Found {len(enabled_sources)} enabled sources")
            
            queued = 0
            skipped = 0
            errors = []
            
            for source in enabled_sources:
                try:
                    # Queue fetch task for each enabled source
                    fetch_source.delay(source.name)
                    queued += 1
                    logger.info(f"Queued fetch task for source: {source.name}")
                    
                except Exception as e:
                    error_msg = f"Failed to queue fetch task for {source.name}: {str(e)}"
                    logger.error(error_msg)
                    errors.append(error_msg)
                    skipped += 1
            
            logger.info(f"Scheduled source fetch complete: {queued} queued, {skipped} skipped")
            
            # Update status to success on completion
            await state_manager.set_last_status("success")
            logger.info("Updated collection state to success")
            
            # Release lock
            await state_manager.release_lock()
            
            return {
                'status': 'success' if not errors else 'partial',
                'sources_queued': queued,
                'sources_skipped': skipped,
                'errors': errors
            }
            
        except Exception as e:
            error_msg = f"Error in scheduled source fetch: {str(e)}"
            logger.error(error_msg, exc_info=True)
            
            try:
                # Update status to failed on error
                await state_manager.set_last_status("failed")
                logger.info("Updated collection state to failed")
            except Exception as state_error:
                logger.error(f"Failed to update collection state to failed: {state_error}")
            
            finally:
                try:
                    # Release lock in finally block to ensure it's always released
                    await state_manager.release_lock()
                except Exception as lock_error:
                    logger.error(f"Failed to release collection lock: {lock_error}")
            
            return {
                'status': 'error',
                'sources_queued': 0,
                'sources_skipped': 0,
                'errors': [error_msg]
            }
        finally:
            await state_manager.close()
    
    # Run the async function in a single event loop
    return asyncio.run(run_collection())


# ============================================================================
# INGESTION TASKS
# ============================================================================

@celery_app.task(
    name='tasks.ingest_threat',
    bind=True,
    max_retries=3,
    default_retry_delay=60
)
def ingest_threat(self, raw_data: dict) -> dict:
    """
    Ingest threat data into the system with dual storage and deduplication.
    
    This task:
    1. Calculates content hash for deduplication
    2. Stores raw data in MinIO object storage
    3. Stores structured data in PostgreSQL
    4. Implements transaction rollback on failure
    
    The ingestion is atomic - both MinIO and PostgreSQL storage must succeed,
    or the entire operation is rolled back.
    
    Args:
        raw_data: Raw threat data from collector with fields:
            - title: str (required)
            - description: str (optional)
            - content: str (optional)
            - source: str (required)
            - url/link: str (optional)
            - authors: list or str (optional)
            - published_at/published/date: datetime or str (optional)
            
    Returns:
        Dictionary with ingestion results:
        {
            'status': 'success' | 'duplicate' | 'error',
            'threat_id': str (UUID) or None,
            'content_hash': str or None,
            'message': str
        }
        
    Raises:
        Retry: If ingestion fails and retries are available
        
    Requirements: 6.16, 6.17, 6.18
    """
    import asyncio
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from services.ingestion import get_ingestion_service
    
    logger.info(f"Ingesting threat from source: {raw_data.get('source', 'Unknown')}")
    
    try:
        # Create async database session
        engine = create_async_engine(settings.database_url, echo=False)
        async_session_maker = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        
        async def _ingest():
            """Async ingestion function"""
            async with async_session_maker() as session:
                try:
                    # Create ingestion service
                    ingestion_service = get_ingestion_service(session)
                    
                    # Perform ingestion
                    result = await ingestion_service.ingest(raw_data)
                    
                    return result
                    
                except Exception as e:
                    logger.error(f"Error in async ingestion: {e}", exc_info=True)
                    raise
                finally:
                    await engine.dispose()
        
        # Run async ingestion
        result = asyncio.run(_ingest())
        
        # Log result
        if result['status'] == 'success':
            logger.info(f"Successfully ingested threat: {result['threat_id']}")
        elif result['status'] == 'duplicate':
            logger.info(f"Duplicate threat detected: {result['threat_id']}")
        else:
            logger.error(f"Ingestion failed: {result['message']}")
        
        # Queue enrichment tasks if ingestion was successful
        if result['status'] == 'success' and result['threat_id']:
            threat_id = result['threat_id']
            
            # Queue complete enrichment task (includes classification, entity extraction, MITRE mapping, severity scoring)
            enrich_threat.delay(threat_id)
            
            logger.info(f"Queued enrichment task for threat: {threat_id}")
        
        return result
        
    except Exception as e:
        error_msg = f"Error ingesting threat: {str(e)}"
        logger.error(error_msg, exc_info=True)
        
        # Retry if we have retries left
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying ingest_threat (attempt {self.request.retries + 1}/{self.max_retries})")
            raise self.retry(exc=e)
        
        return {
            'status': 'error',
            'threat_id': None,
            'content_hash': None,
            'message': error_msg
        }


# ============================================================================
# ENRICHMENT TASKS
# ============================================================================

@celery_app.task(
    name='tasks.enrich_threat',
    bind=True,
    max_retries=3,
    default_retry_delay=60
)
def enrich_threat(self, threat_id: str) -> dict:
    """
    Perform complete enrichment on a threat.
    
    This task performs:
    1. Threat type classification using NLP
    2. Entity extraction (CVEs, frameworks, techniques)
    3. MITRE ATLAS mapping
    4. Severity scoring
    
    The enrichment is designed to handle partial failures - if one step fails,
    the others will still be attempted, and the threat will be marked with
    partial enrichment status.
    
    Args:
        threat_id: UUID of the threat to enrich
        
    Returns:
        Dictionary with enrichment results:
        {
            'status': 'success' | 'partial' | 'error',
            'threat_id': str,
            'threat_type': str or None,
            'severity': int or None,
            'entities_count': int,
            'mappings_count': int,
            'errors': list or None
        }
        
    Raises:
        Retry: If enrichment fails and retries are available
        
    Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8
    """
    import asyncio
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from services.enrichment import EnrichmentService
    
    logger.info(f"Starting enrichment for threat: {threat_id}")
    
    try:
        # Create async database session
        engine = create_async_engine(settings.database_url, echo=False)
        async_session_maker = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        
        async def _enrich():
            """Async enrichment function"""
            async with async_session_maker() as session:
                try:
                    # Create enrichment service
                    enrichment_service = EnrichmentService(session)
                    
                    # Perform enrichment
                    result = await enrichment_service.enrich_threat(threat_id)
                    
                    return result
                    
                except Exception as e:
                    logger.error(f"Error in async enrichment: {e}", exc_info=True)
                    raise
                finally:
                    await engine.dispose()
        
        # Run async enrichment
        result = asyncio.run(_enrich())
        
        # Log result
        if result.get('success'):
            status = 'success' if not result.get('errors') else 'partial'
            logger.info(f"Enrichment completed for threat {threat_id}: {status}")
            
            # Queue LLM analysis if enrichment was successful
            if status == 'success':
                logger.info(f"Queuing LLM analysis for threat: {threat_id}")
                analyze_with_llm.delay(threat_id)
        else:
            logger.error(f"Enrichment failed for threat {threat_id}: {result.get('error')}")
        
        return result
        
    except Exception as e:
        error_msg = f"Error enriching threat {threat_id}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        
        # Retry if we have retries left
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying enrich_threat for {threat_id} (attempt {self.request.retries + 1}/{self.max_retries})")
            raise self.retry(exc=e)
        
        return {
            'success': False,
            'threat_id': threat_id,
            'error': error_msg
        }


@celery_app.task(
    name='tasks.classify_threat',
    bind=True,
    max_retries=3
)
def classify_threat(self, threat_id: str) -> dict:
    """
    Classify threat type using NLP (keyword-based classification).
    
    This is a standalone task for threat type classification only.
    For complete enrichment, use enrich_threat task instead.
    
    Args:
        threat_id: UUID of the threat to classify
        
    Returns:
        Dictionary with classification results:
        {
            'status': 'success' | 'error',
            'threat_id': str,
            'threat_type': str or None,
            'message': str
        }
        
    Requirements: 9.1
    """
    import asyncio
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import select
    from services.enrichment import EnrichmentService
    from models.threat import Threat
    
    logger.info(f"Classifying threat: {threat_id}")
    
    try:
        engine = create_async_engine(settings.database_url, echo=False)
        async_session_maker = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        
        async def _classify():
            async with async_session_maker() as session:
                try:
                    # Fetch threat
                    result = await session.execute(
                        select(Threat).where(Threat.id == threat_id)
                    )
                    threat = result.scalar_one_or_none()
                    
                    if not threat:
                        return {
                            'status': 'error',
                            'threat_id': threat_id,
                            'threat_type': None,
                            'message': 'Threat not found'
                        }
                    
                    # Classify
                    enrichment_service = EnrichmentService(session)
                    content = " ".join(filter(None, [
                        threat.title or "",
                        threat.description or "",
                        threat.content or ""
                    ]))
                    threat_type = await enrichment_service.classify_threat_type(content)
                    
                    # Update threat
                    threat.threat_type = threat_type
                    await session.commit()
                    
                    return {
                        'status': 'success',
                        'threat_id': threat_id,
                        'threat_type': threat_type,
                        'message': f'Classified as {threat_type}'
                    }
                    
                finally:
                    await engine.dispose()
        
        result = asyncio.run(_classify())
        logger.info(f"Classification result for {threat_id}: {result['threat_type']}")
        return result
        
    except Exception as e:
        error_msg = f"Error classifying threat {threat_id}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        
        if self.request.retries < self.max_retries:
            raise self.retry(exc=e)
        
        return {
            'status': 'error',
            'threat_id': threat_id,
            'threat_type': None,
            'message': error_msg
        }


@celery_app.task(
    name='tasks.extract_entities',
    bind=True,
    max_retries=3
)
def extract_entities(self, threat_id: str) -> dict:
    """
    Extract entities (CVEs, frameworks, techniques) from threat.
    
    This is a standalone task for entity extraction only.
    For complete enrichment, use enrich_threat task instead.
    
    Args:
        threat_id: UUID of the threat to extract entities from
        
    Returns:
        Dictionary with extraction results:
        {
            'status': 'success' | 'error',
            'threat_id': str,
            'entities_count': int,
            'message': str
        }
        
    Requirements: 9.2
    """
    import asyncio
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import select
    from services.enrichment import EnrichmentService
    from models.threat import Threat
    
    logger.info(f"Extracting entities for threat: {threat_id}")
    
    try:
        engine = create_async_engine(settings.database_url, echo=False)
        async_session_maker = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        
        async def _extract():
            async with async_session_maker() as session:
                try:
                    # Fetch threat
                    result = await session.execute(
                        select(Threat).where(Threat.id == threat_id)
                    )
                    threat = result.scalar_one_or_none()
                    
                    if not threat:
                        return {
                            'status': 'error',
                            'threat_id': threat_id,
                            'entities_count': 0,
                            'message': 'Threat not found'
                        }
                    
                    # Extract entities
                    enrichment_service = EnrichmentService(session)
                    content = " ".join(filter(None, [
                        threat.title or "",
                        threat.description or "",
                        threat.content or ""
                    ]))
                    entities = await enrichment_service.extract_entities(str(threat.id), content)
                    
                    # Add entities to database
                    for entity in entities:
                        session.add(entity)
                    await session.commit()
                    
                    return {
                        'status': 'success',
                        'threat_id': threat_id,
                        'entities_count': len(entities),
                        'message': f'Extracted {len(entities)} entities'
                    }
                    
                finally:
                    await engine.dispose()
        
        result = asyncio.run(_extract())
        logger.info(f"Extracted {result['entities_count']} entities for {threat_id}")
        return result
        
    except Exception as e:
        error_msg = f"Error extracting entities for {threat_id}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        
        if self.request.retries < self.max_retries:
            raise self.retry(exc=e)
        
        return {
            'status': 'error',
            'threat_id': threat_id,
            'entities_count': 0,
            'message': error_msg
        }


@celery_app.task(
    name='tasks.map_mitre_atlas',
    bind=True,
    max_retries=3
)
def map_mitre_atlas(self, threat_id: str) -> dict:
    """
    Map threat to MITRE ATLAS tactics and techniques.
    
    This is a standalone task for MITRE ATLAS mapping only.
    For complete enrichment, use enrich_threat task instead.
    
    Args:
        threat_id: UUID of the threat to map
        
    Returns:
        Dictionary with mapping results:
        {
            'status': 'success' | 'error',
            'threat_id': str,
            'mappings_count': int,
            'message': str
        }
        
    Requirements: 9.3
    """
    import asyncio
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import select
    from services.enrichment import EnrichmentService
    from models.threat import Threat
    
    logger.info(f"Mapping MITRE ATLAS for threat: {threat_id}")
    
    try:
        engine = create_async_engine(settings.database_url, echo=False)
        async_session_maker = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        
        async def _map():
            async with async_session_maker() as session:
                try:
                    # Fetch threat
                    result = await session.execute(
                        select(Threat).where(Threat.id == threat_id)
                    )
                    threat = result.scalar_one_or_none()
                    
                    if not threat:
                        return {
                            'status': 'error',
                            'threat_id': threat_id,
                            'mappings_count': 0,
                            'message': 'Threat not found'
                        }
                    
                    # Map to MITRE ATLAS
                    enrichment_service = EnrichmentService(session)
                    mappings = await enrichment_service.map_to_mitre_atlas(
                        str(threat.id), 
                        threat.threat_type
                    )
                    
                    # Add mappings to database
                    for mapping in mappings:
                        session.add(mapping)
                    await session.commit()
                    
                    return {
                        'status': 'success',
                        'threat_id': threat_id,
                        'mappings_count': len(mappings),
                        'message': f'Created {len(mappings)} MITRE ATLAS mappings'
                    }
                    
                finally:
                    await engine.dispose()
        
        result = asyncio.run(_map())
        logger.info(f"Created {result['mappings_count']} MITRE mappings for {threat_id}")
        return result
        
    except Exception as e:
        error_msg = f"Error mapping MITRE ATLAS for {threat_id}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        
        if self.request.retries < self.max_retries:
            raise self.retry(exc=e)
        
        return {
            'status': 'error',
            'threat_id': threat_id,
            'mappings_count': 0,
            'message': error_msg
        }


# ============================================================================
# ANALYSIS TASKS
# ============================================================================

@celery_app.task(
    name='tasks.analyze_with_llm',
    bind=True,
    max_retries=3,
    default_retry_delay=120
)
def analyze_with_llm(self, threat_id: str) -> dict:
    """
    Analyze threat using Ollama LLM.
    
    This task:
    1. Connects to the containerized Ollama service
    2. Generates a structured prompt for threat analysis
    3. Requests summary, attack vectors, and mitigations
    4. Parses the LLM response
    5. Stores results in the llm_analysis table
    
    The task handles Ollama unavailability gracefully by logging a warning
    and returning an error status without failing the task.
    
    Args:
        threat_id: UUID of the threat to analyze
        
    Returns:
        Dictionary with analysis results:
        {
            'success': bool,
            'threat_id': str,
            'analysis_id': str (if successful),
            'model_name': str (if successful),
            'error': str (if failed)
        }
        
    Raises:
        Retry: If analysis fails due to temporary errors and retries are available
        
    Requirements: 10.1, 10.4, 10.5, 10.6, 10.7, 10.8, 10.9, 10.10
    """
    import asyncio
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from services.analysis import get_analysis_service
    
    logger.info(f"Starting LLM analysis for threat: {threat_id}")
    
    try:
        # Create async database session
        engine = create_async_engine(settings.database_url, echo=False)
        async_session_maker = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        
        async def _analyze():
            """Async analysis function"""
            async with async_session_maker() as session:
                try:
                    # Create analysis service
                    analysis_service = get_analysis_service(session)
                    
                    # Perform analysis
                    result = await analysis_service.analyze_threat(threat_id)
                    
                    return result
                    
                except Exception as e:
                    logger.error(f"Error in async analysis: {e}", exc_info=True)
                    raise
                finally:
                    await engine.dispose()
        
        # Run async analysis
        result = asyncio.run(_analyze())
        
        # Log result
        if result.get('success'):
            logger.info(f"Successfully analyzed threat {threat_id} with LLM")
        else:
            error = result.get('error', 'Unknown error')
            
            # Check if error is due to Ollama unavailability
            if 'unavailable' in error.lower() or 'connection' in error.lower():
                logger.warning(f"Ollama unavailable for threat {threat_id}, skipping LLM analysis")
                # Don't retry for unavailability - just skip
                return result
            else:
                logger.error(f"LLM analysis failed for threat {threat_id}: {error}")
        
        return result
        
    except Exception as e:
        error_msg = f"Error analyzing threat {threat_id} with LLM: {str(e)}"
        logger.error(error_msg, exc_info=True)
        
        # Retry if we have retries left and it's not a connection error
        if self.request.retries < self.max_retries:
            # Check if it's a retryable error
            if 'unavailable' not in str(e).lower() and 'connection' not in str(e).lower():
                logger.info(f"Retrying analyze_with_llm for {threat_id} (attempt {self.request.retries + 1}/{self.max_retries})")
                raise self.retry(exc=e)
        
        return {
            'success': False,
            'threat_id': threat_id,
            'error': error_msg
        }


# ============================================================================
# ALERT TASKS (Placeholder - will be implemented in task 16)
# ============================================================================

@celery_app.task(
    name='tasks.send_alert',
    bind=True,
    max_retries=3,
    default_retry_delay=60
)
def send_alert(self, threat_id: str, channels: list = None) -> dict:
    """
    Send alert notifications for high-severity threats
    
    This task sends notifications via configured channels (email, webhook)
    for threats that meet the alert criteria.
    
    Args:
        threat_id: UUID of the threat to alert on
        channels: List of notification channels (email, webhook), None for all
        
    Returns:
        Dictionary with alert results:
        {
            'status': 'success' | 'partial' | 'error',
            'threat_id': str,
            'channels': dict with channel results
        }
    
    Requirements: 14.4, 14.5, 14.7
    """
    import asyncio
    from models import AsyncSessionLocal, Threat
    from sqlalchemy import select
    from services.alerts import get_alert_service
    
    logger.info(f"Sending alert for threat {threat_id}")
    
    try:
        # Get threat from database
        async def get_threat():
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(Threat).where(Threat.id == threat_id)
                )
                return result.scalar_one_or_none()
        
        threat = asyncio.run(get_threat())
        
        if not threat:
            logger.error(f"Threat {threat_id} not found")
            return {
                'status': 'error',
                'threat_id': threat_id,
                'error': 'Threat not found'
            }
        
        # Convert threat to dictionary
        threat_dict = {
            'id': str(threat.id),
            'title': threat.title,
            'description': threat.description,
            'severity': threat.severity,
            'threat_type': threat.threat_type,
            'source': threat.source,
            'source_url': threat.source_url,
            'ingested_at': threat.ingested_at.isoformat() if threat.ingested_at else None
        }
        
        # Get alert service
        alert_service = get_alert_service()
        
        # Check if alert should be triggered
        if not alert_service.should_trigger_alert(threat_dict):
            logger.info(f"Threat {threat_id} does not meet alert criteria")
            return {
                'status': 'skipped',
                'threat_id': threat_id,
                'reason': 'Does not meet alert criteria'
            }
        
        # Send alerts
        async def send_alerts():
            return await alert_service.send_alert(threat_dict, channels)
        
        results = asyncio.run(send_alerts())
        
        # Determine overall status
        if all(results.values()):
            status = 'success'
        elif any(results.values()):
            status = 'partial'
        else:
            status = 'error'
        
        logger.info(f"Alert sent for threat {threat_id}: {status}")
        
        return {
            'status': status,
            'threat_id': threat_id,
            'channels': results
        }
    
    except Exception as e:
        logger.error(f"Error sending alert for threat {threat_id}: {e}", exc_info=True)
        
        # Retry on failure
        try:
            raise self.retry(exc=e)
        except self.MaxRetriesExceededError:
            logger.error(f"Max retries exceeded for alert {threat_id}")
            return {
                'status': 'error',
                'threat_id': threat_id,
                'error': str(e),
                'max_retries_exceeded': True
            }


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_task_status(task_id: str) -> dict:
    """
    Get the status of a Celery task
    
    Args:
        task_id: Celery task ID
        
    Returns:
        Dictionary with task status information
    """
    from celery.result import AsyncResult
    
    result = AsyncResult(task_id, app=celery_app)
    
    return {
        'task_id': task_id,
        'status': result.status,
        'result': result.result if result.ready() else None,
        'traceback': result.traceback if result.failed() else None
    }


if __name__ == '__main__':
    # Start Celery worker
    celery_app.start()
