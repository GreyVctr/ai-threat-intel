"""
AI Shield Intelligence - Threat Ingestion Service

Handles ingestion of threat data with:
- Content hash calculation for deduplication
- Metadata extraction
- Storage in both MinIO (raw data) and PostgreSQL (structured data)
- Transaction management for atomic operations

Requirements: 6.14, 6.15, 6.16, 6.17, 6.18, 15.2, 15.3
"""

import hashlib
import json
import logging
from datetime import datetime, date
from typing import Dict, Optional, Any
from io import BytesIO

from minio import Minio
from minio.error import S3Error
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from config import settings
from models.threat import Threat
from utils.hashing import calculate_content_hash as calc_hash

logger = logging.getLogger(__name__)


class IngestionService:
    """
    Service for ingesting threat intelligence data.
    
    Provides deduplication, metadata extraction, and dual storage
    (MinIO for raw data, PostgreSQL for structured data).
    """
    
    def __init__(self, db_session: AsyncSession, minio_client: Optional[Minio] = None):
        """
        Initialize ingestion service.
        
        Args:
            db_session: Async SQLAlchemy database session
            minio_client: MinIO client (optional, will create if not provided)
        """
        self.db = db_session
        
        # Initialize MinIO client
        if minio_client:
            self.minio = minio_client
        else:
            self.minio = Minio(
                settings.minio_endpoint,
                access_key=settings.minio_access_key,
                secret_key=settings.minio_secret_key,
                secure=settings.minio_secure
            )
        
        # Ensure bucket exists
        self._ensure_bucket_exists()
    
    def _ensure_bucket_exists(self):
        """Ensure the MinIO bucket exists, create if it doesn't."""
        try:
            if not self.minio.bucket_exists(settings.minio_bucket):
                self.minio.make_bucket(settings.minio_bucket)
                logger.info(f"Created MinIO bucket: {settings.minio_bucket}")
            else:
                logger.debug(f"MinIO bucket exists: {settings.minio_bucket}")
        except S3Error as e:
            logger.error(f"Error checking/creating MinIO bucket: {e}")
            raise
    
    def calculate_content_hash(self, content: str) -> str:
        """
        Calculate SHA-256 hash of content for deduplication.
        
        Args:
            content: Text content to hash
            
        Returns:
            Hexadecimal SHA-256 hash string
            
        Requirement: 6.14 - Deduplication based on content hash
        """
        content_hash = calc_hash(content)
        logger.debug(f"Calculated content hash: {content_hash[:16]}...")
        return content_hash
    
    async def check_duplicate(self, content_hash: str) -> Optional[Threat]:
        """
        Check if threat with given content hash already exists.
        
        Args:
            content_hash: SHA-256 hash of threat content
            
        Returns:
            Existing Threat object if found, None otherwise
            
        Requirement: 6.14 - Deduplication check
        """
        try:
            result = await self.db.execute(
                select(Threat).where(Threat.content_hash == content_hash)
            )
            existing_threat = result.scalar_one_or_none()
            
            if existing_threat:
                logger.info(f"Duplicate threat found: {existing_threat.id} (hash: {content_hash[:16]}...)")
            else:
                logger.debug(f"No duplicate found for hash: {content_hash[:16]}...")
            
            return existing_threat
            
        except Exception as e:
            logger.error(f"Error checking for duplicate: {e}")
            raise
    
    def extract_metadata(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract and normalize metadata from raw threat data.
        
        Args:
            raw_data: Raw threat data from collector
            
        Returns:
            Dictionary with extracted metadata:
            {
                'title': str,
                'description': str,
                'content': str,
                'source': str,
                'source_url': str,
                'authors': list,
                'published_at': datetime,
                'extra_metadata': dict
            }
            
        Requirement: 6.15 - Metadata extraction
        """
        metadata = {}
        
        # Required fields
        metadata['title'] = raw_data.get('title', 'Untitled Threat')
        metadata['source'] = raw_data.get('source', 'Unknown')
        
        # Optional fields with defaults
        metadata['description'] = raw_data.get('description', '')
        metadata['content'] = raw_data.get('content', raw_data.get('description', ''))
        metadata['source_url'] = raw_data.get('url', raw_data.get('link', ''))
        
        # Authors - handle various formats
        authors = raw_data.get('authors', [])
        if isinstance(authors, str):
            # Single author as string
            metadata['authors'] = [authors] if authors else []
        elif isinstance(authors, list):
            # List of authors
            metadata['authors'] = [str(a) for a in authors if a]
        else:
            metadata['authors'] = []
        
        # Published date - handle various formats
        published_at = raw_data.get('published_at', raw_data.get('published', raw_data.get('date')))
        if published_at:
            if isinstance(published_at, datetime):
                metadata['published_at'] = published_at
            elif isinstance(published_at, str):
                # Try to parse ISO format
                try:
                    metadata['published_at'] = datetime.fromisoformat(published_at.replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    logger.warning(f"Could not parse published date: {published_at}")
                    metadata['published_at'] = None
            else:
                metadata['published_at'] = None
        else:
            metadata['published_at'] = None
        
        # Store additional metadata in extra_metadata field
        extra_fields = {}
        for key, value in raw_data.items():
            if key not in ['title', 'description', 'content', 'source', 'url', 'link', 
                          'authors', 'published_at', 'published', 'date', 'source_type']:
                extra_fields[key] = value
        
        metadata['extra_metadata'] = extra_fields if extra_fields else None
        
        logger.debug(f"Extracted metadata: title='{metadata['title'][:50]}...', source={metadata['source']}")
        
        return metadata
    
    def generate_storage_key(self, content_hash: str, extension: str = 'json') -> str:
        """
        Generate date-based storage key for MinIO.
        
        Format: YYYY/MM/DD/{content_hash}.{extension}
        
        Args:
            content_hash: SHA-256 hash of content
            extension: File extension (default: json)
            
        Returns:
            Storage key string
            
        Requirement: 15.2, 15.3 - Date-based storage keys
        """
        today = date.today()
        storage_key = f"{today.year:04d}/{today.month:02d}/{today.day:02d}/{content_hash}.{extension}"
        
        logger.debug(f"Generated storage key: {storage_key}")
        return storage_key
    
    async def store_raw_data(self, raw_data: Dict[str, Any], storage_key: str) -> bool:
        """
        Store raw threat data in MinIO object storage.
        
        Args:
            raw_data: Raw threat data to store
            storage_key: MinIO object key
            
        Returns:
            True if successful, False otherwise
            
        Requirement: 6.16, 15.2 - Store raw data in MinIO
        """
        try:
            # Convert data to JSON
            json_data = json.dumps(raw_data, indent=2, default=str)
            data_bytes = json_data.encode('utf-8')
            
            # Store in MinIO
            self.minio.put_object(
                bucket_name=settings.minio_bucket,
                object_name=storage_key,
                data=BytesIO(data_bytes),
                length=len(data_bytes),
                content_type='application/json'
            )
            
            logger.info(f"Stored raw data in MinIO: {storage_key}")
            return True
            
        except S3Error as e:
            logger.error(f"MinIO error storing raw data: {e}")
            return False
        except Exception as e:
            logger.error(f"Error storing raw data: {e}")
            return False
    
    async def store_structured_data(self, metadata: Dict[str, Any], content_hash: str, 
                                   raw_data_key: str) -> Optional[Threat]:
        """
        Store structured threat data in PostgreSQL.
        
        Args:
            metadata: Extracted metadata
            content_hash: Content hash for deduplication
            raw_data_key: MinIO storage key reference
            
        Returns:
            Created Threat object if successful, None otherwise
            
        Requirement: 6.17 - Store structured data in PostgreSQL
        """
        try:
            # Create threat record
            threat = Threat(
                title=metadata['title'],
                description=metadata['description'],
                content=metadata['content'],
                source=metadata['source'],
                source_url=metadata['source_url'],
                authors=metadata['authors'],
                published_at=metadata['published_at'],
                content_hash=content_hash,
                raw_data_key=raw_data_key,
                extra_metadata=metadata['extra_metadata'],
                enrichment_status='pending',
                llm_analysis_status='pending'
            )
            
            self.db.add(threat)
            await self.db.flush()  # Flush to get the ID without committing
            
            logger.info(f"Created threat record: {threat.id} (hash: {content_hash[:16]}...)")
            return threat
            
        except IntegrityError as e:
            # Handle duplicate content_hash (race condition)
            logger.warning(f"Duplicate content_hash detected during insert: {content_hash[:16]}...")
            await self.db.rollback()
            
            # Fetch existing threat
            result = await self.db.execute(
                select(Threat).where(Threat.content_hash == content_hash)
            )
            existing_threat = result.scalar_one_or_none()
            return existing_threat
            
        except Exception as e:
            logger.error(f"Error storing structured data: {e}")
            await self.db.rollback()
            return None
    
    async def ingest(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingest threat data with deduplication and dual storage.
        
        This is the main entry point for threat ingestion. It:
        1. Calculates content hash
        2. Checks for duplicates
        3. Extracts metadata
        4. Stores raw data in MinIO
        5. Stores structured data in PostgreSQL
        
        Args:
            raw_data: Raw threat data from collector
            
        Returns:
            Dictionary with ingestion results:
            {
                'status': 'success' | 'duplicate' | 'error',
                'threat_id': str (UUID),
                'content_hash': str,
                'message': str
            }
            
        Requirements: 6.14, 6.15, 6.16, 6.17
        """
        try:
            # Extract content for hashing
            content = raw_data.get('content', raw_data.get('description', ''))
            if not content:
                logger.warning("No content found in raw data, using title")
                content = raw_data.get('title', '')
            
            # Calculate content hash
            content_hash = self.calculate_content_hash(content)
            
            # Check for duplicates
            existing_threat = await self.check_duplicate(content_hash)
            if existing_threat:
                return {
                    'status': 'duplicate',
                    'threat_id': str(existing_threat.id),
                    'content_hash': content_hash,
                    'message': f'Threat already exists: {existing_threat.id}'
                }
            
            # Extract metadata
            metadata = self.extract_metadata(raw_data)
            
            # Generate storage key
            storage_key = self.generate_storage_key(content_hash)
            
            # Store raw data in MinIO
            minio_success = await self.store_raw_data(raw_data, storage_key)
            if not minio_success:
                return {
                    'status': 'error',
                    'threat_id': None,
                    'content_hash': content_hash,
                    'message': 'Failed to store raw data in MinIO'
                }
            
            # Store structured data in PostgreSQL
            threat = await self.store_structured_data(metadata, content_hash, storage_key)
            if not threat:
                # Rollback MinIO storage would be ideal, but MinIO doesn't support transactions
                # Log the orphaned object for cleanup
                logger.error(f"Orphaned MinIO object created: {storage_key}")
                return {
                    'status': 'error',
                    'threat_id': None,
                    'content_hash': content_hash,
                    'message': 'Failed to store structured data in PostgreSQL'
                }
            
            # Commit the database transaction
            await self.db.commit()
            
            logger.info(f"Successfully ingested threat: {threat.id}")
            
            return {
                'status': 'success',
                'threat_id': str(threat.id),
                'content_hash': content_hash,
                'message': 'Threat ingested successfully'
            }
            
        except Exception as e:
            logger.error(f"Error during ingestion: {e}", exc_info=True)
            await self.db.rollback()
            
            return {
                'status': 'error',
                'threat_id': None,
                'content_hash': None,
                'message': f'Ingestion failed: {str(e)}'
            }


def get_ingestion_service(db_session: AsyncSession, minio_client: Optional[Minio] = None) -> IngestionService:
    """
    Factory function to create an IngestionService instance.
    
    Args:
        db_session: Async SQLAlchemy database session
        minio_client: Optional MinIO client
        
    Returns:
        IngestionService instance
    """
    return IngestionService(db_session, minio_client)
