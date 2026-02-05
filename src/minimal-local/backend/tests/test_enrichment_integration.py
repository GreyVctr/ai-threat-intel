"""
Integration tests for EnrichmentService with ClassificationService.

Tests the complete enrichment flow including:
- Hybrid threat classification (keyword + LLM)
- Entity extraction
- MITRE ATLAS mapping
- Severity scoring
- Error handling and fallback behavior
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from services.enrichment import EnrichmentService
from services.classification_service import ClassificationService
from services.classification_types import ClassificationResult
from models.threat import Threat
from models.entity import Entity
from models.mitre import MitreMapping


@pytest.mark.asyncio
async def test_enrich_threat_with_hybrid_classification(db_session):
    """Test enrichment flow with successful hybrid classification."""
    # Create a test threat
    threat = Threat(
        id="test-threat-001",
        title="Adversarial Attack on PyTorch Models",
        description="FGSM-based adversarial perturbations targeting PyTorch image classifiers with evasion techniques",
        content="The attack uses adversarial examples to fool the model",
        source="Test Source",
        source_url="https://test.example.com/threat",
        published_at=datetime.now(timezone.utc)
    )
    db_session.add(threat)
    await db_session.commit()
    
    # Create enrichment service
    enrichment_service = EnrichmentService(db_session)
    
    # Run enrichment
    result = await enrichment_service.enrich_threat(str(threat.id))
    
    # Verify success
    assert result["success"] is True
    assert result["threat_id"] == str(threat.id)
    assert result["threat_type"] is not None
    assert result["classification_method"] in ["keyword", "llm", "hybrid", "keyword_fallback"]
    assert result["classification_confidence"] in ["high", "medium", "low", "none"]
    
    # Verify threat was updated
    await db_session.refresh(threat)
    assert threat.threat_type is not None
    assert threat.classification_method is not None
    assert threat.classification_confidence is not None
    assert threat.classification_metadata is not None
    
    # Verify metadata structure
    metadata = threat.classification_metadata
    assert "method" in metadata
    assert "confidence" in metadata
    assert "timestamp" in metadata
    
    print(f"✅ Enrichment successful: type={threat.threat_type}, method={threat.classification_method}")


@pytest.mark.asyncio
async def test_enrich_threat_with_high_confidence_keyword(db_session):
    """Test enrichment with high-confidence keyword classification (fast path)."""
    # Create a threat with many adversarial keywords
    threat = Threat(
        id="test-threat-002",
        title="Adversarial Attack",
        description="adversarial perturbation evasion attack adversarial example adversarial training",
        content="adversarial robustness adversarial noise",
        source="Test Source",
        source_url="https://test.example.com/threat2",
        published_at=datetime.now(timezone.utc)
    )
    db_session.add(threat)
    await db_session.commit()
    
    # Create enrichment service
    enrichment_service = EnrichmentService(db_session)
    
    # Run enrichment
    result = await enrichment_service.enrich_threat(str(threat.id))
    
    # Verify success
    assert result["success"] is True
    assert result["threat_type"] == "adversarial"
    
    # Verify high confidence keyword classification (should not use LLM)
    await db_session.refresh(threat)
    assert threat.classification_method == "keyword"
    assert threat.classification_confidence == "high"
    assert threat.classification_score >= 5
    
    print(f"✅ High confidence keyword classification: score={threat.classification_score}")


@pytest.mark.asyncio
async def test_enrich_threat_with_classification_fallback(db_session):
    """Test enrichment with classification service failure and fallback."""
    # Create a test threat
    threat = Threat(
        id="test-threat-003",
        title="Test Threat",
        description="poisoning backdoor attack",
        content="Test content",
        source="Test Source",
        source_url="https://test.example.com/threat3",
        published_at=datetime.now(timezone.utc)
    )
    db_session.add(threat)
    await db_session.commit()
    
    # Create enrichment service
    enrichment_service = EnrichmentService(db_session)
    
    # Mock the classification service to raise an exception
    with patch.object(
        enrichment_service.classification_service,
        'classify_threat',
        side_effect=Exception("Classification service unavailable")
    ):
        # Run enrichment
        result = await enrichment_service.enrich_threat(str(threat.id))
    
    # Verify partial success with fallback
    assert result["success"] is True
    assert "Hybrid classification failed" in str(result.get("errors", []))
    
    # Verify fallback classification was used
    await db_session.refresh(threat)
    assert threat.threat_type is not None  # Should have fallback classification
    assert threat.classification_method == "legacy_fallback"
    
    print(f"✅ Fallback classification successful: type={threat.threat_type}")


@pytest.mark.asyncio
async def test_enrich_threat_with_entities_and_mitre(db_session):
    """Test complete enrichment including entities and MITRE mappings."""
    # Create a threat with CVEs and frameworks
    threat = Threat(
        id="test-threat-004",
        title="CVE-2023-12345 affects TensorFlow",
        description="Adversarial attack vulnerability in PyTorch and TensorFlow models",
        content="CVE-2023-12345 and CVE-2023-67890 discovered. Proof of concept on GitHub.",
        source="Test Source",
        source_url="https://test.example.com/threat4",
        published_at=datetime.now(timezone.utc)
    )
    db_session.add(threat)
    await db_session.commit()
    
    # Create enrichment service
    enrichment_service = EnrichmentService(db_session)
    
    # Run enrichment
    result = await enrichment_service.enrich_threat(str(threat.id))
    
    # Verify success
    assert result["success"] is True
    assert result["entities_count"] >= 2  # At least CVEs and frameworks
    assert result["mappings_count"] >= 1  # Should have MITRE mappings
    
    # Verify threat classification and severity
    await db_session.refresh(threat)
    assert threat.threat_type is not None
    assert threat.severity is not None
    assert threat.severity >= 7  # Should be high due to CVE and PoC
    assert threat.exploitability_score is not None
    
    print(f"✅ Complete enrichment: entities={result['entities_count']}, mappings={result['mappings_count']}, severity={threat.severity}")


@pytest.mark.asyncio
async def test_enrich_threat_not_found(db_session):
    """Test enrichment with non-existent threat."""
    enrichment_service = EnrichmentService(db_session)
    
    # Try to enrich non-existent threat (use a valid UUID format)
    non_existent_uuid = "00000000-0000-0000-0000-000000000000"
    result = await enrichment_service.enrich_threat(non_existent_uuid)
    
    # Verify failure
    assert result["success"] is False
    assert "not found" in result["error"].lower()
    
    print("✅ Correctly handled non-existent threat")


@pytest.mark.asyncio
async def test_enrich_threat_with_empty_content(db_session):
    """Test enrichment with threat that has minimal content."""
    # Create a threat with minimal content
    threat = Threat(
        id="test-threat-005",
        title="",
        description="",
        content="",
        source="Test Source",
        source_url="https://test.example.com/threat5",
        published_at=datetime.now(timezone.utc)
    )
    db_session.add(threat)
    await db_session.commit()
    
    # Create enrichment service
    enrichment_service = EnrichmentService(db_session)
    
    # Run enrichment
    result = await enrichment_service.enrich_threat(str(threat.id))
    
    # Verify it completes (may have errors but shouldn't crash)
    assert result["success"] is True
    
    # Verify threat has some classification (even if "unknown")
    await db_session.refresh(threat)
    assert threat.enrichment_status in ["complete", "partial"]
    
    print(f"✅ Handled empty content: status={threat.enrichment_status}")


@pytest.mark.asyncio
async def test_enrich_threat_preserves_classification_metadata(db_session):
    """Test that enrichment preserves detailed classification metadata."""
    # Create a test threat
    threat = Threat(
        id="test-threat-006",
        title="Model extraction attack",
        description="extract steal model weights via API queries",
        content="Model extraction technique",
        source="Test Source",
        source_url="https://test.example.com/threat6",
        published_at=datetime.now(timezone.utc)
    )
    db_session.add(threat)
    await db_session.commit()
    
    # Create enrichment service
    enrichment_service = EnrichmentService(db_session)
    
    # Run enrichment
    result = await enrichment_service.enrich_threat(str(threat.id))
    
    # Verify success
    assert result["success"] is True
    
    # Verify metadata is preserved
    await db_session.refresh(threat)
    assert threat.classification_metadata is not None
    
    metadata = threat.classification_metadata
    assert "method" in metadata
    assert "confidence" in metadata
    assert "timestamp" in metadata
    assert "keyword_matches" in metadata or "keyword_score" in metadata
    
    # Verify classification fields are consistent with metadata
    assert threat.classification_method == metadata["method"]
    assert threat.classification_confidence == metadata["confidence"]
    
    print(f"✅ Metadata preserved: {list(metadata.keys())}")


@pytest.mark.asyncio
async def test_legacy_classify_threat_type_still_works(db_session):
    """Test that legacy classify_threat_type method still works for backward compatibility."""
    enrichment_service = EnrichmentService(db_session)
    
    # Test with adversarial content
    content = "adversarial attack using FGSM perturbations and evasion techniques"
    threat_type = await enrichment_service.classify_threat_type(content)
    
    assert threat_type == "adversarial"
    
    # Test with extraction content
    content = "model extraction attack to steal model weights"
    threat_type = await enrichment_service.classify_threat_type(content)
    
    assert threat_type == "extraction"
    
    # Test with empty content
    threat_type = await enrichment_service.classify_threat_type("")
    assert threat_type is None
    
    print("✅ Legacy classify_threat_type method works")


@pytest.mark.asyncio
async def test_enrich_threat_idempotency(db_session):
    """Test that enrichment can be run multiple times on the same threat."""
    # Create a test threat
    threat = Threat(
        id="test-threat-007",
        title="Poisoning attack",
        description="data poisoning with backdoor triggers",
        content="Training data contamination",
        source="Test Source",
        source_url="https://test.example.com/threat7",
        published_at=datetime.now(timezone.utc)
    )
    db_session.add(threat)
    await db_session.commit()
    
    # Create enrichment service
    enrichment_service = EnrichmentService(db_session)
    
    # Run enrichment first time
    result1 = await enrichment_service.enrich_threat(str(threat.id))
    assert result1["success"] is True
    
    await db_session.refresh(threat)
    first_threat_type = threat.threat_type
    first_method = threat.classification_method
    
    # Run enrichment second time
    result2 = await enrichment_service.enrich_threat(str(threat.id))
    assert result2["success"] is True
    
    await db_session.refresh(threat)
    second_threat_type = threat.threat_type
    second_method = threat.classification_method
    
    # Verify results are consistent (idempotent)
    assert first_threat_type == second_threat_type
    # Method might differ if LLM is involved, but threat type should be stable
    
    print(f"✅ Idempotent enrichment: {first_threat_type} -> {second_threat_type}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
