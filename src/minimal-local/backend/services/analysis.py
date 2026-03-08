"""
LLM-based threat analysis service.

Provides AI-powered analysis of threat intelligence data using local LLMs
via Ollama, generating summaries, identifying attack vectors, and recommending
mitigations.
"""
import logging
import re
from typing import Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models.threat import Threat
from models.llm_analysis import LLMAnalysis
from services.llm_client import get_ollama_client

logger = logging.getLogger(__name__)


class AnalysisService:
    """
    Service for LLM-based threat analysis.
    
    Provides methods for:
    - Generating threat summaries
    - Identifying attack vectors
    - Recommending mitigations
    - Parsing and storing LLM responses
    """
    
    def __init__(self, db_session: AsyncSession):
        """
        Initialize analysis service.
        
        Args:
            db_session: Database session for storing analysis results
        """
        self.db = db_session
        self.ollama_client = get_ollama_client()
    
    def _build_analysis_prompt(
        self,
        title: str,
        description: Optional[str],
        content: Optional[str],
        threat_type: Optional[str]
    ) -> str:
        """
        Build a comprehensive prompt for threat analysis.
        
        Args:
            title: Threat title
            description: Threat description
            content: Full threat content
            threat_type: Classified threat type
        
        Returns:
            Formatted prompt string
        """
        # Combine available content
        full_content = []
        
        if title:
            full_content.append(f"Title: {title}")
        
        if description:
            full_content.append(f"Description: {description}")
        
        if content:
            # Truncate content if too long (keep first 2000 chars)
            truncated_content = content[:2000] + "..." if len(content) > 2000 else content
            full_content.append(f"Content: {truncated_content}")
        
        if threat_type:
            full_content.append(f"Threat Type: {threat_type}")
        
        content_text = "\n\n".join(full_content)
        
        # Build structured prompt
        prompt = f"""You are an AI/ML security expert analyzing a threat to AI systems. Analyze the following threat intelligence and provide a structured response.

{content_text}

Please provide your analysis in the following format:

SUMMARY:
[Provide a concise 2-3 sentence summary of the threat]

KEY FINDINGS:
- [Key finding 1]
- [Key finding 2]
- [Key finding 3]

ATTACK VECTORS:
- [Attack vector 1]
- [Attack vector 2]
- [Attack vector 3]

MITIGATIONS:
- [Mitigation recommendation 1]
- [Mitigation recommendation 2]
- [Mitigation recommendation 3]

Focus on AI/ML security aspects such as adversarial attacks, model extraction, data poisoning, prompt injection, privacy violations, and supply chain risks."""
        
        return prompt
    
    def _parse_llm_response(self, response_text: str) -> Dict[str, any]:
        """
        Parse structured LLM response into components.
        
        Args:
            response_text: Raw LLM response text
        
        Returns:
            Dictionary with parsed components:
            {
                'summary': str,
                'key_findings': List[str],
                'attack_vectors': List[str],
                'mitigations': List[str]
            }
        """
        # Initialize result
        result = {
            'summary': None,
            'key_findings': [],
            'attack_vectors': [],
            'mitigations': []
        }
        
        # Split response into sections
        sections = {
            'summary': r'SUMMARY:\s*\n(.*?)(?=\n\n|\nKEY FINDINGS:|\nATTACK VECTORS:|\nMITIGATIONS:|$)',
            'key_findings': r'KEY FINDINGS:\s*\n(.*?)(?=\n\n|\nATTACK VECTORS:|\nMITIGATIONS:|$)',
            'attack_vectors': r'ATTACK VECTORS:\s*\n(.*?)(?=\n\n|\nMITIGATIONS:|$)',
            'mitigations': r'MITIGATIONS:\s*\n(.*?)(?=\n\n|$)'
        }
        
        # Extract summary
        summary_match = re.search(sections['summary'], response_text, re.DOTALL | re.IGNORECASE)
        if summary_match:
            result['summary'] = summary_match.group(1).strip()
        
        # Extract key findings (bullet points)
        findings_match = re.search(sections['key_findings'], response_text, re.DOTALL | re.IGNORECASE)
        if findings_match:
            findings_text = findings_match.group(1)
            # Extract bullet points
            findings = re.findall(r'[-*]\s*(.+?)(?=\n[-*]|\n\n|$)', findings_text, re.DOTALL)
            result['key_findings'] = [f.strip() for f in findings if f.strip()]
        
        # Extract attack vectors (bullet points)
        vectors_match = re.search(sections['attack_vectors'], response_text, re.DOTALL | re.IGNORECASE)
        if vectors_match:
            vectors_text = vectors_match.group(1)
            vectors = re.findall(r'[-*]\s*(.+?)(?=\n[-*]|\n\n|$)', vectors_text, re.DOTALL)
            result['attack_vectors'] = [v.strip() for v in vectors if v.strip()]
        
        # Extract mitigations (bullet points)
        mitigations_match = re.search(sections['mitigations'], response_text, re.DOTALL | re.IGNORECASE)
        if mitigations_match:
            mitigations_text = mitigations_match.group(1)
            mitigations = re.findall(r'[-*]\s*(.+?)(?=\n[-*]|\n\n|$)', mitigations_text, re.DOTALL)
            result['mitigations'] = [m.strip() for m in mitigations if m.strip()]
        
        # Fallback: if parsing failed, try to extract any content
        if not result['summary'] and not result['key_findings']:
            # Use first paragraph as summary
            paragraphs = [p.strip() for p in response_text.split('\n\n') if p.strip()]
            if paragraphs:
                result['summary'] = paragraphs[0]
        
        logger.info(f"Parsed LLM response: summary={bool(result['summary'])}, "
                   f"findings={len(result['key_findings'])}, "
                   f"vectors={len(result['attack_vectors'])}, "
                   f"mitigations={len(result['mitigations'])}")
        
        return result
    
    async def analyze_threat(self, threat_id: str) -> Dict[str, any]:
        """
        Perform complete LLM analysis on a threat.
        
        Args:
            threat_id: Threat UUID
        
        Returns:
            Dictionary with analysis results:
            {
                'success': bool,
                'threat_id': str,
                'analysis_id': str (if successful),
                'error': str (if failed)
            }
        """
        logger.info(f"Starting LLM analysis for threat {threat_id}")
        
        # Fetch threat from database
        result = await self.db.execute(
            select(Threat).where(Threat.id == threat_id)
        )
        threat = result.scalar_one_or_none()
        
        if not threat:
            logger.error(f"Threat {threat_id} not found")
            return {
                'success': False,
                'threat_id': threat_id,
                'error': 'Threat not found'
            }
        
        # Check if analysis already exists
        existing_analysis = await self.db.execute(
            select(LLMAnalysis).where(LLMAnalysis.threat_id == threat_id)
        )
        existing = existing_analysis.scalar_one_or_none()
        if existing:
            logger.info(f"Analysis already exists for threat {threat_id}, ensuring status is updated")
            # Ensure threat status is marked as complete
            if threat.llm_analysis_status != 'complete':
                threat.llm_analysis_status = 'complete'
                await self.db.commit()
                logger.info(f"Updated threat {threat_id} status to complete")
            return {
                'success': True,
                'threat_id': threat_id,
                'analysis_id': str(existing.id),
                'message': 'Analysis already exists'
            }
        
        try:
            # Check Ollama health
            is_healthy = await self.ollama_client.check_health()
            if not is_healthy:
                logger.warning(f"Ollama service is unavailable, skipping analysis for {threat_id}")
                return {
                    'success': False,
                    'threat_id': threat_id,
                    'error': 'Ollama service unavailable'
                }
            
            # Build analysis prompt
            prompt = self._build_analysis_prompt(
                title=threat.title,
                description=threat.description,
                content=threat.content,
                threat_type=threat.threat_type
            )
            
            logger.info(f"Sending analysis request to Ollama (prompt: {len(prompt)} chars)")
            
            # Generate analysis using LLM
            llm_response = await self.ollama_client.generate(
                prompt=prompt,
                options={
                    'temperature': 0.7,  # Balanced creativity
                    'top_p': 0.9,
                    'num_predict': 1000  # Max tokens to generate
                }
            )
            
            response_text = llm_response.get('response', '')
            model_name = llm_response.get('model', self.ollama_client.model)
            
            logger.info(f"Received LLM response: {len(response_text)} chars")
            
            # Parse LLM response
            parsed = self._parse_llm_response(response_text)
            
            # Create LLM analysis record
            analysis = LLMAnalysis(
                threat_id=threat_id,
                summary=parsed['summary'],
                key_findings=parsed['key_findings'] if parsed['key_findings'] else None,
                attack_vectors=parsed['attack_vectors'] if parsed['attack_vectors'] else None,
                mitigations=parsed['mitigations'] if parsed['mitigations'] else None,
                model_name=model_name
            )
            
            # Save to database
            self.db.add(analysis)
            
            # Update threat LLM analysis status to complete
            threat.llm_analysis_status = 'complete'
            
            await self.db.commit()
            await self.db.refresh(analysis)
            
            logger.info(f"Successfully saved LLM analysis for threat {threat_id}")
            
            return {
                'success': True,
                'threat_id': threat_id,
                'analysis_id': str(analysis.id),
                'model_name': model_name
            }
            
        except ConnectionError as e:
            logger.warning(f"Ollama connection error for threat {threat_id}: {e}")
            # Update threat status to failed
            threat.llm_analysis_status = 'failed'
            await self.db.commit()
            return {
                'success': False,
                'threat_id': threat_id,
                'error': f'Ollama connection error: {str(e)}'
            }
        
        except TimeoutError as e:
            logger.warning(f"Ollama timeout for threat {threat_id}: {e}")
            # Update threat status to failed
            threat.llm_analysis_status = 'failed'
            await self.db.commit()
            return {
                'success': False,
                'threat_id': threat_id,
                'error': f'Ollama timeout: {str(e)}'
            }
        
        except Exception as e:
            logger.error(f"Error analyzing threat {threat_id}: {e}", exc_info=True)
            # Update threat status to failed before rollback
            threat.llm_analysis_status = 'failed'
            try:
                await self.db.commit()
            except Exception as commit_error:
                logger.error(f"Failed to commit status update: {commit_error}")
                await self.db.rollback()
            return {
                'success': False,
                'threat_id': threat_id,
                'error': f'Analysis failed: {str(e)}'
            }
    
    async def get_analysis(self, threat_id: str) -> Optional[LLMAnalysis]:
        """
        Get existing LLM analysis for a threat.
        
        Args:
            threat_id: Threat UUID
        
        Returns:
            LLMAnalysis object or None if not found
        """
        result = await self.db.execute(
            select(LLMAnalysis).where(LLMAnalysis.threat_id == threat_id)
        )
        return result.scalar_one_or_none()


def get_analysis_service(db_session: AsyncSession) -> AnalysisService:
    """
    Factory function to create AnalysisService instance.
    
    Args:
        db_session: Database session
    
    Returns:
        AnalysisService instance
    """
    return AnalysisService(db_session)
