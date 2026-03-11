import { useQuery } from '@tanstack/react-query'
import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, Share2, Mail, Copy, Check } from 'lucide-react'
import { useState, useEffect, useRef } from 'react'
import { threatsApi } from '../services/api'

export default function ThreatDetail() {
  const { id } = useParams<{ id: string }>()
  const [showShareMenu, setShowShareMenu] = useState(false)
  const [copied, setCopied] = useState(false)
  const shareMenuRef = useRef<HTMLDivElement>(null)
  
  const { data: threat, isLoading } = useQuery({
    queryKey: ['threat', id],
    queryFn: () => threatsApi.get(id!),
    enabled: !!id,
  })

  // Close share menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (shareMenuRef.current && !shareMenuRef.current.contains(event.target as Node)) {
        setShowShareMenu(false)
      }
    }

    if (showShareMenu) {
      document.addEventListener('mousedown', handleClickOutside)
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [showShareMenu])

  const handleCopyToClipboard = () => {
    if (!threat) return
    
    const shareText = `${threat.title}

${threat.llm_analysis?.summary || threat.description || 'No summary available'}

Source: ${threat.source_url || window.location.href}`
    
    navigator.clipboard.writeText(shareText).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const handleEmailShare = () => {
    if (!threat) return
    
    const subject = encodeURIComponent(`AI Threat: ${threat.title}`)
    const body = encodeURIComponent(`${threat.title}

${threat.llm_analysis?.summary || threat.description || 'No summary available'}

Source: ${threat.source_url || window.location.href}

View full details: ${window.location.href}`)
    
    window.location.href = `mailto:?subject=${subject}&body=${body}`
  }

  const handleMessageShare = () => {
    if (!threat) return
    
    const shareText = encodeURIComponent(`${threat.title}

${threat.llm_analysis?.summary || threat.description || 'No summary available'}

Source: ${threat.source_url || window.location.href}`)
    
    window.location.href = `sms:&body=${shareText}`
  }

  const handleCopyUrl = () => {
    navigator.clipboard.writeText(window.location.href).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  if (isLoading) {
    return <div className="text-center py-12 text-gray-900 dark:text-gray-100">Loading...</div>
  }

  if (!threat) {
    return <div className="text-center py-12 text-gray-900 dark:text-gray-100">Threat not found</div>
  }

  const getSeverityColor = (severity: number) => {
    if (severity >= 9) return 'text-red-600 bg-red-100 dark:bg-red-900 dark:text-red-200'
    if (severity >= 7) return 'text-orange-600 bg-orange-100 dark:bg-orange-900 dark:text-orange-200'
    if (severity >= 5) return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900 dark:text-yellow-200'
    return 'text-green-600 bg-green-100 dark:bg-green-900 dark:text-green-200'
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Link
          to="/threats"
          className="inline-flex items-center text-sm text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300"
        >
          <ArrowLeft size={16} className="mr-1" />
          Back to threats
        </Link>
        
        {/* Share Button */}
        <div className="relative" ref={shareMenuRef}>
          <button
            onClick={() => setShowShareMenu(!showShareMenu)}
            className="inline-flex items-center px-3 py-2 border border-gray-300 dark:border-gray-600 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
          >
            <Share2 size={16} className="mr-2" />
            Share
          </button>
          
          {/* Share Menu Dropdown */}
          {showShareMenu && (
            <div className="absolute right-0 mt-2 w-56 rounded-md shadow-lg bg-white dark:bg-gray-700 ring-1 ring-black ring-opacity-5 z-10">
              <div className="py-1" role="menu">
                <button
                  onClick={() => {
                    handleCopyToClipboard()
                    setShowShareMenu(false)
                  }}
                  className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-600 flex items-center"
                >
                  {copied ? <Check size={16} className="mr-3" /> : <Copy size={16} className="mr-3" />}
                  {copied ? 'Copied!' : 'Copy Summary & URL'}
                </button>
                <button
                  onClick={() => {
                    handleCopyUrl()
                    setShowShareMenu(false)
                  }}
                  className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-600 flex items-center"
                >
                  {copied ? <Check size={16} className="mr-3" /> : <Copy size={16} className="mr-3" />}
                  {copied ? 'Copied!' : 'Copy Page URL'}
                </button>
                <button
                  onClick={() => {
                    handleEmailShare()
                    setShowShareMenu(false)
                  }}
                  className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-600 flex items-center"
                >
                  <Mail size={16} className="mr-3" />
                  Share via Email
                </button>
                <button
                  onClick={() => {
                    handleMessageShare()
                    setShowShareMenu(false)
                  }}
                  className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-600 flex items-center"
                >
                  <svg className="w-4 h-4 mr-3" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M2.003 5.884L10 9.882l7.997-3.998A2 2 0 0016 4H4a2 2 0 00-1.997 1.884z" />
                    <path d="M18 8.118l-8 4-8-4V14a2 2 0 002 2h12a2 2 0 002-2V8.118z" />
                  </svg>
                  Share via iMessage/SMS
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
      
      <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">{threat.title}</h1>

      <div className="bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-lg">
        <div className="px-4 py-5 sm:px-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-gray-100">
              Threat Details
            </h3>
            {threat.severity && (
              <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getSeverityColor(threat.severity)}`}>
                Severity: {threat.severity}/10
              </span>
            )}
          </div>
        </div>
        <div className="border-t border-gray-200 dark:border-gray-700 px-4 py-5 sm:p-0">
          <dl className="sm:divide-y sm:divide-gray-200 dark:sm:divide-gray-700">
            <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Description</dt>
              <dd className="mt-1 text-sm text-gray-900 dark:text-gray-100 sm:mt-0 sm:col-span-2">
                {threat.description || 'No description available'}
              </dd>
            </div>
            <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Source</dt>
              <dd className="mt-1 text-sm text-gray-900 dark:text-gray-100 sm:mt-0 sm:col-span-2">
                {threat.source}
                {threat.source_url && (
                  <a
                    href={threat.source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="ml-2 text-indigo-600 dark:text-indigo-400 hover:text-indigo-500 dark:hover:text-indigo-300"
                  >
                    View source →
                  </a>
                )}
              </dd>
            </div>
            {threat.threat_type && (
              <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Threat Type</dt>
                <dd className="mt-1 text-sm text-gray-900 dark:text-gray-100 sm:mt-0 sm:col-span-2 capitalize">
                  {threat.threat_type}
                </dd>
              </div>
            )}
            {threat.classification_metadata?.threat_metadata && (
              <>
                {threat.classification_metadata.threat_metadata.testability && (
                  <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                    <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Testability</dt>
                    <dd className="mt-1 text-sm sm:mt-0 sm:col-span-2">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        threat.classification_metadata.threat_metadata.testability === 'yes' 
                          ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                          : threat.classification_metadata.threat_metadata.testability === 'conditional'
                          ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
                          : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                      }`}>
                        {threat.classification_metadata.threat_metadata.testability}
                      </span>
                    </dd>
                  </div>
                )}
                {threat.classification_metadata.threat_metadata.attack_surface && threat.classification_metadata.threat_metadata.attack_surface.length > 0 && (
                  <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                    <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Attack Surface</dt>
                    <dd className="mt-1 text-sm sm:mt-0 sm:col-span-2">
                      <div className="flex flex-wrap gap-2">
                        {threat.classification_metadata.threat_metadata.attack_surface.map((surface: string) => (
                          <span key={surface} className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                            {surface}
                          </span>
                        ))}
                      </div>
                    </dd>
                  </div>
                )}
                {threat.classification_metadata.threat_metadata.techniques && threat.classification_metadata.threat_metadata.techniques.length > 0 && (
                  <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                    <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Techniques</dt>
                    <dd className="mt-1 text-sm sm:mt-0 sm:col-span-2">
                      <div className="flex flex-wrap gap-2">
                        {threat.classification_metadata.threat_metadata.techniques.map((technique: string) => (
                          <span key={technique} className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200">
                            {technique}
                          </span>
                        ))}
                      </div>
                    </dd>
                  </div>
                )}
                {threat.classification_metadata.threat_metadata.target_systems && threat.classification_metadata.threat_metadata.target_systems.length > 0 && (
                  <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                    <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Target Systems</dt>
                    <dd className="mt-1 text-sm sm:mt-0 sm:col-span-2">
                      <div className="flex flex-wrap gap-2">
                        {threat.classification_metadata.threat_metadata.target_systems.map((system: string) => (
                          <span key={system} className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-indigo-100 text-indigo-800 dark:bg-indigo-900 dark:text-indigo-200">
                            {system}
                          </span>
                        ))}
                      </div>
                    </dd>
                  </div>
                )}
                {threat.classification_metadata.threat_metadata.confidence && (
                  <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                    <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Classification Confidence</dt>
                    <dd className="mt-1 text-sm text-gray-900 dark:text-gray-100 sm:mt-0 sm:col-span-2">
                      {(threat.classification_metadata.threat_metadata.confidence * 100).toFixed(0)}%
                    </dd>
                  </div>
                )}
                {threat.classification_metadata.threat_metadata.reasoning && (
                  <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                    <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Classification Reasoning</dt>
                    <dd className="mt-1 text-sm text-gray-700 dark:text-gray-300 sm:mt-0 sm:col-span-2">
                      {threat.classification_metadata.threat_metadata.reasoning}
                    </dd>
                  </div>
                )}
              </>
            )}
            <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Ingested</dt>
              <dd className="mt-1 text-sm text-gray-900 dark:text-gray-100 sm:mt-0 sm:col-span-2">
                {new Date(threat.ingested_at).toLocaleString()}
              </dd>
            </div>
            {threat.content && (
              <div className="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Content</dt>
                <dd className="mt-1 text-sm text-gray-900 dark:text-gray-100 sm:mt-0 sm:col-span-2 whitespace-pre-wrap">
                  {threat.content}
                </dd>
              </div>
            )}
          </dl>
        </div>
      </div>

      {/* Entities */}
      {threat.entities && threat.entities.length > 0 && (
        <div className="bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-lg">
          <div className="px-4 py-5 sm:px-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-gray-100">
              Extracted Entities
            </h3>
          </div>
          <div className="border-t border-gray-200 dark:border-gray-700">
            <ul className="divide-y divide-gray-200 dark:divide-gray-700">
              {threat.entities.map((entity: any) => (
                <li key={entity.id} className="px-4 py-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-900 dark:text-gray-100">{entity.entity_value}</p>
                      <p className="text-sm text-gray-500 dark:text-gray-400 capitalize">{entity.entity_type}</p>
                    </div>
                    {entity.confidence && (
                      <span className="text-sm text-gray-500 dark:text-gray-400">
                        {(entity.confidence * 100).toFixed(0)}% confidence
                      </span>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* MITRE ATLAS Mappings */}
      {threat.mitre_mappings && threat.mitre_mappings.length > 0 && (
        <div className="bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-lg">
          <div className="px-4 py-5 sm:px-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-gray-100">
              MITRE ATLAS Mappings
            </h3>
          </div>
          <div className="border-t border-gray-200 dark:border-gray-700">
            <ul className="divide-y divide-gray-200 dark:divide-gray-700">
              {threat.mitre_mappings.map((mapping: any) => (
                <li key={mapping.id} className="px-4 py-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
                        {mapping.technique} {mapping.technique_id && `(${mapping.technique_id})`}
                      </p>
                      {mapping.tactic && (
                        <p className="text-sm text-gray-500 dark:text-gray-400">Tactic: {mapping.tactic}</p>
                      )}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* LLM Analysis */}
      {threat.llm_analysis && (
        <div className="bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-lg">
          <div className="px-4 py-5 sm:px-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-gray-100">
              LLM Analysis
            </h3>
          </div>
          <div className="border-t border-gray-200 dark:border-gray-700 px-4 py-5 sm:p-6">
            {threat.llm_analysis.summary && (
              <div className="mb-4">
                <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">Summary</h4>
                <p className="text-sm text-gray-700 dark:text-gray-300">{threat.llm_analysis.summary}</p>
              </div>
            )}
            {threat.llm_analysis.attack_vectors && threat.llm_analysis.attack_vectors.length > 0 && (
              <div className="mb-4">
                <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">Attack Vectors</h4>
                <ul className="list-disc list-inside text-sm text-gray-700 dark:text-gray-300 space-y-1">
                  {threat.llm_analysis.attack_vectors.map((vector: string, i: number) => (
                    <li key={i}>{vector}</li>
                  ))}
                </ul>
              </div>
            )}
            {threat.llm_analysis.mitigations && threat.llm_analysis.mitigations.length > 0 && (
              <div>
                <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">Mitigations</h4>
                <ul className="list-disc list-inside text-sm text-gray-700 dark:text-gray-300 space-y-1">
                  {threat.llm_analysis.mitigations.map((mitigation: string, i: number) => (
                    <li key={i}>{mitigation}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
