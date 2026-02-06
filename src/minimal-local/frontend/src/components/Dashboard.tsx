import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { AlertTriangle, TrendingUp, Database, Activity, Clock, Zap, BarChart3, RefreshCw, AlertCircle, CheckCircle, XCircle, HelpCircle } from 'lucide-react'
import { searchApi, healthApi, systemApi } from '../services/api'
import { useState } from 'react'

export default function Dashboard() {
  const queryClient = useQueryClient()
  const [retryLimit, setRetryLimit] = useState(100)
  const [showThreatTypeModal, setShowThreatTypeModal] = useState(false)
  
  const { data: stats } = useQuery({
    queryKey: ['statistics'],
    queryFn: searchApi.statistics,
    refetchInterval: 15000, // Refresh every 15 seconds to stay in sync with LLM stats
  })

  const { data: recentThreats } = useQuery({
    queryKey: ['recent-threats'],
    queryFn: () => searchApi.recent(5),
    refetchInterval: 15000, // Refresh every 15 seconds to show new threats
  })

  const { data: highSeverity } = useQuery({
    queryKey: ['high-severity'],
    queryFn: () => searchApi.highSeverity(8, 5),
    refetchInterval: 15000, // Refresh every 15 seconds to stay in sync with other stats
  })

  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: healthApi.check,
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  const { data: systemStatus } = useQuery({
    queryKey: ['system-status'],
    queryFn: systemApi.status,
    refetchInterval: 10000, // Refresh every 10 seconds for real-time updates
  })

  const { data: llmStats } = useQuery({
    queryKey: ['llm-analysis-stats'],
    queryFn: systemApi.llmAnalysisStats,
    refetchInterval: 15000, // Refresh every 15 seconds
  })

  const { data: ollamaConfig } = useQuery({
    queryKey: ['ollama-config'],
    queryFn: systemApi.ollamaConfig,
    refetchInterval: 60000, // Refresh every minute
  })

  const { data: threatTypeInfo } = useQuery({
    queryKey: ['threat-type-info'],
    queryFn: systemApi.threatTypeInfo,
  })

  const retryMutation = useMutation({
    mutationFn: (limit: number) => systemApi.retryFailedLLM(limit),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['llm-analysis-stats'] })
      queryClient.invalidateQueries({ queryKey: ['system-status'] })
    },
  })

  const getSeverityColor = (severity: number) => {
    if (severity >= 9) return 'text-red-600 bg-red-100'
    if (severity >= 7) return 'text-orange-600 bg-orange-100'
    if (severity >= 5) return 'text-yellow-600 bg-yellow-100'
    return 'text-green-600 bg-green-100'
  }

  const getTimeUntilNext = (nextRun: string | null) => {
    if (!nextRun) return 'Unknown'
    const now = new Date()
    const next = new Date(nextRun)
    const diff = next.getTime() - now.getTime()
    
    if (diff < 0) return 'Overdue'
    
    const minutes = Math.floor(diff / 60000)
    const hours = Math.floor(minutes / 60)
    const days = Math.floor(hours / 24)
    
    if (days > 0) return `${days}d ${hours % 24}h`
    if (hours > 0) return `${hours}h ${minutes % 60}m`
    return `${minutes}m`
  }

  const formatDateTime = (dateStr: string | null) => {
    if (!dateStr) return 'Never'
    const date = new Date(dateStr)
    return date.toLocaleString()
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Dashboard</h1>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Overview of AI threat intelligence
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Database className="h-6 w-6 text-gray-400 dark:text-gray-500" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                    Total Threats
                  </dt>
                  <dd className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                    {stats?.total_threats || 0}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <AlertTriangle className="h-6 w-6 text-red-400 dark:text-red-500" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                    High Severity (≥8)
                  </dt>
                  <dd className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                    {highSeverity?.count || 0}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <TrendingUp className="h-6 w-6 text-green-400 dark:text-green-500" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate flex items-center gap-1">
                    Threat Types
                    <button
                      onClick={() => setShowThreatTypeModal(true)}
                      className="focus:outline-none"
                      title="Click to see threat type descriptions"
                    >
                      <HelpCircle className="h-4 w-4 text-indigo-500 hover:text-indigo-700 dark:text-indigo-400 dark:hover:text-indigo-300 cursor-pointer" />
                    </button>
                  </dt>
                  <dd className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                    {Object.keys(stats?.threat_types || {}).length}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Activity className={`h-6 w-6 ${health?.status === 'healthy' ? 'text-green-400 dark:text-green-500' : 'text-red-400 dark:text-red-500'}`} />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                    System Status
                  </dt>
                  <dd className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                    {health?.status === 'healthy' ? 'Healthy' : 'Degraded'}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Enhanced System Status */}
      {systemStatus && (
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
          <div className="px-4 py-5 sm:px-6 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-gray-100">
              System Activity
            </h3>
          </div>
          <div className="px-4 py-5 sm:p-6">
            <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
              {/* Collection Schedule */}
              <div className="border-l-4 border-indigo-500 pl-4">
                <div className="flex items-center">
                  <Clock className="h-5 w-5 text-indigo-500 mr-2" />
                  <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100">Next Collection</h4>
                </div>
                <p className="mt-2 text-2xl font-semibold text-gray-900 dark:text-gray-100">
                  {getTimeUntilNext(systemStatus.collection?.next_run)}
                </p>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Last run: {formatDateTime(systemStatus.collection?.last_run)}
                </p>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  {systemStatus.collection?.enabled_sources || 0} sources enabled
                </p>
              </div>

              {/* Pipeline Activity */}
              <div className="border-l-4 border-green-500 pl-4">
                <div className="flex items-center">
                  <Zap className="h-5 w-5 text-green-500 mr-2" />
                  <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100">Pipeline</h4>
                </div>
                <p className="mt-2 text-2xl font-semibold text-gray-900 dark:text-gray-100">
                  {systemStatus.pipeline?.active_tasks?.length || 0} active
                </p>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Queue: {systemStatus.pipeline?.queue_depth || 0} tasks
                </p>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Workers: {systemStatus.pipeline?.workers_active || 0}/{systemStatus.pipeline?.workers_total || 0}
                </p>
              </div>

              {/* Ingestion Rate */}
              <div className="border-l-4 border-blue-500 pl-4">
                <div className="flex items-center">
                  <TrendingUp className="h-5 w-5 text-blue-500 mr-2" />
                  <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100">Ingestion</h4>
                </div>
                <p className="mt-2 text-2xl font-semibold text-gray-900 dark:text-gray-100">
                  {systemStatus.performance?.ingestion_rate_per_hour?.toFixed(1) || 0}/hr
                </p>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Threats collected (24h avg)
                </p>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Total: {systemStatus.database?.total_threats || 0}
                </p>
              </div>

              {/* LLM Processing Rate */}
              <div className="border-l-4 border-purple-500 pl-4">
                <div className="flex items-center">
                  <BarChart3 className="h-5 w-5 text-purple-500 mr-2" />
                  <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100">LLM Processing</h4>
                </div>
                <p className="mt-2 text-2xl font-semibold text-gray-900 dark:text-gray-100">
                  {systemStatus.performance?.llm_processing_rate_per_hour || 0}/hr
                </p>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Completions (1h actual)
                </p>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  {systemStatus.performance?.estimated_completion_hours 
                    ? `ETA: ${systemStatus.performance.estimated_completion_hours}h`
                    : 'Backlog: 0'}
                </p>
              </div>
            </div>

            {/* Active Tasks */}
            {systemStatus.pipeline?.active_tasks && systemStatus.pipeline.active_tasks.length > 0 && (
              <div className="mt-5 pt-5 border-t border-gray-200 dark:border-gray-700">
                <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-3">Active Tasks</h4>
                <div className="space-y-2">
                  {systemStatus.pipeline.active_tasks.slice(0, 5).map((task: any, idx: number) => (
                    <div key={idx} className="flex items-center justify-between text-sm">
                      <span className="text-gray-600 dark:text-gray-400">{task.name.split('.').pop()}</span>
                      <span className={`px-2 py-1 rounded text-xs ${
                        task.status === 'running' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
                      }`}>
                        {task.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Service Health */}
            <div className="mt-5 pt-5 border-t border-gray-200 dark:border-gray-700">
              <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-3">Services</h4>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                {systemStatus.services && Object.entries(systemStatus.services).map(([service, status]: [string, any]) => {
                  // Format service names for display
                  const displayName = service
                    .replace('celery_worker', 'Worker')
                    .replace('celery_beat', 'Scheduler')
                    .replace('postgres', 'Database')
                    .replace('redis', 'Redis')
                    .replace('minio', 'Storage')
                    .replace('ollama', 'LLM');
                  
                  return (
                    <div key={service} className="flex items-center">
                      <div className={`h-2 w-2 rounded-full mr-2 ${
                        status === 'healthy' || status === 'up' ? 'bg-green-500' : 
                        status === 'degraded' ? 'bg-yellow-500' : 'bg-red-500'
                      }`} />
                      <span className="text-xs text-gray-600 dark:text-gray-400">{displayName}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Ollama Configuration */}
            {ollamaConfig && ollamaConfig.status === 'ok' && (
              <div className="mt-5 pt-5 border-t border-gray-200 dark:border-gray-700">
                <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-3">Ollama Configuration</h4>
                <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center mb-2">
                        <div className={`h-3 w-3 rounded-full mr-2 ${
                          ollamaConfig.detected_environment?.has_gpu ? 'bg-green-500' : 'bg-yellow-500'
                        }`} />
                        <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                          {ollamaConfig.detected_environment?.description}
                        </span>
                      </div>
                      <div className="text-xs text-gray-600 dark:text-gray-400 space-y-1">
                        <p>Workers: {ollamaConfig.current_config?.celery_workers} 
                          {ollamaConfig.recommendations?.adjustment_needed && (
                            <span className="text-orange-600 dark:text-orange-400"> (recommended: {ollamaConfig.recommendations?.recommended_workers})</span>
                          )}
                        </p>
                        <p>Timeout: {ollamaConfig.current_config?.ollama_timeout}s
                          {ollamaConfig.recommendations?.adjustment_needed && (
                            <span className="text-orange-600 dark:text-orange-400"> (recommended: {ollamaConfig.recommendations?.recommended_timeout}s)</span>
                          )}
                        </p>
                        <p className="text-gray-500 dark:text-gray-400">{ollamaConfig.recommendations?.expected_throughput}</p>
                      </div>
                    </div>
                    {ollamaConfig.recommendations?.adjustment_needed && (
                      <div className="ml-4">
                        <span className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200">
                          Tuning Recommended
                        </span>
                      </div>
                    )}
                  </div>
                  {ollamaConfig.recommendations?.adjustment_needed && (
                    <div className="mt-3 pt-3 border-t border-gray-200 dark:border-gray-600">
                      <p className="text-xs text-gray-600 dark:text-gray-400">
                        <strong>Tip:</strong> {ollamaConfig.recommendations?.reasoning}
                      </p>
                      <a 
                        href="https://github.com/yourusername/ai-threat-intel/blob/main/src/minimal-local/PERFORMANCE_TUNING.md"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 mt-1 inline-block"
                      >
                        View Performance Tuning Guide →
                      </a>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* LLM Analysis Status */}
      {llmStats && (
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
          <div className="px-4 py-5 sm:px-6 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <div>
              <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-gray-100">
                LLM Analysis Status
              </h3>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                Ollama threat analysis progress
              </p>
            </div>
            {llmStats.llm_analysis?.failed > 0 && (
              <button
                onClick={() => retryMutation.mutate(retryLimit)}
                disabled={retryMutation.isPending}
                className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
              >
                <RefreshCw className={`h-4 w-4 mr-2 ${retryMutation.isPending ? 'animate-spin' : ''}`} />
                Retry Failed ({retryLimit})
              </button>
            )}
          </div>
          <div className="px-4 py-5 sm:p-6">
            {/* Progress Bar */}
            <div className="mb-6">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  Completion: {llmStats.llm_analysis?.completion_rate}%
                </span>
                <span className="text-sm text-gray-500 dark:text-gray-400">
                  {llmStats.llm_analysis?.complete} / {llmStats.total_threats}
                </span>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2.5">
                <div 
                  className="bg-indigo-600 dark:bg-indigo-500 h-2.5 rounded-full transition-all duration-500"
                  style={{ width: `${llmStats.llm_analysis?.completion_rate}%` }}
                />
              </div>
            </div>

            {/* Status Cards */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <div className="border-l-4 border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded">
                <div className="flex items-center">
                  <Clock className="h-5 w-5 text-yellow-600 dark:text-yellow-400 mr-2" />
                  <div>
                    <p className="text-sm font-medium text-yellow-800 dark:text-yellow-300">Pending</p>
                    <p className="text-2xl font-bold text-yellow-900 dark:text-yellow-200">
                      {llmStats.llm_analysis?.pending || 0}
                    </p>
                  </div>
                </div>
              </div>

              <div className="border-l-4 border-green-500 bg-green-50 dark:bg-green-900/20 p-4 rounded">
                <div className="flex items-center">
                  <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400 mr-2" />
                  <div>
                    <p className="text-sm font-medium text-green-800 dark:text-green-300">Complete</p>
                    <p className="text-2xl font-bold text-green-900 dark:text-green-200">
                      {llmStats.llm_analysis?.complete || 0}
                    </p>
                  </div>
                </div>
              </div>

              <div className="border-l-4 border-red-500 bg-red-50 dark:bg-red-900/20 p-4 rounded">
                <div className="flex items-center">
                  <XCircle className="h-5 w-5 text-red-600 dark:text-red-400 mr-2" />
                  <div>
                    <p className="text-sm font-medium text-red-800 dark:text-red-300">Failed</p>
                    <p className="text-2xl font-bold text-red-900 dark:text-red-200">
                      {llmStats.llm_analysis?.failed || 0}
                    </p>
                    {llmStats.llm_analysis?.failure_rate > 0 && (
                      <p className="text-xs text-red-600 dark:text-red-400 mt-1">
                        {llmStats.llm_analysis.failure_rate}% failure rate
                      </p>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Failed Threats Sample */}
            {llmStats.failed_sample && llmStats.failed_sample.length > 0 && (
              <div className="mt-6 pt-6 border-t border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100">Recent Failed Analyses</h4>
                  <div className="flex items-center space-x-2">
                    <label htmlFor="retry-limit" className="text-xs text-gray-500 dark:text-gray-400">
                      Retry limit:
                    </label>
                    <select
                      id="retry-limit"
                      value={retryLimit}
                      onChange={(e) => setRetryLimit(Number(e.target.value))}
                      className="text-xs border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200 rounded-md"
                    >
                      <option value={50}>50</option>
                      <option value={100}>100</option>
                      <option value={200}>200</option>
                      <option value={500}>500</option>
                    </select>
                  </div>
                </div>
                <div className="space-y-2">
                  {llmStats.failed_sample.slice(0, 5).map((threat: any) => (
                    <div key={threat.id} className="flex items-start justify-between text-sm bg-gray-50 dark:bg-gray-700 p-2 rounded">
                      <div className="flex-1 min-w-0">
                        <p className="text-gray-900 dark:text-gray-100 truncate">{threat.title}</p>
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                          {new Date(threat.ingested_at).toLocaleString()}
                        </p>
                      </div>
                      <Link
                        to={`/threats/${threat.id}`}
                        className="ml-2 text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 text-xs whitespace-nowrap"
                      >
                        View →
                      </Link>
                    </div>
                  ))}
                </div>
                {llmStats.llm_analysis?.failed > 5 && (
                  <p className="mt-3 text-xs text-gray-500 dark:text-gray-400 text-center">
                    Showing 5 of {llmStats.llm_analysis.failed} failed analyses
                  </p>
                )}
              </div>
            )}

            {/* Retry Success Message */}
            {retryMutation.isSuccess && (
              <div className="mt-4 p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-md">
                <div className="flex items-center">
                  <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400 mr-2" />
                  <p className="text-sm text-green-800 dark:text-green-300">
                    {retryMutation.data?.message || 'Successfully queued threats for retry'}
                  </p>
                </div>
              </div>
            )}

            {/* Retry Error Message */}
            {retryMutation.isError && (
              <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md">
                <div className="flex items-center">
                  <AlertCircle className="h-5 w-5 text-red-600 dark:text-red-400 mr-2" />
                  <p className="text-sm text-red-800 dark:text-red-300">
                    Failed to retry analyses. Please try again.
                  </p>
                </div>
              </div>
            )}

            {/* Info Note */}
            <div className="mt-6 p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-md">
              <p className="text-xs text-blue-800 dark:text-blue-300">
                <strong>Note:</strong> {llmStats.note}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Recent Threats */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
        <div className="px-4 py-5 sm:px-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-gray-100">
                Recent Threats
              </h3>
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                Most recently ingested threats (by database insert time)
              </p>
            </div>
          </div>
        </div>
        <ul className="divide-y divide-gray-200 dark:divide-gray-700">
          {recentThreats?.threats?.map((threat: any) => (
            <li key={threat.id}>
              <Link
                to={`/threats/${threat.id}`}
                className="block hover:bg-gray-50 dark:hover:bg-gray-700 px-4 py-4"
              >
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                      {threat.title}
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400 truncate">
                      {threat.source} • {new Date(threat.ingested_at).toLocaleDateString()}
                    </p>
                  </div>
                  {threat.severity && (
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(threat.severity)}`}>
                      {threat.severity}/10
                    </span>
                  )}
                </div>
              </Link>
            </li>
          ))}
        </ul>
        <div className="px-4 py-4 sm:px-6 border-t border-gray-200 dark:border-gray-700">
          <Link
            to="/threats"
            className="text-sm font-medium text-indigo-600 dark:text-indigo-400 hover:text-indigo-500 dark:hover:text-indigo-300"
          >
            View all threats →
          </Link>
        </div>
      </div>

      {/* High Severity Alerts */}
      {highSeverity?.threats?.length > 0 && (
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
          <div className="px-4 py-5 sm:px-6 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-gray-100">
                  High Severity Alerts
                </h3>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Showing {highSeverity.threats.length} of {highSeverity.count} threats with severity ≥8 (sorted by severity, then ingestion time)
                </p>
              </div>
            </div>
          </div>
          <ul className="divide-y divide-gray-200 dark:divide-gray-700">
            {highSeverity.threats.map((threat: any) => (
              <li key={threat.id}>
                <Link
                  to={`/threats/${threat.id}`}
                  className="block hover:bg-gray-50 dark:hover:bg-gray-700 px-4 py-4"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                        {threat.title}
                      </p>
                      <p className="text-sm text-gray-500 dark:text-gray-400 truncate">
                        {threat.threat_type || 'Unknown type'}
                      </p>
                    </div>
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(threat.severity)}`}>
                      {threat.severity}/10
                    </span>
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Threat Type Info Modal */}
      {showThreatTypeModal && threatTypeInfo && (
        <div className="fixed inset-0 bg-black bg-opacity-50 dark:bg-opacity-70 flex items-center justify-center z-50 p-4" onClick={() => setShowThreatTypeModal(false)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full max-h-[80vh] overflow-hidden" onClick={(e) => e.stopPropagation()}>
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">AI/ML Threat Types</h3>
              <button
                onClick={() => setShowThreatTypeModal(false)}
                className="text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300 focus:outline-none"
              >
                <XCircle className="h-6 w-6" />
              </button>
            </div>
            <div className="px-6 py-4 overflow-y-auto max-h-[calc(80vh-8rem)]">
              <div className="space-y-4">
                {Object.entries(threatTypeInfo.descriptions).map(([type, desc]) => (
                  <div key={type} className="border-l-4 border-indigo-500 pl-4 py-2">
                    <h4 className="font-semibold text-gray-900 dark:text-gray-100 capitalize mb-1">
                      {type.replace(/_/g, ' ')}
                    </h4>
                    <p className="text-sm text-gray-600 dark:text-gray-300">{String(desc)}</p>
                    <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                      {threatTypeInfo.keyword_counts[type]} classification keywords: {threatTypeInfo.keywords?.[type]?.join(', ') || 'N/A'}
                    </p>
                  </div>
                ))}
              </div>
            </div>
            <div className="px-6 py-3 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700 text-xs text-gray-500 dark:text-gray-400">
              {threatTypeInfo.note}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
