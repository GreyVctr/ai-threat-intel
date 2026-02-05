import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Search, Filter, X } from 'lucide-react'
import { searchApi } from '../services/api'

export default function SearchPage() {
  const [query, setQuery] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [showFilters, setShowFilters] = useState(false)
  
  // Filter states
  const [threatType, setThreatType] = useState<string>('')
  const [testability, setTestability] = useState<string>('')
  const [severityMin, setSeverityMin] = useState<number | undefined>()
  const [severityMax, setSeverityMax] = useState<number | undefined>()
  const [dateFrom, setDateFrom] = useState<string>('')
  const [dateTo, setDateTo] = useState<string>('')
  const [perPage, setPerPage] = useState<number>(20)
  const [currentPage, setCurrentPage] = useState<number>(1)
  
  // Applied filters for search
  const [appliedFilters, setAppliedFilters] = useState<any>({})

  // Fetch threat types for dropdown
  const { data: threatTypesData } = useQuery({
    queryKey: ['threatTypes'],
    queryFn: () => searchApi.threatTypes(),
  })

  const { data, isLoading } = useQuery({
    queryKey: ['search', searchQuery, appliedFilters, currentPage],
    queryFn: () => searchApi.search({ 
      q: searchQuery || undefined,
      ...appliedFilters,
      page: currentPage,
      per_page: perPage,
    }),
    enabled: searchQuery.length > 0 || Object.keys(appliedFilters).length > 0,
  })

  // Reset to page 1 when filters change
  useEffect(() => {
    setCurrentPage(1)
  }, [searchQuery, appliedFilters])

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setSearchQuery(query)
    applyFilters()
  }

  const applyFilters = () => {
    const filters: any = {}
    if (threatType) filters.threat_type = threatType
    if (testability) filters.testability = testability
    if (severityMin !== undefined) filters.severity_min = severityMin
    if (severityMax !== undefined) filters.severity_max = severityMax
    if (dateFrom) filters.date_from = dateFrom
    if (dateTo) filters.date_to = dateTo
    setAppliedFilters(filters)
    setCurrentPage(1)
  }

  const clearFilters = () => {
    setThreatType('')
    setTestability('')
    setSeverityMin(undefined)
    setSeverityMax(undefined)
    setDateFrom('')
    setDateTo('')
    setAppliedFilters({})
    setCurrentPage(1)
  }

  const hasActiveFilters = Object.keys(appliedFilters).length > 0

  const getSeverityColor = (severity: number) => {
    if (severity >= 9) return 'text-red-600 bg-red-100 dark:bg-red-900 dark:text-red-200'
    if (severity >= 7) return 'text-orange-600 bg-orange-100 dark:bg-orange-900 dark:text-orange-200'
    if (severity >= 5) return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900 dark:text-yellow-200'
    return 'text-green-600 bg-green-100 dark:bg-green-900 dark:text-green-200'
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Search Threats</h1>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Search through threat intelligence data
        </p>
      </div>

      <form onSubmit={handleSearch} className="space-y-4">
        <div className="flex gap-2">
          <div className="flex-1">
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Search className="h-5 w-5 text-gray-400 dark:text-gray-500" />
              </div>
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="block w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md leading-5 bg-white dark:bg-gray-700 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-gray-100 focus:outline-none focus:placeholder-gray-400 dark:focus:placeholder-gray-500 focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                placeholder="Search threats..."
              />
            </div>
          </div>
          <button
            type="button"
            onClick={() => setShowFilters(!showFilters)}
            className={`inline-flex items-center px-4 py-2 border text-sm font-medium rounded-md ${
              hasActiveFilters
                ? 'border-indigo-600 text-indigo-600 bg-indigo-50 dark:border-indigo-400 dark:text-indigo-400 dark:bg-indigo-900/20'
                : 'border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600'
            }`}
          >
            <Filter className="h-4 w-4 mr-2" />
            Filters
            {hasActiveFilters && (
              <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-indigo-600 text-white dark:bg-indigo-500">
                {Object.keys(appliedFilters).length}
              </span>
            )}
          </button>
          <button
            type="submit"
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
          >
            Search
          </button>
        </div>

        {showFilters && (
          <div className="bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-md p-4 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">Filter Options</h3>
              {hasActiveFilters && (
                <button
                  type="button"
                  onClick={clearFilters}
                  className="text-sm text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 flex items-center"
                >
                  <X className="h-4 w-4 mr-1" />
                  Clear all
                </button>
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {/* Threat Type Filter */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Threat Type
                </label>
                <select
                  value={threatType}
                  onChange={(e) => setThreatType(e.target.value)}
                  className="block w-full pl-3 pr-10 py-2 text-sm border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 rounded-md"
                >
                  <option value="">All Types</option>
                  {threatTypesData?.threat_types?.map((type: string) => (
                    <option key={type} value={type}>
                      {type.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
                    </option>
                  ))}
                </select>
              </div>

              {/* Testability Filter */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Testability
                </label>
                <select
                  value={testability}
                  onChange={(e) => setTestability(e.target.value)}
                  className="block w-full pl-3 pr-10 py-2 text-sm border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 rounded-md"
                >
                  <option value="">All</option>
                  <option value="yes">Yes (Runtime Testable)</option>
                  <option value="no">No (Not Testable)</option>
                  <option value="conditional">Conditional</option>
                </select>
              </div>

              {/* Severity Min Filter */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Min Severity
                </label>
                <select
                  value={severityMin ?? ''}
                  onChange={(e) => setSeverityMin(e.target.value ? Number(e.target.value) : undefined)}
                  className="block w-full pl-3 pr-10 py-2 text-sm border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 rounded-md"
                >
                  <option value="">Any</option>
                  {[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((val) => (
                    <option key={val} value={val}>{val}</option>
                  ))}
                </select>
              </div>

              {/* Severity Max Filter */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Max Severity
                </label>
                <select
                  value={severityMax ?? ''}
                  onChange={(e) => setSeverityMax(e.target.value ? Number(e.target.value) : undefined)}
                  className="block w-full pl-3 pr-10 py-2 text-sm border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 rounded-md"
                >
                  <option value="">Any</option>
                  {[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((val) => (
                    <option key={val} value={val}>{val}</option>
                  ))}
                </select>
              </div>

              {/* Date From Filter */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Published From
                </label>
                <input
                  type="date"
                  value={dateFrom}
                  onChange={(e) => setDateFrom(e.target.value)}
                  className="block w-full px-3 py-2 text-sm border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 rounded-md"
                />
              </div>

              {/* Date To Filter */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Published To
                </label>
                <input
                  type="date"
                  value={dateTo}
                  onChange={(e) => setDateTo(e.target.value)}
                  className="block w-full px-3 py-2 text-sm border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 rounded-md"
                />
              </div>

              {/* Results Per Page */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Results Per Page
                </label>
                <select
                  value={perPage}
                  onChange={(e) => setPerPage(Number(e.target.value))}
                  className="block w-full pl-3 pr-10 py-2 text-sm border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 rounded-md"
                >
                  <option value={10}>10</option>
                  <option value={20}>20</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </div>
            </div>

            <div className="flex justify-end">
              <button
                type="button"
                onClick={applyFilters}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700"
              >
                Apply Filters
              </button>
            </div>
          </div>
        )}
      </form>

      {isLoading && (
        <div className="text-center py-12 text-gray-900 dark:text-gray-100">Searching...</div>
      )}

      {data && (
        <div className="bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-md">
          <div className="px-4 py-5 sm:px-6 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <p className="text-sm text-gray-700 dark:text-gray-300">
              Found {data.total} results
              {hasActiveFilters && (
                <span className="ml-2 text-gray-500 dark:text-gray-400">
                  (filtered)
                </span>
              )}
            </p>
            {data.total_pages > 1 && (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={!data.has_prev}
                  className="px-3 py-1 text-sm border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-600"
                >
                  Previous
                </button>
                <span className="text-sm text-gray-700 dark:text-gray-300">
                  Page {data.page} of {data.total_pages}
                </span>
                <button
                  onClick={() => setCurrentPage(p => p + 1)}
                  disabled={!data.has_next}
                  className="px-3 py-1 text-sm border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-600"
                >
                  Next
                </button>
              </div>
            )}
          </div>
          <ul className="divide-y divide-gray-200 dark:divide-gray-700">
            {data.results?.map((threat: any) => (
              <li key={threat.id}>
                <Link
                  to={`/threats/${threat.id}`}
                  className="block hover:bg-gray-50 dark:hover:bg-gray-700 px-4 py-4"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex-1 min-w-0 pr-4">
                      <p className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                        {threat.title}
                      </p>
                      <p className="text-sm text-gray-500 dark:text-gray-400 truncate mt-1">
                        {threat.description || 'No description'}
                      </p>
                      <div className="mt-2 flex items-center text-sm text-gray-500 dark:text-gray-400">
                        <span>{threat.source}</span>
                        {threat.threat_type && (
                          <>
                            <span className="mx-2">•</span>
                            <span className="capitalize">{threat.threat_type.replace(/_/g, ' ')}</span>
                          </>
                        )}
                        {threat.published_at && (
                          <>
                            <span className="mx-2">•</span>
                            <span>{new Date(threat.published_at).toLocaleDateString()}</span>
                          </>
                        )}
                      </div>
                    </div>
                    {threat.severity && (
                      <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getSeverityColor(threat.severity)}`}>
                        {threat.severity}/10
                      </span>
                    )}
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
