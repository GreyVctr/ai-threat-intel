import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { threatsApi } from '../services/api'

export default function ThreatList() {
  const [page, setPage] = useState(1)
  const [perPage] = useState(20)

  const { data, isLoading } = useQuery({
    queryKey: ['threats', page, perPage],
    queryFn: () => threatsApi.list({ page, per_page: perPage }),
  })

  const getSeverityColor = (severity: number) => {
    if (severity >= 9) return 'text-red-600 bg-red-100 dark:bg-red-900 dark:text-red-200'
    if (severity >= 7) return 'text-orange-600 bg-orange-100 dark:bg-orange-900 dark:text-orange-200'
    if (severity >= 5) return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900 dark:text-yellow-200'
    return 'text-green-600 bg-green-100 dark:bg-green-900 dark:text-green-200'
  }

  if (isLoading) {
    return <div className="text-center py-12 text-gray-900 dark:text-gray-100">Loading...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Threats</h1>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Browse all threat intelligence data
        </p>
      </div>

      <div className="bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-md">
        <ul className="divide-y divide-gray-200 dark:divide-gray-700">
          {data?.threats?.map((threat: any) => (
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
                      <span className="mx-2">•</span>
                      <span>{new Date(threat.ingested_at).toLocaleDateString()}</span>
                      {threat.threat_type && (
                        <>
                          <span className="mx-2">•</span>
                          <span className="capitalize">{threat.threat_type}</span>
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

      {/* Pagination */}
      {data && data.total_pages > 1 && (
        <div className="flex items-center justify-between border-t border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 px-4 py-3 sm:px-6 rounded-lg shadow">
          <div className="flex flex-1 justify-between sm:hidden">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={!data.has_prev}
              className="relative inline-flex items-center rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
            >
              Previous
            </button>
            <button
              onClick={() => setPage(p => p + 1)}
              disabled={!data.has_next}
              className="relative ml-3 inline-flex items-center rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
            >
              Next
            </button>
          </div>
          <div className="hidden sm:flex sm:flex-1 sm:items-center sm:justify-between">
            <div>
              <p className="text-sm text-gray-700 dark:text-gray-300">
                Showing page <span className="font-medium">{data.page}</span> of{' '}
                <span className="font-medium">{data.total_pages}</span> ({data.total} total threats)
              </p>
            </div>
            <div>
              <nav className="isolate inline-flex -space-x-px rounded-md shadow-sm">
                <button
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={!data.has_prev}
                  className="relative inline-flex items-center rounded-l-md px-2 py-2 text-gray-400 dark:text-gray-500 ring-1 ring-inset ring-gray-300 dark:ring-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 bg-white dark:bg-gray-800"
                >
                  Previous
                </button>
                <span className="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-900 dark:text-gray-100 ring-1 ring-inset ring-gray-300 dark:ring-gray-600 bg-white dark:bg-gray-800">
                  {data.page}
                </span>
                <button
                  onClick={() => setPage(p => p + 1)}
                  disabled={!data.has_next}
                  className="relative inline-flex items-center rounded-r-md px-2 py-2 text-gray-400 dark:text-gray-500 ring-1 ring-inset ring-gray-300 dark:ring-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 bg-white dark:bg-gray-800"
                >
                  Next
                </button>
              </nav>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
