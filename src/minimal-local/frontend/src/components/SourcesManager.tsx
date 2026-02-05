import { useQuery } from '@tanstack/react-query'
import { sourcesApi } from '../services/api'

export default function SourcesManager() {
  const { data, isLoading } = useQuery({
    queryKey: ['sources'],
    queryFn: sourcesApi.list,
  })

  if (isLoading) {
    return <div className="text-center py-12 text-gray-900 dark:text-gray-100">Loading...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Intelligence Sources</h1>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Configured threat intelligence sources
        </p>
      </div>

      <div className="bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-md">
        <ul className="divide-y divide-gray-200 dark:divide-gray-700">
          {data?.sources?.map((source: any) => (
            <li key={source.name} className="px-4 py-4">
              <div className="flex items-center justify-between">
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                    {source.name}
                  </p>
                  <p className="text-sm text-gray-500 dark:text-gray-400 truncate mt-1">
                    {source.url}
                  </p>
                  <div className="mt-2 flex items-center text-sm text-gray-500 dark:text-gray-400">
                    <span className="capitalize">{source.type}</span>
                    {source.frequency && (
                      <>
                        <span className="mx-2">•</span>
                        <span>{source.frequency}</span>
                      </>
                    )}
                  </div>
                </div>
                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                  source.enabled ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'
                }`}>
                  {source.enabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}
