import { Moon, Sun } from 'lucide-react'
import { useTheme } from '../contexts/ThemeContext'

export default function Settings() {
  const { darkMode, toggleDarkMode } = useTheme()

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Settings</h1>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Configure system preferences and alerts
        </p>
      </div>

      {/* Appearance Settings */}
      <div className="bg-white dark:bg-gray-800 shadow sm:rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-gray-100">
            Appearance
          </h3>
          <div className="mt-2 max-w-xl text-sm text-gray-500 dark:text-gray-400">
            <p>
              Customize the visual appearance of the interface
            </p>
          </div>
          <div className="mt-5">
            <div className="rounded-md bg-gray-50 dark:bg-gray-700 px-6 py-5 sm:flex sm:items-center sm:justify-between">
              <div className="sm:flex sm:items-start">
                <div className="flex items-center">
                  {darkMode ? (
                    <Moon className="h-5 w-5 text-indigo-600 dark:text-indigo-400 mr-3" />
                  ) : (
                    <Sun className="h-5 w-5 text-yellow-500 mr-3" />
                  )}
                  <div>
                    <div className="text-sm font-medium text-gray-900 dark:text-gray-100">
                      Dark Mode
                    </div>
                    <div className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                      {darkMode ? 'Dark theme enabled' : 'Light theme enabled'}
                    </div>
                  </div>
                </div>
              </div>
              <div className="mt-4 sm:mt-0 sm:ml-6 sm:flex-shrink-0">
                <button
                  type="button"
                  onClick={toggleDarkMode}
                  className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-indigo-600 focus:ring-offset-2 ${
                    darkMode ? 'bg-indigo-600' : 'bg-gray-200'
                  }`}
                  role="switch"
                  aria-checked={darkMode}
                >
                  <span
                    className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                      darkMode ? 'translate-x-5' : 'translate-x-0'
                    }`}
                  />
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white dark:bg-gray-800 shadow sm:rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-gray-100">
            Alert Configuration
          </h3>
          <div className="mt-2 max-w-xl text-sm text-gray-500 dark:text-gray-400">
            <p>
              Alert settings are configured via environment variables. See the README for details on configuring email and webhook alerts.
            </p>
          </div>
          <div className="mt-5">
            <div className="rounded-md bg-gray-50 dark:bg-gray-700 px-6 py-5 sm:flex sm:items-start sm:justify-between">
              <div className="sm:flex sm:items-start">
                <div className="mt-3 sm:mt-0">
                  <div className="text-sm font-medium text-gray-900 dark:text-gray-100">
                    Alert Severity Threshold
                  </div>
                  <div className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                    Currently set to trigger on severity ≥ 8
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white dark:bg-gray-800 shadow sm:rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-gray-100">
            System Information
          </h3>
          <div className="mt-2 max-w-xl text-sm text-gray-500 dark:text-gray-400">
            <p>
              AI Shield Intelligence - Minimal Local Profile
            </p>
            <p className="mt-1">
              Version: 0.1.0
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
