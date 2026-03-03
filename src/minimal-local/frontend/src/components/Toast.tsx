import { useEffect } from 'react'
import { CheckCircle, XCircle, AlertCircle } from 'lucide-react'

export type ToastType = 'success' | 'error' | 'warning'

interface ToastProps {
  message: string
  type: ToastType
  onClose: () => void
  duration?: number
}

export default function Toast({ message, type, onClose, duration = 5000 }: ToastProps) {
  useEffect(() => {
    const timer = setTimeout(() => {
      onClose()
    }, duration)

    return () => clearTimeout(timer)
  }, [duration, onClose])

  const getIcon = () => {
    switch (type) {
      case 'success':
        return <CheckCircle className="h-5 w-5 text-green-500" />
      case 'error':
        return <XCircle className="h-5 w-5 text-red-500" />
      case 'warning':
        return <AlertCircle className="h-5 w-5 text-yellow-500" />
    }
  }

  const getBackgroundColor = () => {
    switch (type) {
      case 'success':
        return 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
      case 'error':
        return 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'
      case 'warning':
        return 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800'
    }
  }

  const getTextColor = () => {
    switch (type) {
      case 'success':
        return 'text-green-800 dark:text-green-300'
      case 'error':
        return 'text-red-800 dark:text-red-300'
      case 'warning':
        return 'text-yellow-800 dark:text-yellow-300'
    }
  }

  return (
    <div className="fixed top-4 right-4 z-50 animate-slide-in">
      <div className={`flex items-center p-4 border rounded-lg shadow-lg ${getBackgroundColor()}`}>
        <div className="flex-shrink-0">{getIcon()}</div>
        <p className={`ml-3 text-sm font-medium ${getTextColor()}`}>{message}</p>
        <button
          onClick={onClose}
          className={`ml-4 inline-flex flex-shrink-0 ${getTextColor()} hover:opacity-75 focus:outline-none`}
        >
          <span className="sr-only">Close</span>
          <XCircle className="h-5 w-5" />
        </button>
      </div>
    </div>
  )
}
