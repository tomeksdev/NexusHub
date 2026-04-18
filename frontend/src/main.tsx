import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

import './index.css'
import App from './App.tsx'
import { AuthProvider } from './lib/auth'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Retry once on failure — the api() client already retries 401 with a
      // refreshed token, so a second retry here would mostly paper over
      // backend errors we'd rather see.
      retry: 1,
      staleTime: 15_000,
      refetchOnWindowFocus: false,
    },
  },
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </QueryClientProvider>
  </StrictMode>,
)
