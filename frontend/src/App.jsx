import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Navbar from './components/Navbar'
import Dashboard from './pages/Dashboard'
import Analyzer from './pages/Analyzer'
import ThreatMap from './pages/ThreatMap'
import History from './pages/History'
import GraphView from './pages/GraphView'
import Settings from './pages/Settings'
import NotFoundPage from './pages/NotFoundPage'

function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-gradient-to-br from-slate-950 via-purple-950 to-slate-900 text-white">
        <Navbar />

        <main className="ml-0 min-h-screen px-4 py-10 sm:px-6 lg:px-8 xl:ml-64">
          <div className="mx-auto max-w-7xl">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/analyze" element={<Analyzer />} />
              <Route path="/threat-map" element={<ThreatMap />} />
              <Route path="/history" element={<History />} />
              <Route path="/graph" element={<GraphView />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="*" element={<NotFoundPage />} />
            </Routes>
          </div>
        </main>
      </div>
    </BrowserRouter>
  )
}

export default App;

