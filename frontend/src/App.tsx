import { BrowserRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { Home } from "./pages/Home";
import { Dashboard } from "./pages/Dashboard";
import { Alerts } from "./pages/Alerts";
import { Anomalies } from "./pages/Anomalies";
import { DLQ } from "./pages/DLQ";
import { Performance } from "./pages/Performance";

// Configure TanStack Query client with global refetch interval
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchInterval: 30000, // 30s auto-refresh globally
      refetchOnWindowFocus: false,
      retry: 1
    }
  }
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          {/* Public Landing */}
          <Route path="/" element={<Home />} />
          
          {/* Inner Operations Panel */}
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/anomalies" element={<Anomalies />} />
          <Route path="/dlq" element={<DLQ />} />
          <Route path="/performance" element={<Performance />} />
        </Routes>
      </BrowserRouter>
      
      {/* Toast Notifications */}
      <Toaster />
    </QueryClientProvider>
  );
}

export default App;
