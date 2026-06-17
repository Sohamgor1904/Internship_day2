import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchDlqItems, requeueDlqItems, clearDlqItems } from "../api/dlqApi";
import { Sidebar } from "../components/Sidebar";
import { useAppStore } from "../store/useAppStore";
import { format } from "date-fns";
import { Skull, RefreshCw, Play, Trash2, ShieldAlert } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export function DLQ() {
  const { sidebarCollapsed } = useAppStore();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Fetch DLQ Items Query
  const { data: dlqItems = [], isFetching, refetch } = useQuery({
    queryKey: ["dlqItems"],
    queryFn: fetchDlqItems,
    refetchInterval: 30000 // 30s auto-refresh
  });

  // Requeue DLQ Items Mutation
  const requeueMutation = useMutation({
    mutationFn: requeueDlqItems,
    onSuccess: (data) => {
      // Invalidate DLQ items query cache to refresh depth instantly
      queryClient.invalidateQueries({ queryKey: ["dlqItems"] });
      
      // Determine toast message and styling based on response counts
      if (data.requeued > 0) {
        toast({
          title: "Successful Requeue",
          description: `Requeued ${data.requeued} alerts. Discarded ${data.discarded_max_retries} (max retries).`,
          className: "bg-emerald-950 border-emerald-500/30 text-emerald-300",
        });
      } else if (data.discarded_max_retries > 0) {
        toast({
          title: "All Discarded",
          description: `0 requeued. ${data.discarded_max_retries} discarded as permanent failures.`,
          variant: "destructive", // red/yellow warning fallback
        });
      } else {
        toast({
          title: "Empty DLQ",
          description: "DLQ is empty. Nothing to requeue.",
          className: "bg-blue-950 border-blue-500/30 text-blue-300",
        });
      }
    },
    onError: (error) => {
      toast({
        title: "API Failure",
        description: "Requeue failed. Check pipeline health.",
        variant: "destructive",
      });
    }
  });

  // Clear DLQ Items Mutation
  const clearMutation = useMutation({
    mutationFn: clearDlqItems,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["dlqItems"] });
      toast({
        title: "DLQ Purged",
        description: "All isolated failure logs have been cleared successfully.",
        className: "bg-slate-900 border-slate-800 text-slate-300",
      });
    },
    onError: () => {
      toast({
        title: "Clear Failed",
        description: "Failed to purge the DLQ queue. Please try again.",
        variant: "destructive",
      });
    }
  });

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 flex">
      {/* Sidebar Nav */}
      <Sidebar />

      {/* Main Panel Content */}
      <main className={`flex-1 transition-all duration-300 p-8 ${sidebarCollapsed ? "ml-16" : "ml-64"}`}>
        
        {/* Header */}
        <div className="flex items-center justify-between pb-6 border-b border-slate-200 animate-fade-in-up">
          <div>
            <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight">Dead Letter Queue (DLQ) Monitor</h1>
            <p className="text-xs text-slate-500 mt-1">Administer database transaction failures and control requeue pipelines.</p>
          </div>
          <button
            onClick={() => refetch()}
            className="p-2 bg-white border border-slate-200 rounded-lg text-slate-500 hover:text-slate-800 hover:bg-slate-100 shadow-sm transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${isFetching ? "animate-spin text-indigo-600" : ""}`} />
          </button>
        </div>

        {/* Counter Widget & Admin controls */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-8 items-start animate-fade-in-up animation-delay-100">
          
          {/* Depth Counter Card */}
          <Card className="bg-white border-slate-200 shadow-sm hover-lift lg:col-span-1">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Queue Depth</CardTitle>
              <Skull className={`w-5 h-5 ${dlqItems.length > 0 ? "text-amber-600 animate-bounce" : "text-slate-400"}`} />
            </CardHeader>
            <CardContent>
              <div className="text-5xl font-black text-slate-800">{dlqItems.length}</div>
              <p className="text-xxs text-slate-400 mt-2">Currently isolated poison pill transaction blocks.</p>
            </CardContent>
          </Card>

          {/* Admin Controls Panel */}
          <Card className="bg-white border-slate-200 shadow-sm hover-lift lg:col-span-2">
            <CardHeader>
              <CardTitle className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Queue Controls</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-4">
              <Button
                onClick={() => requeueMutation.mutate()}
                disabled={requeueMutation.isPending || dlqItems.length === 0}
                className="bg-indigo-600 hover:bg-indigo-700 text-white font-semibold flex items-center gap-2 px-6 shadow"
              >
                <Play className="w-4 h-4 fill-white" />
                <span>Requeue Batch</span>
              </Button>

              <Button
                onClick={() => clearMutation.mutate()}
                disabled={clearMutation.isPending || dlqItems.length === 0}
                variant="outline"
                className="border-slate-200 text-slate-650 hover:bg-rose-50 hover:text-rose-600 hover:border-rose-200 font-semibold flex items-center gap-2 px-6"
              >
                <Trash2 className="w-4 h-4" />
                <span>Purge DLQ</span>
              </Button>
            </CardContent>
          </Card>

        </div>

        {/* DLQ Failure Items Table */}
        <div className="mt-8 bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden animate-fade-in-up animation-delay-200">
          <div className="p-5 border-b border-slate-200 flex items-center gap-2 bg-slate-50">
            <ShieldAlert className="w-4 h-4 text-amber-600" />
            <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider">Isolated Transaction Failures</h3>
          </div>
          
          <Table>
            <TableHeader className="bg-slate-50 border-b border-slate-200">
              <TableRow className="hover:bg-transparent border-slate-200">
                <TableHead className="text-slate-500 font-semibold py-4 w-24 text-center">Retry Count</TableHead>
                <TableHead className="text-slate-500 font-semibold w-48">First Failed At</TableHead>
                <TableHead className="text-slate-500 font-semibold w-48">Last Failed At</TableHead>
                <TableHead className="text-slate-500 font-semibold">Transaction Failure Reason</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {dlqItems.length > 0 ? (
                dlqItems.map((item) => (
                  <TableRow 
                    key={item.id}
                    className="border-slate-200 hover:bg-slate-55 transition-colors hover:bg-slate-50"
                  >
                    <TableCell className="font-mono text-center font-bold text-amber-600 py-4.5">
                      {item.retryCount}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-slate-600">
                      {format(new Date(item.firstFailedAt), "yyyy-MM-dd HH:mm:ss")}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-slate-600">
                      {format(new Date(item.lastFailedAt), "yyyy-MM-dd HH:mm:ss")}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-slate-600 select-all leading-normal max-w-md truncate hover:text-slate-900" title={item.failureReason}>
                      {item.failureReason}
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={4} className="text-center py-12 text-slate-400 font-medium">
                    Excellent! The Dead Letter Queue is currently empty.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </main>
    </div>
  );
}
