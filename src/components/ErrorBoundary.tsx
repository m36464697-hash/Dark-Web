import React from 'react';
import { ShieldAlert, RotateCcw } from 'lucide-react';

interface State {
  hasError: boolean;
  errorMessage: string;
}

export class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  State
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, errorMessage: '' };
  }

  static getDerivedStateFromError(error: Error): State {
    return {
      hasError: true,
      errorMessage: error.message || 'حدث خطأ غير متوقع في طبقة الحماية.',
    };
  }

  override render() {
    if (this.state.hasError) {
      let readable = this.state.errorMessage;
      try {
        const parsed = JSON.parse(this.state.errorMessage) as {
          error?: string;
          operationType?: string;
          path?: string;
        };
        if (parsed.error) {
          readable = `${parsed.error} (${parsed.operationType || 'op'} · ${parsed.path || 'unknown'})`;
        }
      } catch {
        // Keep raw message if not JSON
      }

      return (
        <div className="min-h-screen bg-[#060709] text-zinc-100 flex items-center justify-center p-6">
          <div className="max-w-lg w-full bg-[#0F1217] border border-red-500/30 rounded-xl p-8 space-y-5">
            <div className="flex items-center gap-3 text-red-400">
              <ShieldAlert className="w-6 h-6 shrink-0" />
              <h1 className="text-xl font-bold">تم رصد اعتراض أمني أو خطأ في النظام</h1>
            </div>
            <p className="text-sm text-zinc-400 leading-relaxed font-mono-tabular break-words">
              {readable}
            </p>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-zinc-100 text-zinc-950 text-sm font-semibold hover:bg-zinc-200 transition-colors cursor-pointer"
            >
              <RotateCcw className="w-4 h-4" />
              إعادة تحميل الجلسة
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
