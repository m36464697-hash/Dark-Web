import { useEffect, useRef } from 'react';

export function CipherBackdrop() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let animationId = 0;

    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    const glyphs = '0123456789ABCDEF#%*+';
    const columnWidth = 28;
    const columns = Math.ceil(window.innerWidth / columnWidth);
    const drops = Array.from({ length: columns }, () => Math.random() * -40);

    let lastTime = 0;
    const renderFrame = (time: number) => {
      if (time - lastTime > 95) {
        lastTime = time;
        ctx.fillStyle = 'rgba(6, 7, 9, 0.22)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.font = '11px "JetBrains Mono", monospace';
        for (let i = 0; i < drops.length; i += 1) {
          if (i % 3 !== 0) continue;
          const char = glyphs[Math.floor(Math.random() * glyphs.length)];
          const x = i * columnWidth;
          const y = drops[i] * 18;
          ctx.fillStyle = Math.random() > 0.92 ? 'rgba(16, 185, 129, 0.24)' : 'rgba(113, 113, 122, 0.14)';
          ctx.fillText(char, x, y);

          if (y > canvas.height && Math.random() > 0.97) {
            drops[i] = 0;
          } else {
            drops[i] += 1;
          }
        }
      }
      if (!prefersReduced) {
        animationId = requestAnimationFrame(renderFrame);
      }
    };

    if (!prefersReduced) {
      animationId = requestAnimationFrame(renderFrame);
    }

    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden" aria-hidden="true">
      <canvas ref={canvasRef} className="w-full h-full opacity-80" />
      <div
        className="absolute inset-0"
        style={{
          backgroundImage:
            'radial-gradient(circle at 50% 0%, rgba(16, 185, 129, 0.06), transparent 55%), linear-gradient(to right, rgba(255,255,255,0.02) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,0.02) 1px, transparent 1px)',
          backgroundSize: '100% 100%, 64px 64px, 64px 64px',
        }}
      />
    </div>
  );
}
