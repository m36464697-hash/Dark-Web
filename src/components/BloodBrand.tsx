interface BloodBrandProps {
  size?: 'sm' | 'md' | 'lg';
  suffix?: string;
}

export function BloodBrand({ size = 'md', suffix }: BloodBrandProps) {
  const sizeClass =
    size === 'lg'
      ? 'text-3xl sm:text-4xl'
      : size === 'sm'
        ? 'text-base'
        : 'text-xl';

  const dripHeight = size === 'lg' ? 24 : size === 'sm' ? 12 : 16;

  return (
    <span className="inline-flex flex-col items-start leading-none select-none relative" dir="ltr">
      <span className="inline-flex items-baseline gap-2">
        <span
          className={`font-display font-bold tracking-tight text-transparent bg-clip-text bg-gradient-to-b from-zinc-100 via-red-200 to-red-700 ${sizeClass}`}
        >
          Dark Web
        </span>
        {suffix && (
          <span className="text-xs font-mono-tabular text-red-400/90 font-semibold">
            {suffix}
          </span>
        )}
      </span>

      {/* Dripping crimson SVG tendrils directly beneath the wordmark */}
      <svg
        viewBox="0 0 180 28"
        style={{ height: `${dripHeight}px` }}
        className="w-full max-w-[148px] -mt-1 overflow-visible pointer-events-none"
        aria-hidden="true"
      >
        <defs>
          <linearGradient id="crimsonBloodGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#991b1b" />
            <stop offset="55%" stopColor="#dc2626" />
            <stop offset="100%" stopColor="#450a0a" />
          </linearGradient>
        </defs>
        <path
          d="M6,0 L166,0 C162,4 159,5 157,10 C155,15 153,16 151,10 C149,4 142,2 132,2 C125,2 123,7 121,17 C119,23 115,23 114,16 C113,7 109,2 96,2 C86,2 84,6 82,11 C80,15 77,15 76,10 C75,4 67,2 56,2 C48,2 45,8 43,21 C41,27 37,27 36,20 C35,9 31,2 21,2 C14,2 11,5 9,10 C7,13 6,6 6,0 Z"
          fill="url(#crimsonBloodGrad)"
          className="animate-blood-drip"
        />
        <circle cx="39.5" cy="24" r="2.2" fill="#dc2626" className="animate-blood-drop" />
        <circle
          cx="117.5"
          cy="21"
          r="1.9"
          fill="#b91c1c"
          className="animate-blood-drop"
          style={{ animationDelay: '1.4s' }}
        />
      </svg>
    </span>
  );
}
