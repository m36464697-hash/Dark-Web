import React, { useEffect, useMemo, useState } from 'react';
import { signOut, type User } from 'firebase/auth';
import { collection, onSnapshot, query, where } from 'firebase/firestore';
import {
  Eye,
  FileText,
  Film,
  Image as ImageIcon,
  KeyRound,
  Lock,
  LogOut,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShoppingBag,
  Unlock,
} from 'lucide-react';
import { decryptPayload } from '../lib/crypto';
import { auth, db, handleFirestoreError, OperationType } from '../lib/firebase';
import type { AdminRecord, ContentType, SystemSettings, UserProfile, VaultContent } from '../types';
import { BloodBrand } from './BloodBrand';

interface DarkWebPortalProps {
  firebaseUser: User;
  userProfile: UserProfile | null;
  adminRecord: AdminRecord | null;
  isOwner: boolean;
  systemSettings: SystemSettings | null;
  onNavigateAdmin: () => void;
}

const TYPE_LABELS: Record<ContentType, string> = {
  video: 'تسجيل فيديو',
  image: 'وثيقة مصورة',
  message: 'ملف سري / رسالة',
  product: 'عهدة / منتج خاص',
};

const CLASSIFICATION_LABELS: Record<VaultContent['classification'], string> = {
  standard: 'سري — أعضاء موثقون',
  confidential: 'سري للغاية',
  encrypted: 'مشفر AES-256',
};

function formatTimestamp(ts?: { toDate?: () => Date } | null): string {
  if (!ts || typeof ts.toDate !== 'function') return 'الآن';
  return new Intl.DateTimeFormat('ar-EG', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(ts.toDate());
}

function getEmbedUrl(url: string): string | null {
  try {
    const parsed = new URL(url);
    if (parsed.hostname.includes('youtube.com') && parsed.searchParams.get('v')) {
      return `https://www.youtube.com/embed/${parsed.searchParams.get('v')}`;
    }
    if (parsed.hostname === 'youtu.be') {
      return `https://www.youtube.com/embed/${parsed.pathname.replace('/', '')}`;
    }
    return null;
  } catch {
    return null;
  }
}

export function DarkWebPortal({
  firebaseUser,
  userProfile,
  adminRecord,
  isOwner,
  systemSettings,
  onNavigateAdmin,
}: DarkWebPortalProps) {
  const [items, setItems] = useState<VaultContent[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState<'all' | ContentType>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const [passphrases, setPassphrases] = useState<Record<string, string>>({});
  const [decryptedMap, setDecryptedMap] = useState<
    Record<string, { body?: string; mediaUrl?: string }>
  >({});
  const [decryptErrors, setDecryptErrors] = useState<Record<string, string>>({});
  const [activeMediaError, setActiveMediaError] = useState<Record<string, boolean>>({});
  const [selectedItem, setSelectedItem] = useState<VaultContent | null>(null);

  const canAccessAdmin = isOwner || Boolean(adminRecord?.active);
  const allowDownloads = systemSettings?.allowDownloads !== false;
  const watermarkMedia = Boolean(systemSettings?.watermarkMedia);
  const watermarkLabel = `${firebaseUser.email || 'MEMBER'} · ${(userProfile?.securityFingerprint || firebaseUser.uid).slice(0, 10)}`;

  useEffect(() => {
    const q = query(
      collection(db, 'content'),
      where('visibility', '==', 'published')
    );

    const unsubscribe = onSnapshot(
      q,
      (snapshot) => {
        const loaded: VaultContent[] = snapshot.docs
          .map((d) => d.data() as VaultContent)
          .sort((a, b) => {
            const ta = a.createdAt && typeof a.createdAt.toMillis === 'function' ? a.createdAt.toMillis() : 0;
            const tb = b.createdAt && typeof b.createdAt.toMillis === 'function' ? b.createdAt.toMillis() : 0;
            return tb - ta;
          });
        setItems(loaded);
        setLoading(false);
      },
      (error) => {
        setLoading(false);
        handleFirestoreError(error, OperationType.LIST, 'content');
      }
    );

    return () => unsubscribe();
  }, []);

  const filteredItems = useMemo(() => {
    return items.filter((item) => {
      if (filterType !== 'all' && item.type !== filterType) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.trim().toLowerCase();
        const hay = `${item.title} ${item.summary || ''} ${item.authorName}`.toLowerCase();
        return hay.includes(q);
      }
      return true;
    });
  }, [items, filterType, searchQuery]);

  const handleDecryptItem = async (item: VaultContent) => {
    const key = passphrases[item.id] || '';
    if (!key) {
      setDecryptErrors((prev) => ({ ...prev, [item.id]: 'أدخل مفتاح فك التشفير أولاً.' }));
      return;
    }
    if (!item.encryptionIv || !item.encryptionSalt || !item.body) {
      setDecryptErrors((prev) => ({ ...prev, [item.id]: 'بيانات التشفير غير مكتملة.' }));
      return;
    }
    try {
      const plaintext = await decryptPayload(
        item.body,
        item.encryptionIv,
        item.encryptionSalt,
        key
      );
      let parsed: { body?: string; mediaUrl?: string } = { body: plaintext };
      try {
        const json = JSON.parse(plaintext) as { body?: string; mediaUrl?: string };
        if (typeof json === 'object' && json !== null) {
          parsed = json;
        }
      } catch {
        parsed = { body: plaintext };
      }
      setDecryptedMap((prev) => ({ ...prev, [item.id]: parsed }));
      setDecryptErrors((prev) => ({ ...prev, [item.id]: '' }));
    } catch {
      setDecryptErrors((prev) => ({
        ...prev,
        [item.id]: 'مفتاح فك التشفير غير صحيح أو تم تعديل الحزمة.',
      }));
    }
  };

  if (systemSettings?.emergencyLockdown && !canAccessAdmin) {
    return (
      <div className="min-h-screen flex items-center justify-center p-6 relative z-10">
        <div className="max-w-lg w-full bg-[#0F1217] border border-red-600/50 rounded-xl p-8 space-y-5">
          <div className="flex items-center justify-between">
            <BloodBrand size="md" />
            <ShieldAlert className="w-7 h-7 text-red-500 shrink-0" />
          </div>
          <h1 className="text-xl font-bold text-red-400">
            تم تفعيل الإغلاق الطارئ الشامل — الوصول مقيد تماماً
          </h1>
          <p className="text-sm text-zinc-300 leading-relaxed">
            {systemSettings.vaultNotice ||
              'أصدرت إدارة المنصة أمر إغلاق أمني فوري لجميع الجلسات. تم تجميد عرض الملفات السرية مؤقتاً لحماية سرية البيانات.'}
          </p>
          <button
            type="button"
            onClick={() => signOut(auth)}
            className="px-4 py-2.5 rounded-lg bg-red-950/60 border border-red-700/50 text-red-200 text-sm font-semibold hover:bg-red-900/60 transition-colors cursor-pointer"
          >
            إنهاء الجلسة وتسجيل الخروج
          </button>
        </div>
      </div>
    );
  }

  if (systemSettings?.maintenanceMode && !canAccessAdmin) {
    return (
      <div className="min-h-screen flex items-center justify-center p-6 relative z-10">
        <div className="max-w-lg w-full bg-[#0F1217] border border-amber-500/30 rounded-xl p-8 space-y-5">
          <div className="flex items-center gap-3 text-amber-400">
            <Shield className="w-6 h-6 shrink-0" />
            <h1 className="text-xl font-bold">الخزنة في وضع الصيانة والإغلاق المؤقت</h1>
          </div>
          <p className="text-sm text-zinc-300 leading-relaxed">
            {systemSettings.vaultNotice ||
              'يقوم مالك المنصة حالياً بإجراء تحديثات أمنية وتشفير إضافي. يرجى العودة لاحقاً.'}
          </p>
          <button
            type="button"
            onClick={() => signOut(auth)}
            className="px-4 py-2 rounded-lg bg-zinc-900 border border-zinc-700 text-zinc-200 text-sm font-semibold hover:bg-zinc-800 transition-colors cursor-pointer"
          >
            تسجيل الخروج
          </button>
        </div>
      </div>
    );
  }

  const renderMediaBlock = (
    item: VaultContent,
    effectiveMedia: string,
    isModal = false
  ) => {
    const embedUrl = getEmbedUrl(effectiveMedia);
    const heightClass = isModal ? 'max-h-[420px]' : 'aspect-video';

    if (item.type === 'image') {
      if (activeMediaError[item.id]) {
        return (
          <div className={`rounded-lg border border-zinc-800 bg-[#090B0E] ${heightClass} min-h-[180px] flex flex-col items-center justify-center p-4 text-zinc-500 gap-2`}>
            <ImageIcon className="w-6 h-6" />
            <span className="text-xs">وثيقة محمية ({item.title})</span>
          </div>
        );
      }

      return (
        <div
          className={`relative rounded-lg overflow-hidden border border-zinc-800 bg-[#090B0E] ${heightClass}`}
          onContextMenu={!allowDownloads ? (e) => e.preventDefault() : undefined}
        >
          <img
            src={effectiveMedia}
            alt={item.title}
            referrerPolicy="no-referrer"
            draggable={allowDownloads}
            onError={() =>
              setActiveMediaError((prev) => ({ ...prev, [item.id]: true }))
            }
            className="w-full h-full object-cover"
          />
          {watermarkMedia && (
            <div className="pointer-events-none select-none absolute inset-0 flex items-center justify-center overflow-hidden">
              <span className="-rotate-12 text-[11px] font-mono-tabular text-zinc-200/35 bg-black/25 px-3 py-1 rounded tracking-wider">
                {watermarkLabel}
              </span>
            </div>
          )}
        </div>
      );
    }

    if (item.type === 'video') {
      return (
        <div
          className={`relative rounded-lg overflow-hidden border border-zinc-800 bg-[#090B0E] ${heightClass}`}
          onContextMenu={!allowDownloads ? (e) => e.preventDefault() : undefined}
        >
          {embedUrl ? (
            <iframe
              src={embedUrl}
              title={item.title}
              className="w-full h-full min-h-[200px]"
              allowFullScreen
            />
          ) : (
            <video
              src={effectiveMedia}
              controls
              playsInline
              preload="metadata"
              controlsList={!allowDownloads ? 'nodownload noremoteplayback' : undefined}
              disablePictureInPicture={!allowDownloads}
              className="w-full h-full object-contain bg-black"
            />
          )}
          {watermarkMedia && (
            <div className="pointer-events-none select-none absolute top-3 left-3 bg-black/45 px-2.5 py-1 rounded text-[10px] font-mono-tabular text-zinc-200/50">
              {watermarkLabel}
            </div>
          )}
        </div>
      );
    }

    if (item.type === 'product' && effectiveMedia) {
      return (
        <div
          className={`relative rounded-lg overflow-hidden border border-zinc-800 bg-[#090B0E] ${heightClass}`}
          onContextMenu={!allowDownloads ? (e) => e.preventDefault() : undefined}
        >
          {/\.(mp4|webm|mov|ogv)(\?|$)/i.test(effectiveMedia) ? (
            <video
              src={effectiveMedia}
              controls
              playsInline
              preload="metadata"
              controlsList={!allowDownloads ? 'nodownload noremoteplayback' : undefined}
              disablePictureInPicture={!allowDownloads}
              className="w-full h-full object-contain bg-black"
            />
          ) : (
            <img
              src={effectiveMedia}
              alt={item.title}
              referrerPolicy="no-referrer"
              draggable={allowDownloads}
              className="w-full h-full object-cover"
            />
          )}
          {watermarkMedia && (
            <div className="pointer-events-none select-none absolute inset-0 flex items-center justify-center overflow-hidden">
              <span className="-rotate-12 text-[11px] font-mono-tabular text-zinc-200/35 bg-black/25 px-3 py-1 rounded">
                {watermarkLabel}
              </span>
            </div>
          )}
        </div>
      );
    }

    return null;
  };

  return (
    <div className="min-h-screen relative z-10 flex flex-col">
      {/* Strict 3-Zone Top Bar */}
      <header className="sticky top-0 z-30 bg-[#060709]/92 backdrop-blur-md border-b border-zinc-800/80">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-8">
          {/* Zone 1: Blood-dripping Brand Wordmark */}
          <button
            type="button"
            onClick={() => setFilterType('all')}
            className="whitespace-nowrap shrink-0 cursor-pointer flex items-center pt-1"
            aria-label="العودة إلى الرئيسية"
          >
            <BloodBrand size="sm" />
          </button>

          {/* Zone 2: Concise single-line navigation links */}
          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-zinc-400">
            {(
              [
                ['all', 'الكل'],
                ['video', 'الفيديوهات'],
                ['image', 'الصور'],
                ['message', 'الملفات والرسائل'],
                ['product', 'المنتجات'],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                onClick={() => setFilterType(key)}
                className={`whitespace-nowrap shrink-0 transition-colors pb-1 border-b cursor-pointer ${
                  filterType === key
                    ? 'text-zinc-100 border-red-600'
                    : 'border-transparent hover:text-zinc-200'
                }`}
              >
                {label}
              </button>
            ))}
          </nav>

          {/* Zone 3: Single primary action */}
          <div className="flex items-center gap-3 shrink-0">
            {canAccessAdmin ? (
              <button
                type="button"
                onClick={onNavigateAdmin}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-zinc-950 text-xs font-bold whitespace-nowrap shrink-0 transition-colors cursor-pointer"
              >
                لوحة تحكم الأدمن
              </button>
            ) : (
              <button
                type="button"
                onClick={() => signOut(auth)}
                className="px-4 py-2 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-200 text-xs font-semibold whitespace-nowrap shrink-0 transition-colors cursor-pointer"
              >
                تسجيل الخروج
              </button>
            )}
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-10 space-y-12">
        {/* Hero Split */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
          <div className="lg:col-span-7 bg-[#0F1217] border border-zinc-800/90 rounded-xl p-8 flex flex-col justify-between space-y-8">
            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-400 font-mono-tabular">
                <span>AES-256-GCM</span>
                <span aria-hidden="true">·</span>
                <span>ملف موثق بالبريد</span>
                <span aria-hidden="true">·</span>
                <span>{userProfile?.securityFingerprint || 'VERIFIED'}</span>
              </div>

              <h1 className="text-3xl sm:text-4xl font-bold text-zinc-100 leading-tight">
                {systemSettings?.siteTitle || 'Dark Web'} — الأرشيف السري للملفات والقضايا المصنفة
              </h1>

              <p className="text-sm sm:text-base text-zinc-400 leading-relaxed max-w-2xl">
                {systemSettings?.vaultNotice ||
                  'بوابة سرية مغلقة لتبادل المعلومات الاستخباراتية، ملفات القضايا، التسجيلات الميدانية، والوثائق الحساسة بإشراف حصري من إدارة المنصة.'}
              </p>
            </div>

            <div className="pt-6 border-t border-zinc-800/80 flex flex-wrap items-center justify-between gap-4">
              <div className="text-xs text-zinc-400 space-y-1">
                <div>
                  العضو الموثق:{' '}
                  <span className="text-zinc-200 font-semibold">
                    {userProfile?.fullName || firebaseUser.displayName || firebaseUser.email}
                  </span>
                </div>
                <div className="font-mono-tabular text-zinc-500">
                  {firebaseUser.email} · المستوى:{' '}
                  {isOwner
                    ? 'رئيس الموقع'
                    : adminRecord?.active
                      ? 'أدمن مفوض'
                      : userProfile?.clearanceLevel === 'elevated'
                        ? 'تصريح متقدم'
                        : 'تصريح قياسي'}
                </div>
              </div>

              <button
                type="button"
                onClick={() => signOut(auth)}
                className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-[#090B0E] border border-zinc-800 hover:border-red-500/40 text-zinc-300 text-xs font-semibold transition-colors cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5" />
                إنهاء الجلسة
              </button>
            </div>
          </div>

          <div className="lg:col-span-5 relative rounded-xl overflow-hidden border border-zinc-800/90 min-h-[280px] bg-[#090B0E]">
            <img
              src="/src/assets/images/hacker_terminal_hero_1794920207041.jpg"
              alt="مشغل أمني أمام شاشات النظام السرية"
              referrerPolicy="no-referrer"
              className="w-full h-full object-cover"
            />
            <div className="absolute inset-0 bg-gradient-to-t from-[#060709]/95 via-[#060709]/35 to-transparent" />
            <div className="absolute bottom-5 right-5 left-5 flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <img
                  src="/src/assets/images/hacker_hood_emblem_1794920209158.jpg"
                  alt="شعار Dark Web"
                  referrerPolicy="no-referrer"
                  className="w-10 h-10 rounded-lg object-cover border border-red-800/60"
                />
                <div>
                  <p className="text-sm font-bold text-zinc-100">مستودع الملفات السرية</p>
                  <p className="text-xs text-zinc-400 font-mono-tabular">
                    الملفات المنشورة: {items.length}
                  </p>
                </div>
              </div>
              <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
            </div>
          </div>
        </section>

        {/* Filter & Search Toolbar */}
        <section className="space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-zinc-800/80 pb-5">
            <div className="flex items-center gap-1 p-1 bg-[#0F1217] border border-zinc-800 rounded-lg overflow-x-auto">
              {(
                [
                  ['all', 'الكل'],
                  ['video', 'فيديوهات'],
                  ['image', 'صور'],
                  ['message', 'ملفات ورسائل'],
                  ['product', 'منتجات'],
                ] as const
              ).map(([key, label]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setFilterType(key)}
                  className={`px-3.5 py-2 rounded-md text-xs font-semibold whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                    filterType === key
                      ? 'bg-zinc-800 text-zinc-100'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="relative w-full md:w-80">
              <Search className="w-4 h-4 text-zinc-500 absolute right-3 top-1/2 -translate-y-1/2" />
              <input
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="ابحث داخل الملفات والتقارير..."
                className="w-full bg-[#0F1217] border border-zinc-800 focus:border-emerald-500 rounded-lg pr-10 pl-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none"
              />
            </div>
          </div>

          {/* Content Grid */}
          {loading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {[1, 2, 3].map((n) => (
                <div
                  key={n}
                  className="h-64 rounded-xl bg-[#0F1217] border border-zinc-800/80 animate-pulse"
                />
              ))}
            </div>
          ) : filteredItems.length === 0 ? (
            <div className="bg-[#0F1217] border border-zinc-800/90 rounded-xl p-12 text-center space-y-4">
              <div className="w-12 h-12 rounded-xl bg-[#090B0E] border border-zinc-800 flex items-center justify-center mx-auto text-zinc-400">
                <Lock className="w-5 h-5" />
              </div>
              <h2 className="text-xl font-bold text-zinc-100">
                {items.length === 0
                  ? 'لا توجد ملفات أو تسجيلات منشورة في الأرشيف حتى الآن'
                  : 'لا توجد نتائج مطابقة للبحث'}
              </h2>
              <p className="text-sm text-zinc-400 max-w-md mx-auto leading-relaxed">
                {items.length === 0
                  ? 'لا تعرض هذه البوابة أي مواد افتراضية أو تجريبية. سيتم إظهار الفيديوهات والوثائق والملفات السرية هنا فور نشرها من قِبل رئيس الموقع أو المدراء المخولين.'
                  : 'جرّب تغيير تصنيف الملف أو مسح كلمة البحث.'}
              </p>
              {canAccessAdmin && items.length === 0 && (
                <button
                  type="button"
                  onClick={onNavigateAdmin}
                  className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-zinc-950 text-xs font-bold transition-colors cursor-pointer"
                >
                  الانتقال إلى لوحة الأدمن لرفع ونشر المحتوى
                </button>
              )}
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredItems.map((item) => {
                const decrypted = decryptedMap[item.id];
                const effectiveBody = item.isEncrypted ? decrypted?.body : item.body;
                const effectiveMedia = item.isEncrypted ? decrypted?.mediaUrl : item.mediaUrl;
                const isLocked = item.isEncrypted && !decrypted;

                return (
                  <article
                    key={item.id}
                    className="bg-[#0F1217] border border-zinc-800/90 rounded-xl overflow-hidden flex flex-col justify-between"
                  >
                    <div className="p-6 space-y-4">
                      <div className="flex items-center justify-between gap-2 text-xs text-zinc-400">
                        <div className="flex items-center gap-2 truncate">
                          {item.type === 'video' && <Film className="w-3.5 h-3.5 text-red-400 shrink-0" />}
                          {item.type === 'image' && <ImageIcon className="w-3.5 h-3.5 text-emerald-400 shrink-0" />}
                          {item.type === 'message' && <FileText className="w-3.5 h-3.5 text-emerald-400 shrink-0" />}
                          {item.type === 'product' && <ShoppingBag className="w-3.5 h-3.5 text-amber-400 shrink-0" />}
                          <span>{TYPE_LABELS[item.type]}</span>
                          <span aria-hidden="true">·</span>
                          <span>{CLASSIFICATION_LABELS[item.classification]}</span>
                        </div>
                        <span className="font-mono-tabular text-zinc-500 shrink-0">
                          {formatTimestamp(item.createdAt)}
                        </span>
                      </div>

                      <h3 className="text-lg font-bold text-zinc-100 leading-snug">{item.title}</h3>

                      {item.summary && (
                        <p className="text-sm text-zinc-400 leading-relaxed line-clamp-3">
                          {item.summary}
                        </p>
                      )}

                      {item.price && item.type === 'product' && (
                        <div className="text-sm font-bold text-emerald-400 font-mono-tabular">
                          القيمة: {item.price}
                        </div>
                      )}

                      {isLocked ? (
                        <div className="p-4 rounded-lg bg-[#090B0E] border border-zinc-800 space-y-3">
                          <div className="flex items-center gap-2 text-xs text-amber-400 font-semibold">
                            <KeyRound className="w-4 h-4 shrink-0" />
                            <span>ملف مشفر بـ AES-256-GCM</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <input
                              type="password"
                              value={passphrases[item.id] || ''}
                              onChange={(e) =>
                                setPassphrases((prev) => ({ ...prev, [item.id]: e.target.value }))
                              }
                              placeholder="أدخل مفتاح فك التشفير..."
                              className="flex-1 min-w-0 bg-[#0F1217] border border-zinc-800 focus:border-emerald-500 rounded-md px-3 py-1.5 text-xs text-zinc-100 focus:outline-none"
                            />
                            <button
                              type="button"
                              onClick={() => handleDecryptItem(item)}
                              className="px-3 py-1.5 rounded-md bg-emerald-600 hover:bg-emerald-500 text-zinc-950 text-xs font-bold whitespace-nowrap shrink-0 cursor-pointer"
                            >
                              فك التشفير
                            </button>
                          </div>
                          {decryptErrors[item.id] && (
                            <p className="text-xs text-red-400">{decryptErrors[item.id]}</p>
                          )}
                        </div>
                      ) : (
                        <>
                          {effectiveMedia && renderMediaBlock(item, effectiveMedia, false)}

                          {item.type === 'image' && !effectiveMedia && (
                            <div className="rounded-lg border border-zinc-800 bg-[#090B0E] aspect-video flex flex-col items-center justify-center p-4 text-zinc-500 gap-2">
                              <ImageIcon className="w-6 h-6" />
                              <span className="text-xs">وثيقة محمية ({item.title})</span>
                            </div>
                          )}

                          {effectiveBody && (
                            <div className="p-3.5 rounded-lg bg-[#090B0E] border border-zinc-800/80 text-xs text-zinc-300 leading-relaxed whitespace-pre-wrap break-words max-h-40 overflow-y-auto">
                              {effectiveBody}
                            </div>
                          )}
                        </>
                      )}
                    </div>

                    <div className="px-6 py-3.5 bg-[#090B0E]/70 border-t border-zinc-800/80 flex items-center justify-between gap-3 text-xs text-zinc-500">
                      <span className="truncate">الناشر: {item.authorName}</span>
                      <button
                        type="button"
                        onClick={() => setSelectedItem(item)}
                        className="inline-flex items-center gap-1.5 text-zinc-300 hover:text-emerald-400 font-semibold whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        فتح الملف الكامل
                      </button>
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </section>
      </main>

      {/* Detail & Cryptographic Verification Modal */}
      {selectedItem && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="max-w-2xl w-full bg-[#0F1217] border border-zinc-800 rounded-xl p-6 sm:p-8 space-y-5 max-h-[90vh] overflow-y-auto">
            <div className="flex items-start justify-between gap-4 border-b border-zinc-800 pb-4">
              <div>
                <div className="text-xs text-zinc-400 mb-1">
                  {TYPE_LABELS[selectedItem.type]} · {CLASSIFICATION_LABELS[selectedItem.classification]}
                </div>
                <h2 className="text-xl font-bold text-zinc-100">{selectedItem.title}</h2>
              </div>
              <button
                type="button"
                onClick={() => setSelectedItem(null)}
                className="px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-xs text-zinc-300 hover:text-zinc-100 cursor-pointer"
              >
                إغلاق
              </button>
            </div>

            {selectedItem.summary && (
              <p className="text-sm text-zinc-300 leading-relaxed">{selectedItem.summary}</p>
            )}

            {selectedItem.isEncrypted && !decryptedMap[selectedItem.id] ? (
              <div className="p-4 rounded-lg bg-[#090B0E] border border-zinc-800 space-y-3">
                <div className="flex items-center gap-2 text-xs text-amber-400 font-semibold">
                  <Lock className="w-4 h-4" />
                  <span>هذا الملف مشفر. أدخل المفتاح لفك التشفير وعرض المحتوى الكامل.</span>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="password"
                    value={passphrases[selectedItem.id] || ''}
                    onChange={(e) =>
                      setPassphrases((prev) => ({ ...prev, [selectedItem.id]: e.target.value }))
                    }
                    placeholder="مفتاح فك التشفير..."
                    className="flex-1 bg-[#0F1217] border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 focus:outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => handleDecryptItem(selectedItem)}
                    className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-zinc-950 text-xs font-bold cursor-pointer"
                  >
                    فك التشفير
                  </button>
                </div>
                {decryptErrors[selectedItem.id] && (
                  <p className="text-xs text-red-400">{decryptErrors[selectedItem.id]}</p>
                )}
              </div>
            ) : (
              <div className="space-y-4">
                {(decryptedMap[selectedItem.id]?.mediaUrl || selectedItem.mediaUrl) &&
                  renderMediaBlock(
                    selectedItem,
                    decryptedMap[selectedItem.id]?.mediaUrl || selectedItem.mediaUrl || '',
                    true
                  )}

                {(decryptedMap[selectedItem.id]?.body || selectedItem.body) && (
                  <div className="p-4 rounded-lg bg-[#090B0E] border border-zinc-800 text-sm text-zinc-200 leading-relaxed whitespace-pre-wrap break-words">
                    {decryptedMap[selectedItem.id]?.body || selectedItem.body}
                  </div>
                )}
              </div>
            )}

            <div className="pt-4 border-t border-zinc-800 space-y-2 text-xs text-zinc-400 font-mono-tabular">
              <div className="flex items-center gap-2 text-emerald-400">
                <Unlock className="w-3.5 h-3.5" />
                <span>بصمة التحقق SHA-256:</span>
              </div>
              <div className="p-2.5 rounded bg-[#090B0E] border border-zinc-800 break-all text-zinc-300">
                {selectedItem.integrityHash}
              </div>
              <div>
                الناشر: {selectedItem.authorName} · تاريخ النشر: {formatTimestamp(selectedItem.createdAt)}
              </div>
            </div>
          </div>
        </div>
      )}

      <footer className="border-t border-zinc-800/80 py-6 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-zinc-500">
          <span>Dark Web — أرشيف سري مشفر</span>
          <div className="flex items-center gap-4">
            {canAccessAdmin && (
              <button
                type="button"
                onClick={onNavigateAdmin}
                className="text-zinc-400 hover:text-zinc-200 cursor-pointer"
              >
                لوحة تحكم الأدمن
              </button>
            )}
            <span className="font-mono-tabular">AES-256-GCM</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
