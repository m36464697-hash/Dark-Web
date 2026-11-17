import React, { useEffect, useState } from 'react';
import {
  createUserWithEmailAndPassword,
  sendEmailVerification,
  sendPasswordResetEmail,
  signInWithEmailAndPassword,
  signInWithPopup,
  signOut,
  updateProfile,
  type User,
} from 'firebase/auth';
import { doc, getDoc, serverTimestamp, setDoc, updateDoc } from 'firebase/firestore';
import {
  AlertTriangle,
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  Mail,
  Phone,
  RefreshCw,
  Shield,
  ShieldCheck,
  User as UserIcon,
} from 'lucide-react';
import { auth, db, googleProvider, handleFirestoreError, OperationType } from '../lib/firebase';
import { generateSecurityFingerprint, generateValidDocId } from '../lib/crypto';
import { BLUEPRINT_LIMITS, SITE_OWNER_EMAIL, type UserProfile } from '../types';
import { BloodBrand } from './BloodBrand';

interface AuthGateProps {
  firebaseUser: User | null;
  userProfile: UserProfile | null;
  registrationOpen: boolean;
  maxFailedLogins?: number;
  isAdminMode?: boolean;
  onVerifiedComplete: () => void;
}

function mapFirebaseAuthError(code: string, fallback: string): string {
  switch (code) {
    case 'auth/invalid-credential':
    case 'auth/wrong-password':
    case 'auth/user-not-found':
      return 'بيانات الدخول غير صحيحة. تأكد من البريد الإلكتروني وكلمة المرور.';
    case 'auth/email-already-in-use':
      return 'هذا البريد الإلكتروني مسجل مسبقاً. انتقل إلى تبويب تسجيل الدخول.';
    case 'auth/weak-password':
      return 'كلمة المرور ضعيفة جداً؛ استخدم 8 خانات على الأقل مع أرقام ورموز.';
    case 'auth/too-many-requests':
      return 'تم رصد محاولات متكررة. تم تقييد الطلب مؤقتاً؛ انتظر بضع دقائق وحاول مجدداً.';
    case 'auth/network-request-failed':
      return 'تعذر الاتصال بخادم المصادقة. تحقق من اتصال الإنترنت وأعد المحاولة.';
    case 'auth/popup-closed-by-user':
    case 'auth/cancelled-popup-request':
      return 'تم إغلاق نافذة المصادقة قبل إتمام الدخول.';
    case 'auth/user-disabled':
      return 'تم تعطيل هذا الحساب من قِبل إدارة النظام.';
    default:
      return fallback;
  }
}

export function AuthGate({
  firebaseUser,
  userProfile,
  registrationOpen,
  maxFailedLogins = 5,
  isAdminMode = false,
  onVerifiedComplete,
}: AuthGateProps) {
  const [mode, setMode] = useState<'register' | 'login'>(isAdminMode ? 'login' : 'register');
  const [fullName, setFullName] = useState('');
  const [phone, setPhone] = useState('');
  const [email, setEmail] = useState(isAdminMode ? SITE_OWNER_EMAIL : '');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [infoMsg, setInfoMsg] = useState('');
  const [showConsoleHelp, setShowConsoleHelp] = useState(false);

  const [failedAttempts, setFailedAttempts] = useState(0);
  const [lockUntilMs, setLockUntilMs] = useState(0);
  const [lockSecondsLeft, setLockSecondsLeft] = useState(0);

  useEffect(() => {
    if (lockUntilMs <= Date.now()) {
      setLockSecondsLeft(0);
      return;
    }
    const timer = setInterval(() => {
      const diff = Math.ceil((lockUntilMs - Date.now()) / 1000);
      if (diff <= 0) {
        setLockUntilMs(0);
        setLockSecondsLeft(0);
        setFailedAttempts(0);
      } else {
        setLockSecondsLeft(diff);
      }
    }, 500);
    return () => clearInterval(timer);
  }, [lockUntilMs]);

  const recordFailedAttempt = () => {
    const next = failedAttempts + 1;
    setFailedAttempts(next);
    if (next >= maxFailedLogins) {
      setLockUntilMs(Date.now() + 60_000);
      setLockSecondsLeft(60);
    }
  };

  const validateTwoWordName = (value: string): boolean => {
    const words = value.trim().split(/\s+/).filter(Boolean);
    return words.length >= 2 && value.trim().length >= BLUEPRINT_LIMITS.FULL_NAME_MIN;
  };

  const validatePhone = (value: string): boolean => {
    const cleaned = value.trim();
    return /^[+0-9\s\-()]{6,32}$/.test(cleaned) && cleaned.replace(/\D/g, '').length >= 6;
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    setInfoMsg('');
    setShowConsoleHelp(false);

    if (!registrationOpen) {
      setErrorMsg('التسجيل مغلق مؤقتاً بقرار من إدارة المنصة.');
      return;
    }

    if (!validateTwoWordName(fullName)) {
      setErrorMsg('يرجى إدخال الاسم الثنائي كاملاً (الاسم الأول واسم العائلة على الأقل).');
      return;
    }

    if (!validatePhone(phone)) {
      setErrorMsg('يرجى إدخال رقم هاتف صحيح (6 أرقام على الأقل).');
      return;
    }

    const trimmedEmail = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
      setErrorMsg('صيغة البريد الإلكتروني غير صالحة.');
      return;
    }

    if (password.length < 8) {
      setErrorMsg('كلمة المرور يجب أن تتكون من 8 خانات على الأقل لضمان التشفير والحماية.');
      return;
    }

    setLoading(true);
    try {
      const cred = await createUserWithEmailAndPassword(auth, trimmedEmail, password);
      const user = cred.user;

      await updateProfile(user, { displayName: fullName.trim() });

      const fingerprint = await generateSecurityFingerprint(user.uid, trimmedEmail);
      const profilePath = `users/${user.uid}`;
      try {
        await setDoc(doc(db, 'users', user.uid), {
          uid: user.uid,
          fullName: fullName.trim().slice(0, BLUEPRINT_LIMITS.FULL_NAME_MAX),
          phone: phone.trim().slice(0, BLUEPRINT_LIMITS.PHONE_MAX),
          email: trimmedEmail.slice(0, BLUEPRINT_LIMITS.EMAIL_MAX),
          emailVerified: user.emailVerified,
          status: 'active',
          clearanceLevel: 'standard',
          securityFingerprint: fingerprint,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
          lastLoginAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, profilePath);
      }

      await sendEmailVerification(user);
      setInfoMsg('تم إنشاء حسابك المشفر وإرسال رابط التحقق إلى بريدك الإلكتروني.');
    } catch (err: unknown) {
      const code = (err as { code?: string })?.code || '';
      if (code === 'auth/operation-not-allowed') {
        setShowConsoleHelp(true);
        setErrorMsg('مزود البريد الإلكتروني وكلمة المرور غير مفعّل بعد في إعدادات Firebase Console.');
      } else {
        setErrorMsg(mapFirebaseAuthError(code, (err as Error)?.message || 'تعذر إنشاء الحساب.'));
      }
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    setInfoMsg('');
    setShowConsoleHelp(false);

    if (lockSecondsLeft > 0) {
      setErrorMsg(`تم قفل المحاولات مؤقتاً لأسباب أمنية. انتظر ${lockSecondsLeft} ثانية.`);
      return;
    }

    const trimmedEmail = email.trim().toLowerCase();
    if (!trimmedEmail || !password) {
      setErrorMsg('يرجى إدخال البريد الإلكتروني وكلمة المرور.');
      return;
    }

    setLoading(true);
    try {
      const cred = await signInWithEmailAndPassword(auth, trimmedEmail, password);
      const user = cred.user;
      await user.getIdToken(true);
      const profileRef = doc(db, 'users', user.uid);
      const snap = await getDoc(profileRef);
      if (snap.exists()) {
        await updateDoc(profileRef, {
          emailVerified: user.emailVerified,
          lastLoginAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
      }
      setFailedAttempts(0);
      if (user.emailVerified) {
        onVerifiedComplete();
      }
    } catch (err: unknown) {
      const code = (err as { code?: string })?.code || '';
      if (
        (code === 'auth/user-not-found' || code === 'auth/invalid-credential') &&
        trimmedEmail === SITE_OWNER_EMAIL.toLowerCase()
      ) {
        try {
          const checkRes = await fetch('/api/admin/verify-bootstrap', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: trimmedEmail, password }),
          });
          const checkData = (await checkRes.json()) as { authorized?: boolean };
          if (checkData.authorized) {
            const created = await createUserWithEmailAndPassword(auth, trimmedEmail, password);
            await updateProfile(created.user, { displayName: 'رئيس الموقع' });
            const fp = await generateSecurityFingerprint(created.user.uid, trimmedEmail);
            await setDoc(doc(db, 'users', created.user.uid), {
              uid: created.user.uid,
              fullName: 'رئيس الموقع',
              phone: 'موثق إدارياً',
              email: trimmedEmail,
              emailVerified: created.user.emailVerified,
              status: 'active',
              clearanceLevel: 'elevated',
              securityFingerprint: fp,
              createdAt: serverTimestamp(),
              updatedAt: serverTimestamp(),
              lastLoginAt: serverTimestamp(),
            });
            await sendEmailVerification(created.user);
            setInfoMsg('تم تهيئة حساب رئيس الموقع وإرسال رابط التحقق إلى بريدك الإلكتروني.');
            return;
          }
        } catch (bootstrapErr: unknown) {
          const bCode = (bootstrapErr as { code?: string })?.code || '';
          if (bCode === 'auth/email-already-in-use') {
            recordFailedAttempt();
            setErrorMsg(
              'كلمة المرور غير صحيحة أو تم تغييرها، أو أن الحساب مرتبط بدخول Google (يمكنك الدخول عبر Google ثم ربط كلمة مرور من لوحة التحكم).'
            );
            return;
          }
          if (bCode === 'auth/operation-not-allowed') {
            setShowConsoleHelp(true);
            setErrorMsg('تسجيل الدخول بالبريد وكلمة المرور يتطلب تفعيل مزود Email/Password في Firebase Console.');
            return;
          }
        }
      }

      if (code === 'auth/operation-not-allowed') {
        setShowConsoleHelp(true);
        setErrorMsg('تسجيل الدخول بالبريد وكلمة المرور يتطلب تفعيل مزود Email/Password في Firebase Console.');
      } else {
        recordFailedAttempt();
        setErrorMsg(mapFirebaseAuthError(code, (err as Error)?.message || 'تعذر تسجيل الدخول.'));
      }
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async () => {
    setErrorMsg('');
    setInfoMsg('');
    const trimmedEmail = email.trim().toLowerCase();
    if (!trimmedEmail) {
      setErrorMsg('أدخل بريدك الإلكتروني أولاً لإرسال رابط إعادة تعيين كلمة المرور.');
      return;
    }
    setLoading(true);
    try {
      await sendPasswordResetEmail(auth, trimmedEmail);
      setInfoMsg('تم إرسال رابط تغيير / إعادة تعيين كلمة المرور إلى بريدك الإلكتروني.');
    } catch (err: unknown) {
      const code = (err as { code?: string })?.code || '';
      setErrorMsg(mapFirebaseAuthError(code, (err as Error)?.message || 'تعذر إرسال رابط إعادة التعيين.'));
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setErrorMsg('');
    setInfoMsg('');
    setLoading(true);
    try {
      const cred = await signInWithPopup(auth, googleProvider);
      const user = cred.user;
      await user.getIdToken(true);
      const profileRef = doc(db, 'users', user.uid);
      const snap = await getDoc(profileRef);

      if (!snap.exists()) {
        const displayName =
          user.displayName && user.displayName.trim().split(/\s+/).length >= 2
            ? user.displayName.trim()
            : `${user.displayName || 'مستخدم'} موثق`;
        const fingerprint = await generateSecurityFingerprint(user.uid, user.email || '');
        try {
          await setDoc(profileRef, {
            uid: user.uid,
            fullName: displayName.slice(0, BLUEPRINT_LIMITS.FULL_NAME_MAX),
            phone: user.phoneNumber || 'غير مضاف',
            email: (user.email || '').toLowerCase(),
            emailVerified: user.emailVerified,
            status: 'active',
            clearanceLevel: 'standard',
            securityFingerprint: fingerprint,
            createdAt: serverTimestamp(),
            updatedAt: serverTimestamp(),
            lastLoginAt: serverTimestamp(),
          });
        } catch (err) {
          handleFirestoreError(err, OperationType.CREATE, `users/${user.uid}`);
        }
      } else {
        try {
          await updateDoc(profileRef, {
            emailVerified: user.emailVerified,
            lastLoginAt: serverTimestamp(),
            updatedAt: serverTimestamp(),
          });
        } catch (err) {
          handleFirestoreError(err, OperationType.UPDATE, `users/${user.uid}`);
        }
      }
      onVerifiedComplete();
    } catch (err: unknown) {
      const code = (err as { code?: string })?.code || '';
      setErrorMsg(mapFirebaseAuthError(code, (err as Error)?.message || 'تعذر تسجيل الدخول عبر Google.'));
    } finally {
      setLoading(false);
    }
  };

  const handleCheckVerification = async () => {
    if (!firebaseUser) return;
    setLoading(true);
    setErrorMsg('');
    setInfoMsg('');
    try {
      await firebaseUser.reload();
      const refreshed = auth.currentUser;
      if (refreshed?.emailVerified) {
        // Force refresh ID token so Firestore Security Rules immediately see email_verified == true
        await refreshed.getIdToken(true);
        const userRef = doc(db, 'users', refreshed.uid);
        const snap = await getDoc(userRef);
        try {
          if (snap.exists()) {
            await updateDoc(userRef, {
              emailVerified: true,
              lastLoginAt: serverTimestamp(),
              updatedAt: serverTimestamp(),
            });
          } else {
            const fp = await generateSecurityFingerprint(refreshed.uid, refreshed.email || '');
            await setDoc(userRef, {
              uid: refreshed.uid,
              fullName: refreshed.displayName || 'عضو موثق',
              phone: refreshed.phoneNumber || 'غير مضاف',
              email: (refreshed.email || '').toLowerCase(),
              emailVerified: true,
              status: 'active',
              clearanceLevel: 'standard',
              securityFingerprint: fp,
              createdAt: serverTimestamp(),
              updatedAt: serverTimestamp(),
              lastLoginAt: serverTimestamp(),
            });
          }
        } catch (err) {
          handleFirestoreError(err, OperationType.UPDATE, `users/${refreshed.uid}`);
        }
        onVerifiedComplete();
      } else {
        setErrorMsg('لم يتم تأكيد البريد الإلكتروني بعد. افتح الرسالة في بريدك واضغط رابط التفعيل ثم أعد الفحص.');
      }
    } catch (err: unknown) {
      setErrorMsg((err as Error)?.message || 'تعذر تحديث حالة التحقق.');
    } finally {
      setLoading(false);
    }
  };

  const handleResendVerification = async () => {
    if (!firebaseUser) return;
    setLoading(true);
    setErrorMsg('');
    setInfoMsg('');
    try {
      await sendEmailVerification(firebaseUser);
      setInfoMsg('تمت إعادة إرسال رابط التحقق إلى بريدك الإلكتروني.');
    } catch (err: unknown) {
      const code = (err as { code?: string })?.code || '';
      setErrorMsg(mapFirebaseAuthError(code, (err as Error)?.message || 'تعذر إرسال رسالة التحقق.'));
    } finally {
      setLoading(false);
    }
  };

  const handleSignOut = async () => {
    await signOut(auth);
    setErrorMsg('');
    setInfoMsg('');
  };

  if (firebaseUser && userProfile && userProfile.status !== 'active') {
    return (
      <div className="min-h-screen flex items-center justify-center p-6 relative z-10">
        <div className="max-w-lg w-full bg-[#0C0E13] border border-red-600/40 rounded-xl p-8 space-y-6">
          <div className="flex items-center gap-3 text-red-400">
            <Shield className="w-7 h-7 shrink-0" />
            <div>
              <h1 className="text-xl font-bold">تم تقييد الوصول إلى هذا الحساب</h1>
              <p className="text-xs text-zinc-400 mt-1">
                الحالة الأمنية الحالية: {userProfile.status === 'banned' ? 'حظر دائم' : 'تعليق مؤقت'}
              </p>
            </div>
          </div>
          <p className="text-sm text-zinc-300 leading-relaxed">
            تم إيقاف صلاحية دخولك إلى أرشيف Dark Web من قِبل إدارة النظام.
          </p>
          <button
            type="button"
            onClick={handleSignOut}
            className="w-full py-2.5 px-4 rounded-lg bg-zinc-900 border border-zinc-700 text-zinc-200 text-sm font-semibold hover:bg-zinc-800 transition-colors cursor-pointer"
          >
            تسجيل الخروج
          </button>
        </div>
      </div>
    );
  }

  if (firebaseUser && !firebaseUser.emailVerified) {
    return (
      <div className="min-h-screen flex items-center justify-center p-6 relative z-10">
        <div className="max-w-lg w-full bg-[#0C0E13] border border-zinc-800 rounded-xl p-8 space-y-6">
          <div className="flex items-center gap-4">
            <img
              src="/src/assets/images/hacker_hood_emblem_1794920209158.jpg"
              alt="بوابة التحقق"
              referrerPolicy="no-referrer"
              className="w-14 h-14 rounded-lg object-cover border border-red-900/60"
            />
            <div>
              <h1 className="text-xl font-bold text-zinc-100">التحقق من البريد الإلكتروني مطلوب</h1>
              <p className="text-xs text-zinc-400 mt-1 font-mono-tabular">{firebaseUser.email}</p>
            </div>
          </div>

          <p className="text-sm text-zinc-300 leading-relaxed">
            لا يُسمح بدخول الأرشيف السري قبل تأكيد ملكية البريد الإلكتروني. افتح رابط التفعيل المرسل إلى بريدك ثم اضغط زر التحقق أدناه.
          </p>

          {errorMsg && (
            <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{errorMsg}</span>
            </div>
          )}

          {infoMsg && (
            <div className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-start gap-2.5">
              <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{infoMsg}</span>
            </div>
          )}

          <div className="space-y-3">
            <button
              type="button"
              disabled={loading}
              onClick={handleCheckVerification}
              className="w-full py-2.5 px-4 rounded-lg bg-red-700 hover:bg-red-600 disabled:opacity-60 text-zinc-100 font-bold text-sm flex items-center justify-center gap-2 transition-colors cursor-pointer"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              تحديث حالة التحقق والدخول
            </button>

            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                disabled={loading}
                onClick={handleResendVerification}
                className="py-2.5 px-4 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-200 text-xs font-semibold transition-colors cursor-pointer"
              >
                إعادة إرسال الرابط
              </button>
              <button
                type="button"
                onClick={handleSignOut}
                className="py-2.5 px-4 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-400 text-xs font-semibold transition-colors cursor-pointer"
              >
                تغيير الحساب
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-10 relative z-10">
      <div className="max-w-5xl w-full grid grid-cols-1 lg:grid-cols-12 bg-[#0C0E13] border border-zinc-800/90 rounded-xl overflow-hidden">
        {/* Hacker Visual Column */}
        <div className="lg:col-span-5 relative bg-[#07080B] border-b lg:border-b-0 lg:border-l border-zinc-800/80 flex flex-col justify-between p-8 min-h-[320px]">
          <img
            src="/src/assets/images/hacker_terminal_hero_1794920207041.jpg"
            alt="مخترق يجلس أمام شاشات الحاسوب في الظلام"
            referrerPolicy="no-referrer"
            className="absolute inset-0 w-full h-full object-cover opacity-55"
          />
          <div className="absolute inset-0 bg-gradient-to-t from-[#07080B] via-[#07080B]/70 to-[#07080B]/50" />

          <div className="relative z-10 flex items-center gap-3">
            <img
              src="/src/assets/images/hacker_hood_emblem_1794920209158.jpg"
              alt="شعار Dark Web"
              referrerPolicy="no-referrer"
              className="w-12 h-12 rounded-lg object-cover border border-red-900/60"
            />
            <BloodBrand size="md" suffix={isAdminMode ? 'ADMIN' : undefined} />
          </div>

          <div className="relative z-10 space-y-4 mt-12">
            <h1 className="text-2xl sm:text-3xl font-bold text-zinc-100 leading-snug">
              {isAdminMode
                ? 'مركز القيادة والتحكم في الملفات السرية'
                : 'بوابة النفاذ إلى أرشيف المعلومات السرية والملفات المحظورة'}
            </h1>
            <p className="text-sm text-zinc-300 leading-relaxed">
              {isAdminMode
                ? 'الوصول مقصور على رئيس الموقع والمدراء المفوضين بالتحقق المزدوج وصلاحيات RBAC.'
                : 'الدخول مشروط بتسجيل الاسم الثنائي، رقم الهاتف، البريد الإلكتروني المؤكد، وكلمة مرور مشفرة.'}
            </p>
            <div className="pt-2 border-t border-zinc-800/80 flex items-center gap-3 text-xs text-zinc-400 font-mono-tabular">
              <Lock className="w-3.5 h-3.5 text-red-400 shrink-0" />
              <span>AES-256-GCM</span>
              <span aria-hidden="true">·</span>
              <span>PBKDF2-SHA256</span>
              <span aria-hidden="true">·</span>
              <span>TLS</span>
            </div>
          </div>
        </div>

        {/* Auth Form Column */}
        <div className="lg:col-span-7 p-6 sm:p-10 space-y-6">
          <div className="flex items-center justify-between gap-4 border-b border-zinc-800 pb-4">
            <div className="flex items-center gap-1 p-1 bg-[#07080B] border border-zinc-800 rounded-lg">
              {!isAdminMode && (
                <button
                  type="button"
                  onClick={() => {
                    setMode('register');
                    setErrorMsg('');
                  }}
                  className={`px-4 py-2 rounded-md text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    mode === 'register'
                      ? 'bg-zinc-800 text-zinc-100'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  تسجيل عضوية جديدة
                </button>
              )}
              <button
                type="button"
                onClick={() => {
                  setMode('login');
                  setErrorMsg('');
                }}
                className={`px-4 py-2 rounded-md text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  mode === 'login'
                    ? 'bg-zinc-800 text-zinc-100'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                تسجيل الدخول
              </button>
            </div>
            <span className="text-xs text-zinc-500 font-mono-tabular hidden sm:inline">
              {generateValidDocId('NODE').slice(0, 14)}
            </span>
          </div>

          {errorMsg && (
            <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-xs space-y-2">
              <div className="flex items-start gap-2.5">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{errorMsg}</span>
              </div>
              {showConsoleHelp && (
                <div className="pt-2 border-t border-red-500/20 text-zinc-300 leading-relaxed space-y-1">
                  <p className="font-semibold text-zinc-100">تفعيل تسجيل البريد الإلكتروني في Firebase:</p>
                  <p>
                    1. افتح مزودات المصادقة:{' '}
                    <a
                      href="https://console.firebase.google.com/project/echo-93e7d/authentication/providers"
                      target="_blank"
                      rel="noreferrer"
                      className="text-red-400 underline"
                    >
                      Authentication Providers
                    </a>
                  </p>
                  <p>2. اختر Email/Password ثم فعّل الخيار الأول واضغط Save.</p>
                </div>
              )}
            </div>
          )}

          {infoMsg && (
            <div className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-start gap-2.5">
              <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{infoMsg}</span>
            </div>
          )}

          <form onSubmit={mode === 'register' && !isAdminMode ? handleRegister : handleLogin} className="space-y-4">
            {mode === 'register' && !isAdminMode && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-zinc-300 mb-1.5">
                    الاسم الثنائي الكامل
                  </label>
                  <div className="relative">
                    <UserIcon className="w-4 h-4 text-zinc-500 absolute right-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      required
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      placeholder="مثال: أحمد منصور"
                      className="w-full bg-[#07080B] border border-zinc-800 focus:border-red-600 rounded-lg pr-10 pl-3 py-2.5 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-zinc-300 mb-1.5">
                    رقم الهاتف
                  </label>
                  <div className="relative">
                    <Phone className="w-4 h-4 text-zinc-500 absolute right-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="tel"
                      required
                      dir="ltr"
                      value={phone}
                      onChange={(e) => setPhone(e.target.value)}
                      placeholder="+20 100 000 0000"
                      className="w-full bg-[#07080B] border border-zinc-800 focus:border-red-600 rounded-lg pr-10 pl-3 py-2.5 text-sm text-zinc-100 font-mono-tabular placeholder:text-zinc-600 focus:outline-none text-left"
                    />
                  </div>
                </div>
              </div>
            )}

            <div>
              <label className="block text-xs font-semibold text-zinc-300 mb-1.5">
                البريد الإلكتروني
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-zinc-500 absolute right-3 top-1/2 -translate-y-1/2" />
                <input
                  type="email"
                  required
                  dir="ltr"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@domain.com"
                  className="w-full bg-[#07080B] border border-zinc-800 focus:border-red-600 rounded-lg pr-10 pl-3 py-2.5 text-sm text-zinc-100 font-mono-tabular placeholder:text-zinc-600 focus:outline-none text-left"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-zinc-300 mb-1.5">
                كلمة المرور
              </label>
              <div className="relative">
                <KeyRound className="w-4 h-4 text-zinc-500 absolute right-3 top-1/2 -translate-y-1/2" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  dir="ltr"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-[#07080B] border border-zinc-800 focus:border-red-600 rounded-lg pr-10 pl-10 py-2.5 text-sm text-zinc-100 font-mono-tabular placeholder:text-zinc-600 focus:outline-none text-left"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 cursor-pointer"
                  aria-label="إظهار أو إخفاء كلمة المرور"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {(mode === 'login' || isAdminMode) && (
              <div className="flex items-center justify-between gap-2 text-xs">
                <button
                  type="button"
                  disabled={loading}
                  onClick={handleResetPassword}
                  className="text-zinc-400 hover:text-red-400 transition-colors cursor-pointer"
                >
                  نسيت كلمة المرور أو تريد إعادة تعيينها؟
                </button>
                {lockSecondsLeft > 0 && (
                  <span className="text-red-400 font-mono-tabular">
                    إعادة المحاولة بعد {lockSecondsLeft}ث
                  </span>
                )}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || lockSecondsLeft > 0}
              className="w-full py-2.5 px-4 rounded-lg bg-red-700 hover:bg-red-600 disabled:opacity-60 text-zinc-100 font-bold text-sm flex items-center justify-center gap-2 transition-colors cursor-pointer"
            >
              <ShieldCheck className="w-4 h-4" />
              {loading
                ? 'جاري التحقق والتشفير...'
                : mode === 'register' && !isAdminMode
                  ? 'إنشاء الحساب وإرسال رابط التحقق'
                  : 'تسجيل الدخول الآمن'}
            </button>
          </form>

          <div className="relative flex items-center py-1">
            <div className="flex-grow border-t border-zinc-800" />
            <span className="shrink mx-3 text-xs text-zinc-500">أو المصادقة الفورية</span>
            <div className="flex-grow border-t border-zinc-800" />
          </div>

          <button
            type="button"
            disabled={loading}
            onClick={handleGoogleSignIn}
            className="w-full py-2.5 px-4 rounded-lg bg-[#07080B] border border-zinc-800 hover:border-zinc-700 text-zinc-200 text-sm font-semibold flex items-center justify-center gap-2 transition-colors cursor-pointer"
          >
            <Shield className="w-4 h-4 text-red-400" />
            الدخول الموثق عبر Google
          </button>
        </div>
      </div>
    </div>
  );
}
