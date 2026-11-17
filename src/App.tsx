import { useEffect, useState } from 'react';
import { onAuthStateChanged, signOut, type User } from 'firebase/auth';
import {
  deleteDoc,
  doc,
  getDoc,
  onSnapshot,
  serverTimestamp,
  setDoc,
} from 'firebase/firestore';
import { AdminDashboard } from './components/AdminDashboard';
import { AuthGate } from './components/AuthGate';
import { CipherBackdrop } from './components/CipherBackdrop';
import { DarkWebPortal } from './components/DarkWebPortal';
import { ErrorBoundary } from './components/ErrorBoundary';
import { deriveInviteId, generateSecurityFingerprint } from './lib/crypto';
import { auth, db, handleFirestoreError, OperationType } from './lib/firebase';
import {
  ALL_ADMIN_PERMISSIONS,
  SITE_OWNER_EMAIL,
  type AdminInvite,
  type AdminRecord,
  type SystemSettings,
  type UserProfile,
} from './types';

const IS_STANDALONE_ADMIN = import.meta.env.VITE_SITE_ROLE === 'admin';

function AppShell() {
  const [authReady, setAuthReady] = useState(false);
  const [firebaseUser, setFirebaseUser] = useState<User | null>(null);
  const [authSyncTick, setAuthSyncTick] = useState(0);
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [adminRecord, setAdminRecord] = useState<AdminRecord | null>(null);
  const [systemSettings, setSystemSettings] = useState<SystemSettings | null>(null);
  const [route, setRoute] = useState<'portal' | 'admin'>(() =>
    IS_STANDALONE_ADMIN || window.location.pathname.startsWith('/admin') ? 'admin' : 'portal'
  );

  useEffect(() => {
    const onPop = () => {
      setRoute(
        IS_STANDALONE_ADMIN || window.location.pathname.startsWith('/admin') ? 'admin' : 'portal'
      );
    };
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  const navigateTo = (target: 'portal' | 'admin') => {
    if (IS_STANDALONE_ADMIN) return;
    const nextPath = target === 'admin' ? '/admin' : '/';
    if (window.location.pathname !== nextPath) {
      window.history.pushState({}, '', nextPath);
    }
    setRoute(target);
  };

  useEffect(() => {
    const ref = doc(db, 'system_settings', 'global');
    const unsub = onSnapshot(
      ref,
      (snap) => {
        if (snap.exists()) {
          setSystemSettings(snap.data() as SystemSettings);
        }
      },
      () => {
        // Default settings until initialized by owner/admin
      }
    );
    return () => unsub();
  }, []);

  useEffect(() => {
    const unsub = onAuthStateChanged(auth, (user) => {
      setFirebaseUser(user);
      setAuthReady(true);
      if (!user) {
        setUserProfile(null);
        setAdminRecord(null);
      }
    });
    return () => unsub();
  }, []);

  // Idle session auto-logout governed by systemSettings.sessionTimeoutMinutes
  useEffect(() => {
    const timeoutMins = systemSettings?.sessionTimeoutMinutes ?? 0;
    if (!firebaseUser || timeoutMins <= 0) return;

    let timer: ReturnType<typeof setTimeout>;
    const resetTimer = () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        void signOut(auth);
      }, timeoutMins * 60_000);
    };

    const events = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'] as const;
    events.forEach((ev) => window.addEventListener(ev, resetTimer, { passive: true }));
    resetTimer();

    return () => {
      clearTimeout(timer);
      events.forEach((ev) => window.removeEventListener(ev, resetTimer));
    };
  }, [firebaseUser, systemSettings?.sessionTimeoutMinutes]);

  const isOwner = Boolean(
    firebaseUser?.emailVerified &&
      firebaseUser.email?.toLowerCase() === SITE_OWNER_EMAIL.toLowerCase()
  );

  useEffect(() => {
    if (!authReady || !firebaseUser) return;

    const userRef = doc(db, 'users', firebaseUser.uid);
    const adminRef = doc(db, 'admins', firebaseUser.uid);

    const unsubUser = onSnapshot(
      userRef,
      (snap) => {
        if (snap.exists()) {
          setUserProfile(snap.data() as UserProfile);
        } else {
          setUserProfile(null);
        }
      },
      (err) => handleFirestoreError(err, OperationType.GET, `users/${firebaseUser.uid}`)
    );

    const unsubAdmin = onSnapshot(
      adminRef,
      (snap) => {
        if (snap.exists()) {
          setAdminRecord(snap.data() as AdminRecord);
        } else {
          setAdminRecord(null);
        }
      },
      (err) => handleFirestoreError(err, OperationType.GET, `admins/${firebaseUser.uid}`)
    );

    const syncPrivileges = async () => {
      if (!firebaseUser.emailVerified || !firebaseUser.email) return;
      const emailLower = firebaseUser.email.toLowerCase();

      if (emailLower === SITE_OWNER_EMAIL.toLowerCase()) {
        const ownerAdminSnap = await getDoc(adminRef);
        if (!ownerAdminSnap.exists()) {
          try {
            await setDoc(adminRef, {
              uid: firebaseUser.uid,
              fullName: firebaseUser.displayName || 'رئيس الموقع',
              email: emailLower,
              role: 'owner',
              permissions: ALL_ADMIN_PERMISSIONS.map((p) => p.id),
              active: true,
              addedBy: firebaseUser.uid,
              addedByEmail: emailLower,
              createdAt: serverTimestamp(),
              updatedAt: serverTimestamp(),
            });
          } catch (err) {
            handleFirestoreError(err, OperationType.CREATE, `admins/${firebaseUser.uid}`);
          }
        }

        const ownerUserSnap = await getDoc(userRef);
        if (!ownerUserSnap.exists()) {
          const fp = await generateSecurityFingerprint(firebaseUser.uid, emailLower);
          try {
            await setDoc(userRef, {
              uid: firebaseUser.uid,
              fullName: firebaseUser.displayName || 'رئيس الموقع',
              phone: firebaseUser.phoneNumber || 'موثق إدارياً',
              email: emailLower,
              emailVerified: true,
              status: 'active',
              clearanceLevel: 'elevated',
              securityFingerprint: fp,
              createdAt: serverTimestamp(),
              updatedAt: serverTimestamp(),
              lastLoginAt: serverTimestamp(),
            });
          } catch (err) {
            handleFirestoreError(err, OperationType.CREATE, `users/${firebaseUser.uid}`);
          }
        }
        return;
      }

      const inviteId = await deriveInviteId(emailLower);
      const inviteRef = doc(db, 'admin_invites', inviteId);
      try {
        const inviteSnap = await getDoc(inviteRef);
        if (inviteSnap.exists()) {
          const inv = inviteSnap.data() as AdminInvite;
          if (inv.active) {
            const existingAdminSnap = await getDoc(adminRef);
            if (!existingAdminSnap.exists()) {
              await setDoc(adminRef, {
                uid: firebaseUser.uid,
                fullName: inv.fullName,
                email: emailLower,
                ...(inv.phone ? { phone: inv.phone } : {}),
                role: 'admin',
                permissions: inv.permissions,
                active: true,
                addedBy: inv.invitedBy,
                addedByEmail: inv.invitedByEmail,
                inviteId,
                createdAt: serverTimestamp(),
                updatedAt: serverTimestamp(),
              });
              await deleteDoc(inviteRef);
            }
          }
        }
      } catch {
        // No pending admin invite
      }
    };

    void syncPrivileges();

    return () => {
      unsubUser();
      unsubAdmin();
    };
  }, [authReady, firebaseUser, authSyncTick]);

  if (!authReady) {
    return (
      <div className="min-h-screen bg-[#050608] text-zinc-300 flex items-center justify-center p-6">
        <div className="text-sm font-mono-tabular">جاري تهيئة طبقة التشفير والمصادقة...</div>
      </div>
    );
  }

  const isAuthenticatedAndVerified = Boolean(
    firebaseUser &&
      firebaseUser.emailVerified &&
      (!userProfile || userProfile.status === 'active')
  );

  return (
    <div className="min-h-screen bg-[#050608] text-zinc-100 relative">
      <CipherBackdrop />
      {!isAuthenticatedAndVerified || !firebaseUser ? (
        <AuthGate
          firebaseUser={firebaseUser}
          userProfile={userProfile}
          registrationOpen={systemSettings?.registrationOpen ?? true}
          maxFailedLogins={systemSettings?.maxFailedLogins ?? 5}
          isAdminMode={route === 'admin'}
          onVerifiedComplete={() => {
            setFirebaseUser(auth.currentUser);
            setAuthSyncTick((t) => t + 1);
          }}
        />
      ) : route === 'admin' ? (
        <AdminDashboard
          firebaseUser={firebaseUser}
          adminRecord={adminRecord}
          isOwner={isOwner}
          systemSettings={systemSettings}
          onNavigatePortal={() => navigateTo('portal')}
          isStandaloneAdminSite={IS_STANDALONE_ADMIN}
        />
      ) : (
        <DarkWebPortal
          firebaseUser={firebaseUser}
          userProfile={userProfile}
          adminRecord={adminRecord}
          isOwner={isOwner}
          systemSettings={systemSettings}
          onNavigateAdmin={() => navigateTo('admin')}
        />
      )}
    </div>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <AppShell />
    </ErrorBoundary>
  );
}
