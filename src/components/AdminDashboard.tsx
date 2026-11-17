import React, { useEffect, useMemo, useState } from 'react';
import {
  EmailAuthProvider,
  linkWithCredential,
  reauthenticateWithCredential,
  signOut,
  updatePassword,
  type User,
} from 'firebase/auth';
import {
  collection,
  deleteDoc,
  doc,
  limit,
  onSnapshot,
  orderBy,
  query,
  serverTimestamp,
  setDoc,
  updateDoc,
} from 'firebase/firestore';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Bell,
  Check,
  CheckCircle2,
  Download,
  Edit3,
  Eye,
  EyeOff,
  FileText,
  Film,
  Image as ImageIcon,
  KeyRound,
  Lock,
  LogOut,
  Plus,
  Search,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShoppingBag,
  Trash2,
  UserCheck,
  UserPlus,
  Users,
  X,
} from 'lucide-react';
import { emitSecurityAlert, recordAdminAction } from '../lib/audit';
import { deriveInviteId, encryptPayload, generateValidDocId, sha256Hex } from '../lib/crypto';
import { auth, db, handleFirestoreError, OperationType } from '../lib/firebase';
import {
  ALL_ADMIN_PERMISSIONS,
  BLUEPRINT_LIMITS,
  SITE_OWNER_EMAIL,
  type ActivityLog,
  type AdminInvite,
  type AdminPermission,
  type AdminRecord,
  type ClearanceLevel,
  type ContentClassification,
  type ContentType,
  type ContentVisibility,
  type SecurityAlert,
  type SystemSettings,
  type UserProfile,
  type UserStatus,
  type VaultContent,
} from '../types';

interface AdminDashboardProps {
  firebaseUser: User;
  adminRecord: AdminRecord | null;
  isOwner: boolean;
  systemSettings: SystemSettings | null;
  onNavigatePortal?: () => void;
  isStandaloneAdminSite: boolean;
}

type AdminTab = 'overview' | 'content' | 'users' | 'admins' | 'logs' | 'settings';

function formatDateTime(ts?: { toDate?: () => Date } | null): string {
  if (!ts || typeof ts.toDate !== 'function') return 'الآن';
  return new Intl.DateTimeFormat('ar-EG', {
    dateStyle: 'short',
    timeStyle: 'medium',
  }).format(ts.toDate());
}

export function AdminDashboard({
  firebaseUser,
  adminRecord,
  isOwner,
  systemSettings,
  onNavigatePortal,
  isStandaloneAdminSite,
}: AdminDashboardProps) {
  const hasAccess = isOwner || Boolean(adminRecord?.active);

  const hasPermission = (perm: AdminPermission): boolean => {
    if (isOwner) return true;
    return Boolean(adminRecord?.active && adminRecord.permissions.includes(perm));
  };

  const actorName =
    adminRecord?.fullName || firebaseUser.displayName || (isOwner ? 'رئيس الموقع' : 'مدير النظام');
  const actorEmail = (firebaseUser.email || '').toLowerCase();
  const actorRole: 'owner' | 'admin' = isOwner ? 'owner' : 'admin';

  const [activeTab, setActiveTab] = useState<AdminTab>('overview');

  // Live collections
  const [contentList, setContentList] = useState<VaultContent[]>([]);
  const [usersList, setUsersList] = useState<UserProfile[]>([]);
  const [adminsList, setAdminsList] = useState<AdminRecord[]>([]);
  const [invitesList, setInvitesList] = useState<AdminInvite[]>([]);
  const [logsList, setLogsList] = useState<ActivityLog[]>([]);
  const [alertsList, setAlertsList] = useState<SecurityAlert[]>([]);
  const [toastAlert, setToastAlert] = useState<SecurityAlert | null>(null);
  const [statusBanner, setStatusBanner] = useState<{ type: 'ok' | 'err'; text: string } | null>(
    null
  );

  // Health endpoint state
  const [serverHealth, setServerHealth] = useState<{
    status: string;
    service: string;
    nodeVersion: string;
    uptimeSeconds: number;
    encryptionStandard: string;
  } | null>(null);

  // Content Publisher Form
  const [editingContentId, setEditingContentId] = useState<string | null>(null);
  const [cType, setCType] = useState<ContentType>('message');
  const [cTitle, setCTitle] = useState('');
  const [cSummary, setCSummary] = useState('');
  const [cBody, setCBody] = useState('');
  const [cMediaUrl, setCMediaUrl] = useState('');
  const [cPrice, setCPrice] = useState('');
  const [cClassification, setCClassification] = useState<ContentClassification>('standard');
  const [cVisibility, setCVisibility] = useState<ContentVisibility>('published');
  const [cEncrypt, setCEncrypt] = useState(false);
  const [cPassphrase, setCPassphrase] = useState('');
  const [cSubmitting, setCSubmitting] = useState(false);

  // Users Inspector
  const [userSearch, setUserSearch] = useState('');
  const [userStatusFilter, setUserStatusFilter] = useState<'all' | UserStatus>('all');
  const [inspectedUser, setInspectedUser] = useState<UserProfile | null>(null);
  const [editNotes, setEditNotes] = useState('');

  // Admin Management Form
  const [inviteMode, setInviteMode] = useState<'promote' | 'email'>('promote');
  const [selectedUserUid, setSelectedUserUid] = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteName, setInviteName] = useState('');
  const [invitePhone, setInvitePhone] = useState('');
  const [selectedPerms, setSelectedPerms] = useState<AdminPermission[]>([
    'manage_content',
    'view_logs',
  ]);
  const [editingAdmin, setEditingAdmin] = useState<AdminRecord | null>(null);

  // Logs Filters
  const [logActorFilter, setLogActorFilter] = useState('all');
  const [logSeverityFilter, setLogSeverityFilter] = useState<'all' | ActivityLog['severity']>('all');
  const [logTargetFilter, setLogTargetFilter] = useState<'all' | ActivityLog['targetType']>('all');

  // System Settings Form
  const [sSiteTitle, setSSiteTitle] = useState(systemSettings?.siteTitle || 'Dark Web');
  const [sMaintenance, setSMaintenance] = useState(Boolean(systemSettings?.maintenanceMode));
  const [sRegOpen, setSRegOpen] = useState(systemSettings?.registrationOpen ?? true);
  const [sRequireVerify, setSRequireVerify] = useState(
    systemSettings?.requireEmailVerification ?? true
  );
  const [sNotice, setSNotice] = useState(systemSettings?.vaultNotice || '');

  // Password Change / Link Modal
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [currentPwd, setCurrentPwd] = useState('');
  const [newPwd, setNewPwd] = useState('');
  const [confirmPwd, setConfirmPwd] = useState('');
  const [pwdSaving, setPwdSaving] = useState(false);
  const [pwdError, setPwdError] = useState('');

  const hasPasswordProvider = useMemo(
    () => firebaseUser.providerData.some((p) => p.providerId === 'password'),
    [firebaseUser]
  );

  useEffect(() => {
    if (systemSettings) {
      setSSiteTitle(systemSettings.siteTitle);
      setSMaintenance(systemSettings.maintenanceMode);
      setSRegOpen(systemSettings.registrationOpen);
      setSRequireVerify(systemSettings.requireEmailVerification);
      setSNotice(systemSettings.vaultNotice || '');
    }
  }, [systemSettings]);

  // Fetch /api/health
  useEffect(() => {
    fetch('/api/health')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) setServerHealth(data);
      })
      .catch(() => null);
  }, []);

  // Subscribe to collections permitted by RBAC
  useEffect(() => {
    if (!hasAccess) return;
    const unsubs: (() => void)[] = [];

    if (hasPermission('manage_content')) {
      const qContent = query(collection(db, 'content'), orderBy('createdAt', 'desc'));
      unsubs.push(
        onSnapshot(
          qContent,
          (snap) => setContentList(snap.docs.map((d) => d.data() as VaultContent)),
          (err) => handleFirestoreError(err, OperationType.LIST, 'content')
        )
      );
    }

    if (hasPermission('manage_users')) {
      const qUsers = query(collection(db, 'users'), orderBy('createdAt', 'desc'));
      unsubs.push(
        onSnapshot(
          qUsers,
          (snap) => setUsersList(snap.docs.map((d) => d.data() as UserProfile)),
          (err) => handleFirestoreError(err, OperationType.LIST, 'users')
        )
      );
    }

    // Admins list is readable by any active admin/owner
    const qAdmins = query(collection(db, 'admins'), orderBy('createdAt', 'desc'));
    unsubs.push(
      onSnapshot(
        qAdmins,
        (snap) => setAdminsList(snap.docs.map((d) => d.data() as AdminRecord)),
        (err) => handleFirestoreError(err, OperationType.LIST, 'admins')
      )
    );

    if (hasPermission('manage_admins')) {
      const qInvites = query(collection(db, 'admin_invites'), orderBy('createdAt', 'desc'));
      unsubs.push(
        onSnapshot(
          qInvites,
          (snap) => setInvitesList(snap.docs.map((d) => d.data() as AdminInvite)),
          (err) => handleFirestoreError(err, OperationType.LIST, 'admin_invites')
        )
      );
    }

    if (hasPermission('view_logs')) {
      const qLogs = query(
        collection(db, 'activity_logs'),
        orderBy('createdAt', 'desc'),
        limit(200)
      );
      unsubs.push(
        onSnapshot(
          qLogs,
          (snap) => setLogsList(snap.docs.map((d) => ({ id: d.id, ...(d.data() as ActivityLog) }))),
          (err) => handleFirestoreError(err, OperationType.LIST, 'activity_logs')
        )
      );
    }

    if (hasPermission('view_alerts')) {
      const qAlerts = query(
        collection(db, 'security_alerts'),
        orderBy('createdAt', 'desc'),
        limit(100)
      );
      let initialized = false;
      unsubs.push(
        onSnapshot(
          qAlerts,
          (snap) => {
            const next = snap.docs.map((d) => ({ id: d.id, ...(d.data() as SecurityAlert) }));
            if (initialized) {
              const newestUnack = next.find((a) => !a.acknowledged);
              if (newestUnack) {
                setToastAlert(newestUnack);
              }
            }
            initialized = true;
            setAlertsList(next);
          },
          (err) => handleFirestoreError(err, OperationType.LIST, 'security_alerts')
        )
      );
    }

    return () => {
      unsubs.forEach((u) => u());
    };
  }, [hasAccess, isOwner, adminRecord]);

  // Report unauthorized attempt if non-admin hits /admin
  useEffect(() => {
    if (!hasAccess && firebaseUser.emailVerified) {
      void emitSecurityAlert({
        title: 'محاولة وصول غير مصرح به للوحة التحكم',
        message: `حاول المستخدم ${firebaseUser.email || firebaseUser.uid} فتح بوابة الإدارة بدون صلاحيات.`,
        category: 'auth_event',
        severity: 'critical',
        actorId: firebaseUser.uid,
        actorEmail: firebaseUser.email || 'unknown@user',
      }).catch(() => null);
    }
  }, [hasAccess, firebaseUser]);

  const unacknowledgedAlerts = useMemo(
    () => alertsList.filter((a) => !a.acknowledged),
    [alertsList]
  );

  const filteredUsers = useMemo(() => {
    return usersList.filter((u) => {
      if (userStatusFilter !== 'all' && u.status !== userStatusFilter) return false;
      if (userSearch.trim()) {
        const q = userSearch.trim().toLowerCase();
        return `${u.fullName} ${u.email} ${u.phone} ${u.securityFingerprint}`
          .toLowerCase()
          .includes(q);
      }
      return true;
    });
  }, [usersList, userSearch, userStatusFilter]);

  const filteredLogs = useMemo(() => {
    return logsList.filter((l) => {
      if (logActorFilter !== 'all' && l.actorId !== logActorFilter) return false;
      if (logSeverityFilter !== 'all' && l.severity !== logSeverityFilter) return false;
      if (logTargetFilter !== 'all' && l.targetType !== logTargetFilter) return false;
      return true;
    });
  }, [logsList, logActorFilter, logSeverityFilter, logTargetFilter]);

  const uniqueLogActors = useMemo(() => {
    const map = new Map<string, { id: string; name: string; email: string }>();
    logsList.forEach((l) => {
      if (!map.has(l.actorId)) {
        map.set(l.actorId, { id: l.actorId, name: l.actorName, email: l.actorEmail });
      }
    });
    return Array.from(map.values());
  }, [logsList]);

  const notify = (type: 'ok' | 'err', text: string) => {
    setStatusBanner({ type, text });
    setTimeout(() => setStatusBanner(null), 5000);
  };

  // Unauthorized Lockout Screen
  if (!hasAccess) {
    return (
      <div className="min-h-screen flex items-center justify-center p-6 relative z-10">
        <div className="max-w-lg w-full bg-[#0F1217] border border-red-500/40 rounded-xl p-8 space-y-6">
          <div className="flex items-center gap-3 text-red-400">
            <ShieldAlert className="w-7 h-7 shrink-0" />
            <div>
              <h1 className="text-xl font-bold">رفض أمني — بوابة الإدارة محظورة</h1>
              <p className="text-xs text-zinc-400 mt-1 font-mono-tabular">{firebaseUser.email}</p>
            </div>
          </div>
          <p className="text-sm text-zinc-300 leading-relaxed">
            هذا الموقع مخصص حصرياً لمالك المنصة والمدراء المعتمدين. تم تسجيل محاولة الوصول وإرسال تنبيه أمني فوري للإدارة.
          </p>
          <div className="flex items-center gap-3">
            {!isStandaloneAdminSite && onNavigatePortal && (
              <button
                type="button"
                onClick={onNavigatePortal}
                className="flex-1 py-2.5 px-4 rounded-lg bg-zinc-100 text-zinc-950 text-xs font-bold hover:bg-zinc-200 transition-colors cursor-pointer"
              >
                العودة إلى موقع Dark Web
              </button>
            )}
            <button
              type="button"
              onClick={() => signOut(auth)}
              className="flex-1 py-2.5 px-4 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-300 text-xs font-semibold hover:border-zinc-700 transition-colors cursor-pointer"
            >
              تسجيل الخروج
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Content Create / Update
  const resetContentForm = () => {
    setEditingContentId(null);
    setCType('message');
    setCTitle('');
    setCSummary('');
    setCBody('');
    setCMediaUrl('');
    setCPrice('');
    setCClassification('standard');
    setCVisibility('published');
    setCEncrypt(false);
    setCPassphrase('');
  };

  const handleSaveContent = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!hasPermission('manage_content')) return;
    if (!cTitle.trim()) {
      notify('err', 'يرجى إدخال عنوان المحتوى.');
      return;
    }
    if (cEncrypt && cPassphrase.length < 6) {
      notify('err', 'عند تفعيل التشفير يجب إدخال مفتاح تشفير لا يقل عن 6 أحرف.');
      return;
    }

    setCSubmitting(true);
    try {
      const contentId = editingContentId || generateValidDocId('cnt');
      let storedBody = cBody.trim().slice(0, BLUEPRINT_LIMITS.BODY_MAX);
      let storedMediaUrl = cMediaUrl.trim().slice(0, BLUEPRINT_LIMITS.MEDIA_URL_MAX);
      let encryptionIv: string | undefined;
      let encryptionSalt: string | undefined;
      let integrityHash = await sha256Hex(`${contentId}:${cTitle}:${storedBody}:${storedMediaUrl}`);

      if (cEncrypt) {
        const bundlePayload = JSON.stringify({
          body: storedBody,
          mediaUrl: storedMediaUrl,
        });
        const encrypted = await encryptPayload(bundlePayload, cPassphrase);
        storedBody = encrypted.ciphertext;
        storedMediaUrl = '';
        encryptionIv = encrypted.iv;
        encryptionSalt = encrypted.salt;
        integrityHash = encrypted.integrityHash;
      }

      const payload: Record<string, unknown> = {
        id: contentId,
        type: cType,
        title: cTitle.trim().slice(0, BLUEPRINT_LIMITS.TITLE_MAX),
        ...(cSummary.trim() ? { summary: cSummary.trim().slice(0, BLUEPRINT_LIMITS.SUMMARY_MAX) } : {}),
        ...(storedBody ? { body: storedBody } : {}),
        ...(storedMediaUrl ? { mediaUrl: storedMediaUrl } : {}),
        ...(cType === 'product' && cPrice.trim()
          ? { price: cPrice.trim().slice(0, BLUEPRINT_LIMITS.PRICE_MAX) }
          : {}),
        classification: cEncrypt ? 'encrypted' : cClassification,
        isEncrypted: cEncrypt,
        ...(encryptionIv ? { encryptionIv } : {}),
        ...(encryptionSalt ? { encryptionSalt } : {}),
        integrityHash,
        visibility: cVisibility,
        updatedAt: serverTimestamp(),
      };

      if (editingContentId) {
        try {
          await updateDoc(doc(db, 'content', editingContentId), {
            type: payload.type,
            title: payload.title,
            summary: payload.summary || '',
            body: payload.body || '',
            mediaUrl: payload.mediaUrl || '',
            price: payload.price || '',
            classification: payload.classification,
            isEncrypted: payload.isEncrypted,
            encryptionIv: encryptionIv || '',
            encryptionSalt: encryptionSalt || '',
            integrityHash,
            visibility: payload.visibility,
            updatedAt: serverTimestamp(),
          });
        } catch (err) {
          handleFirestoreError(err, OperationType.UPDATE, `content/${editingContentId}`);
        }
        await recordAdminAction({
          actorId: firebaseUser.uid,
          actorName,
          actorEmail,
          actorRole,
          actionType: 'UPDATE_CONTENT',
          targetType: 'content',
          targetId: contentId,
          details: `تحديث محتوى (${cType}): ${cTitle}`,
          severity: 'info',
        });
        notify('ok', 'تم تحديث المحتوى وتسجيل العملية في سجل النشاط.');
      } else {
        try {
          await setDoc(doc(db, 'content', contentId), {
            ...payload,
            authorId: firebaseUser.uid,
            authorName: actorName.slice(0, 120),
            createdAt: serverTimestamp(),
          });
        } catch (err) {
          handleFirestoreError(err, OperationType.CREATE, `content/${contentId}`);
        }
        await recordAdminAction({
          actorId: firebaseUser.uid,
          actorName,
          actorEmail,
          actorRole,
          actionType: 'PUBLISH_CONTENT',
          targetType: 'content',
          targetId: contentId,
          details: `نشر محتوى جديد (${cType}${cEncrypt ? ' · مشفر AES-256' : ''}): ${cTitle}`,
          severity: cEncrypt ? 'warning' : 'info',
        });
        notify('ok', 'تم نشر المحتوى في الخزنة وتسجيل العملية في سجل النشاط.');
      }

      resetContentForm();
    } finally {
      setCSubmitting(false);
    }
  };

  const handleToggleVisibility = async (item: VaultContent) => {
    const nextVis: ContentVisibility = item.visibility === 'published' ? 'hidden' : 'published';
    try {
      await updateDoc(doc(db, 'content', item.id), {
        visibility: nextVis,
        updatedAt: serverTimestamp(),
      });
    } catch (err) {
      handleFirestoreError(err, OperationType.UPDATE, `content/${item.id}`);
    }
    await recordAdminAction({
      actorId: firebaseUser.uid,
      actorName,
      actorEmail,
      actorRole,
      actionType: 'TOGGLE_CONTENT_VISIBILITY',
      targetType: 'content',
      targetId: item.id,
      details: `تغيير ظهور "${item.title}" إلى ${nextVis === 'published' ? 'منشور' : 'مخفي'}`,
      severity: 'info',
    });
    notify('ok', 'تم تحديث حالة الظهور.');
  };

  const handleDeleteContent = async (item: VaultContent) => {
    try {
      await deleteDoc(doc(db, 'content', item.id));
    } catch (err) {
      handleFirestoreError(err, OperationType.DELETE, `content/${item.id}`);
    }
    await recordAdminAction({
      actorId: firebaseUser.uid,
      actorName,
      actorEmail,
      actorRole,
      actionType: 'DELETE_CONTENT',
      targetType: 'content',
      targetId: item.id,
      details: `حذف نهائي للمحتوى: ${item.title} (${item.type})`,
      severity: 'critical',
    });
    await emitSecurityAlert({
      title: 'حذف محتوى من الخزنة',
      message: `قام ${actorName} (${actorEmail}) بحذف "${item.title}" نهائياً.`,
      category: 'content_removal',
      severity: 'high',
      actorId: firebaseUser.uid,
      actorEmail,
    });
    notify('ok', 'تم حذف المحتوى وإطلاق تنبيه أمني فوري.');
  };

  // User Actions
  const handleUpdateUserStatus = async (user: UserProfile, nextStatus: UserStatus) => {
    try {
      await updateDoc(doc(db, 'users', user.uid), {
        status: nextStatus,
        updatedAt: serverTimestamp(),
      });
    } catch (err) {
      handleFirestoreError(err, OperationType.UPDATE, `users/${user.uid}`);
    }
    const sev = nextStatus === 'active' ? 'info' : 'critical';
    await recordAdminAction({
      actorId: firebaseUser.uid,
      actorName,
      actorEmail,
      actorRole,
      actionType: `USER_STATUS_${nextStatus.toUpperCase()}`,
      targetType: 'user',
      targetId: user.uid,
      details: `تغيير حالة العضو ${user.fullName} (${user.email}) إلى ${nextStatus}`,
      severity: sev,
    });
    if (nextStatus !== 'active') {
      await emitSecurityAlert({
        title: nextStatus === 'banned' ? 'حظر عضو دائم' : 'تعليق حساب عضو',
        message: `قام ${actorName} بتغيير حالة العضو ${user.fullName} (${user.email}) إلى ${nextStatus}.`,
        category: 'user_restriction',
        severity: 'critical',
        actorId: firebaseUser.uid,
        actorEmail,
      });
    }
    notify('ok', 'تم تحديث حالة المستخدم.');
  };

  const handleUpdateClearance = async (user: UserProfile, clearanceLevel: ClearanceLevel) => {
    try {
      await updateDoc(doc(db, 'users', user.uid), {
        clearanceLevel,
        updatedAt: serverTimestamp(),
      });
    } catch (err) {
      handleFirestoreError(err, OperationType.UPDATE, `users/${user.uid}`);
    }
    await recordAdminAction({
      actorId: firebaseUser.uid,
      actorName,
      actorEmail,
      actorRole,
      actionType: 'UPDATE_USER_CLEARANCE',
      targetType: 'user',
      targetId: user.uid,
      details: `تعديل تصريح العضو ${user.fullName} إلى ${clearanceLevel}`,
      severity: 'warning',
    });
    notify('ok', 'تم تحديث مستوى التصريح.');
  };

  const handleSaveUserNotes = async () => {
    if (!inspectedUser) return;
    try {
      await updateDoc(doc(db, 'users', inspectedUser.uid), {
        notes: editNotes.slice(0, BLUEPRINT_LIMITS.NOTES_MAX),
        updatedAt: serverTimestamp(),
      });
    } catch (err) {
      handleFirestoreError(err, OperationType.UPDATE, `users/${inspectedUser.uid}`);
    }
    await recordAdminAction({
      actorId: firebaseUser.uid,
      actorName,
      actorEmail,
      actorRole,
      actionType: 'UPDATE_USER_NOTES',
      targetType: 'user',
      targetId: inspectedUser.uid,
      details: `تحديث الملاحظات الإدارية للعضو ${inspectedUser.fullName}`,
      severity: 'info',
    });
    setInspectedUser({ ...inspectedUser, notes: editNotes });
    notify('ok', 'تم حفظ الملاحظات الأمنية للعضو.');
  };

  const handleDeleteUser = async (user: UserProfile) => {
    if (user.email.toLowerCase() === SITE_OWNER_EMAIL) {
      notify('err', 'لا يمكن حذف سجل رئيس الموقع.');
      return;
    }
    try {
      await deleteDoc(doc(db, 'users', user.uid));
    } catch (err) {
      handleFirestoreError(err, OperationType.DELETE, `users/${user.uid}`);
    }
    await recordAdminAction({
      actorId: firebaseUser.uid,
      actorName,
      actorEmail,
      actorRole,
      actionType: 'DELETE_USER',
      targetType: 'user',
      targetId: user.uid,
      details: `حذف ملف العضو ${user.fullName} (${user.email})`,
      severity: 'critical',
    });
    await emitSecurityAlert({
      title: 'حذف ملف مستخدم',
      message: `قام ${actorName} بحذف سجل المستخدم ${user.fullName} (${user.email}).`,
      category: 'user_restriction',
      severity: 'critical',
      actorId: firebaseUser.uid,
      actorEmail,
    });
    if (inspectedUser?.uid === user.uid) setInspectedUser(null);
    notify('ok', 'تم حذف سجل المستخدم وتسجيل التنبيه.');
  };

  // Admin Management
  const togglePerm = (perm: AdminPermission) => {
    setSelectedPerms((prev) =>
      prev.includes(perm) ? prev.filter((p) => p !== perm) : [...prev, perm]
    );
  };

  const handleAddAdmin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!hasPermission('manage_admins')) return;
    if (selectedPerms.length === 0) {
      notify('err', 'اختر صلاحية واحدة على الأقل للأدمن الجديد.');
      return;
    }

    if (inviteMode === 'promote') {
      const targetUser = usersList.find((u) => u.uid === selectedUserUid);
      if (!targetUser) {
        notify('err', 'اختر عضواً من القائمة لترقيته.');
        return;
      }
      try {
        await setDoc(doc(db, 'admins', targetUser.uid), {
          uid: targetUser.uid,
          fullName: targetUser.fullName,
          email: targetUser.email.toLowerCase(),
          phone: targetUser.phone,
          role: 'admin',
          permissions: selectedPerms,
          active: true,
          addedBy: firebaseUser.uid,
          addedByEmail: actorEmail,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, `admins/${targetUser.uid}`);
      }
      await recordAdminAction({
        actorId: firebaseUser.uid,
        actorName,
        actorEmail,
        actorRole,
        actionType: 'ADD_ADMIN_PROMOTE',
        targetType: 'admin',
        targetId: targetUser.uid,
        details: `ترقية ${targetUser.fullName} (${targetUser.email}) إلى أدمن بالصلاحيات: ${selectedPerms.join(', ')}`,
        severity: 'critical',
      });
      await emitSecurityAlert({
        title: 'إضافة أدمن جديد للنظام',
        message: `قام ${actorName} بمنح صلاحيات إدارية إلى ${targetUser.fullName} (${targetUser.email}).`,
        category: 'admin_change',
        severity: 'critical',
        actorId: firebaseUser.uid,
        actorEmail,
      });
      setSelectedUserUid('');
      notify('ok', 'تمت ترقية العضو إلى أدمن وإرسال تنبيه فوري.');
    } else {
      const cleanEmail = inviteEmail.trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail) || inviteName.trim().length < 2) {
        notify('err', 'أدخل البريد الإلكتروني والاسم الثنائي للأدمن بشكل صحيح.');
        return;
      }
      const inviteId = await deriveInviteId(cleanEmail);
      try {
        await setDoc(doc(db, 'admin_invites', inviteId), {
          id: inviteId,
          email: cleanEmail,
          fullName: inviteName.trim().slice(0, 120),
          ...(invitePhone.trim() ? { phone: invitePhone.trim().slice(0, 32) } : {}),
          permissions: selectedPerms,
          active: true,
          invitedBy: firebaseUser.uid,
          invitedByEmail: actorEmail,
          createdAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, `admin_invites/${inviteId}`);
      }
      await recordAdminAction({
        actorId: firebaseUser.uid,
        actorName,
        actorEmail,
        actorRole,
        actionType: 'INVITE_ADMIN',
        targetType: 'admin',
        targetId: inviteId,
        details: `تخويل دعوة أدمن مسبقة للبريد ${cleanEmail} بالصلاحيات: ${selectedPerms.join(', ')}`,
        severity: 'critical',
      });
      await emitSecurityAlert({
        title: 'تفويض دعوة أدمن جديدة',
        message: `أصدر ${actorName} تفويضاً إدارياً مسبقاً للبريد ${cleanEmail}.`,
        category: 'admin_change',
        severity: 'critical',
        actorId: firebaseUser.uid,
        actorEmail,
      });
      setInviteEmail('');
      setInviteName('');
      setInvitePhone('');
      notify('ok', 'تم حفظ التفويض المسبق. بمجرد تسجيل دخول الأدمن ببريده المؤكد سيتم تفعيل صلاحياته تلقائياً.');
    }
  };

  const handleSaveAdminPermissions = async (admin: AdminRecord, nextPerms: AdminPermission[], nextActive: boolean) => {
    try {
      await updateDoc(doc(db, 'admins', admin.uid), {
        permissions: nextPerms,
        active: nextActive,
        updatedAt: serverTimestamp(),
      });
    } catch (err) {
      handleFirestoreError(err, OperationType.UPDATE, `admins/${admin.uid}`);
    }
    await recordAdminAction({
      actorId: firebaseUser.uid,
      actorName,
      actorEmail,
      actorRole,
      actionType: 'UPDATE_ADMIN_PERMISSIONS',
      targetType: 'admin',
      targetId: admin.uid,
      details: `تحديث صلاحيات الأدمن ${admin.fullName} (${admin.email}) — نشط: ${nextActive ? 'نعم' : 'لا'} — الصلاحيات: ${nextPerms.join(', ')}`,
      severity: 'critical',
    });
    await emitSecurityAlert({
      title: 'تعديل صلاحيات أدمن',
      message: `عدّل ${actorName} صلاحيات ${admin.fullName} (${admin.email}).`,
      category: 'admin_change',
      severity: 'high',
      actorId: firebaseUser.uid,
      actorEmail,
    });
    setEditingAdmin(null);
    notify('ok', 'تم تحديث صلاحيات الأدمن.');
  };

  const handleRemoveAdmin = async (admin: AdminRecord) => {
    if (admin.email.toLowerCase() === SITE_OWNER_EMAIL) {
      notify('err', 'لا يمكن إزالة رئيس الموقع.');
      return;
    }
    try {
      await deleteDoc(doc(db, 'admins', admin.uid));
    } catch (err) {
      handleFirestoreError(err, OperationType.DELETE, `admins/${admin.uid}`);
    }
    await recordAdminAction({
      actorId: firebaseUser.uid,
      actorName,
      actorEmail,
      actorRole,
      actionType: 'REVOKE_ADMIN',
      targetType: 'admin',
      targetId: admin.uid,
      details: `سحب الصلاحيات الإدارية وإزالة الأدمن ${admin.fullName} (${admin.email})`,
      severity: 'critical',
    });
    await emitSecurityAlert({
      title: 'سحب صلاحيات أدمن',
      message: `قام ${actorName} بإزالة ${admin.fullName} (${admin.email}) من طاقم الإدارة.`,
      category: 'admin_change',
      severity: 'critical',
      actorId: firebaseUser.uid,
      actorEmail,
    });
    notify('ok', 'تمت إزالة الأدمن وتسجيل العملية.');
  };

  const handleAcknowledgeAlert = async (alert: SecurityAlert) => {
    if (!alert.id) return;
    try {
      await updateDoc(doc(db, 'security_alerts', alert.id), {
        acknowledged: true,
        acknowledgedBy: actorEmail,
        acknowledgedAt: serverTimestamp(),
      });
    } catch (err) {
      handleFirestoreError(err, OperationType.UPDATE, `security_alerts/${alert.id}`);
    }
    if (toastAlert?.id === alert.id) setToastAlert(null);
  };

  const handleSaveSystemSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!hasPermission('system_settings')) return;
    try {
      await setDoc(doc(db, 'system_settings', 'global'), {
        siteTitle: sSiteTitle.trim().slice(0, 80) || 'Dark Web',
        maintenanceMode: sMaintenance,
        registrationOpen: sRegOpen,
        requireEmailVerification: sRequireVerify,
        encryptionStandard: 'AES-256-GCM',
        vaultNotice: sNotice.trim().slice(0, BLUEPRINT_LIMITS.VAULT_NOTICE_MAX),
        updatedBy: actorEmail,
        updatedAt: serverTimestamp(),
      });
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, 'system_settings/global');
    }
    await recordAdminAction({
      actorId: firebaseUser.uid,
      actorName,
      actorEmail,
      actorRole,
      actionType: 'UPDATE_SYSTEM_SETTINGS',
      targetType: 'system',
      targetId: 'global',
      details: `تعديل إعدادات النظام — صيانة: ${sMaintenance} · فتح التسجيل: ${sRegOpen}`,
      severity: 'critical',
    });
    await emitSecurityAlert({
      title: 'تحديث سياسات الأمان والنظام',
      message: `قام ${actorName} بتعديل الإعدادات العامة (وضع الصيانة: ${sMaintenance ? 'مفعل' : 'متوقف'}).`,
      category: 'policy_update',
      severity: 'high',
      actorId: firebaseUser.uid,
      actorEmail,
    });
    notify('ok', 'تم حفظ إعدادات الأمان والنظام.');
  };

  const exportLogsCsv = () => {
    const header = ['Timestamp', 'ActorName', 'ActorEmail', 'Role', 'Action', 'TargetType', 'TargetId', 'Severity', 'Details', 'Checksum'];
    const rows = filteredLogs.map((l) => [
      formatDateTime(l.createdAt),
      l.actorName,
      l.actorEmail,
      l.actorRole,
      l.actionType,
      l.targetType,
      l.targetId || '',
      l.severity,
      `"${(l.details || '').replace(/"/g, '""')}"`,
      l.checksum,
    ]);
    const csv = [header.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `darkweb-audit-logs-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleChangeOwnPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwdError('');

    if (newPwd.length < 8) {
      setPwdError('كلمة المرور الجديدة يجب أن تتكون من 8 خانات على الأقل.');
      return;
    }
    if (newPwd !== confirmPwd) {
      setPwdError('تأكيد كلمة المرور غير متطابق.');
      return;
    }
    if (hasPasswordProvider && !currentPwd) {
      setPwdError('يرجى إدخال كلمة المرور الحالية.');
      return;
    }
    if (!firebaseUser.email) {
      setPwdError('لا يوجد بريد إلكتروني مرتبط بالحساب.');
      return;
    }

    setPwdSaving(true);
    try {
      if (hasPasswordProvider) {
        const cred = EmailAuthProvider.credential(firebaseUser.email, currentPwd);
        await reauthenticateWithCredential(firebaseUser, cred);
        await updatePassword(firebaseUser, newPwd);
      } else {
        const cred = EmailAuthProvider.credential(firebaseUser.email, newPwd);
        await linkWithCredential(firebaseUser, cred);
      }

      await recordAdminAction({
        actorId: firebaseUser.uid,
        actorName,
        actorEmail,
        actorRole,
        actionType: hasPasswordProvider ? 'CHANGE_ADMIN_PASSWORD' : 'LINK_ADMIN_PASSWORD',
        targetType: 'security',
        targetId: firebaseUser.uid,
        details: hasPasswordProvider
          ? `تغيير كلمة مرور الحساب الإداري ${actorEmail}`
          : `ربط كلمة مرور بالبريد الإلكتروني للحساب الإداري ${actorEmail}`,
        severity: 'critical',
      });

      await emitSecurityAlert({
        title: 'تحديث كلمة مرور حساب إداري',
        message: `قام ${actorName} (${actorEmail}) بتحديث كلمة مرور دخوله إلى لوحة التحكم.`,
        category: 'auth_event',
        severity: 'high',
        actorId: firebaseUser.uid,
        actorEmail,
      });

      setShowPasswordModal(false);
      setCurrentPwd('');
      setNewPwd('');
      setConfirmPwd('');
      notify('ok', 'تم تحديث كلمة المرور وتوثيق العملية أمنياً بنجاح.');
    } catch (err: unknown) {
      const code = (err as { code?: string })?.code || '';
      if (code === 'auth/wrong-password' || code === 'auth/invalid-credential') {
        setPwdError('كلمة المرور الحالية غير صحيحة.');
      } else if (code === 'auth/requires-recent-login') {
        setPwdError('لأسباب أمنية، سجل الخروج ثم أعد الدخول قبل تغيير كلمة المرور.');
      } else if (code === 'auth/operation-not-allowed') {
        setPwdError('يرجى تفعيل مزود Email/Password في Firebase Console Authentication Providers أولاً.');
      } else {
        setPwdError((err as Error)?.message || 'تعذر تحديث كلمة المرور.');
      }
    } finally {
      setPwdSaving(false);
    }
  };

  const navItems: { id: AdminTab; label: string; icon: React.ReactNode; visible: boolean; badge?: number }[] = [
    {
      id: 'overview',
      label: 'القيادة والتنبيهات',
      icon: <Bell className="w-4 h-4" />,
      visible: true,
      badge: unacknowledgedAlerts.length,
    },
    {
      id: 'content',
      label: 'إدارة المحتوى المشفر',
      icon: <Lock className="w-4 h-4" />,
      visible: hasPermission('manage_content'),
    },
    {
      id: 'users',
      label: 'المستخدمون والبيانات',
      icon: <Users className="w-4 h-4" />,
      visible: hasPermission('manage_users'),
    },
    {
      id: 'admins',
      label: 'المدراء والصلاحيات',
      icon: <UserCheck className="w-4 h-4" />,
      visible: hasPermission('manage_admins') || isOwner,
    },
    {
      id: 'logs',
      label: 'سجل نشاط المدراء',
      icon: <Activity className="w-4 h-4" />,
      visible: hasPermission('view_logs'),
    },
    {
      id: 'settings',
      label: 'الأمان و Render',
      icon: <Settings className="w-4 h-4" />,
      visible: hasPermission('system_settings'),
    },
  ];

  return (
    <div className="min-h-screen relative z-10 flex flex-col lg:flex-row">
      {/* Sidebar */}
      <aside className="lg:w-64 shrink-0 bg-[#090B0E] border-b lg:border-b-0 lg:border-l border-zinc-800/90 flex flex-col justify-between p-5 gap-6">
        <div className="space-y-6">
          <div className="flex items-center gap-3 pb-4 border-b border-zinc-800/80">
            <img
              src="/src/assets/images/crypto_seal_emblem_1794858486145.jpg"
              alt="شعار القيادة"
              referrerPolicy="no-referrer"
              className="w-10 h-10 rounded-lg object-cover border border-zinc-700"
            />
            <div className="min-w-0">
              <div className="text-sm font-bold text-zinc-100 truncate">Dark Web Admin</div>
              <div className="text-xs text-emerald-400 truncate">
                {isOwner ? 'رئيس الموقع' : 'أدمن مفوض'}
              </div>
            </div>
          </div>

          <nav className="flex lg:flex-col gap-1.5 overflow-x-auto lg:overflow-visible">
            {navItems
              .filter((n) => n.visible)
              .map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveTab(item.id)}
                  className={`flex items-center justify-between gap-3 px-3.5 py-2.5 rounded-lg text-xs font-semibold whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                    activeTab === item.id
                      ? 'bg-zinc-800 text-zinc-100'
                      : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/60'
                  }`}
                >
                  <span className="flex items-center gap-2.5">
                    {item.icon}
                    {item.label}
                  </span>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span className="font-mono-tabular text-red-400 font-bold">({item.badge})</span>
                  )}
                </button>
              ))}
          </nav>
        </div>

        <div className="pt-4 border-t border-zinc-800/80 space-y-2.5">
          <div className="text-xs text-zinc-500 font-mono-tabular truncate">{actorEmail}</div>
          <button
            type="button"
            onClick={() => {
              setPwdError('');
              setShowPasswordModal(true);
            }}
            className="w-full py-2 px-3 rounded-lg bg-[#0F1217] border border-zinc-800 hover:border-emerald-500/40 text-zinc-200 text-xs font-semibold flex items-center justify-center gap-2 cursor-pointer"
          >
            <KeyRound className="w-3.5 h-3.5 text-emerald-400" />
            تغيير كلمة المرور
          </button>
          {!isStandaloneAdminSite && onNavigatePortal && (
            <button
              type="button"
              onClick={onNavigatePortal}
              className="w-full py-2 px-3 rounded-lg bg-[#0F1217] border border-zinc-800 hover:border-zinc-700 text-zinc-200 text-xs font-semibold flex items-center justify-center gap-2 cursor-pointer"
            >
              <ArrowRight className="w-3.5 h-3.5" />
              الذهاب إلى موقع Dark Web
            </button>
          )}
          <button
            type="button"
            onClick={() => signOut(auth)}
            className="w-full py-2 px-3 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-red-500/40 text-zinc-300 text-xs font-semibold flex items-center justify-center gap-2 cursor-pointer"
          >
            <LogOut className="w-3.5 h-3.5" />
            تسجيل الخروج
          </button>
        </div>
      </aside>

      {/* Main Workspace */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Top Breadcrumb Bar */}
        <header className="h-16 px-6 border-b border-zinc-800/80 bg-[#060709]/90 backdrop-blur-md flex items-center justify-between gap-4 sticky top-0 z-20">
          <div className="text-xs sm:text-sm text-zinc-400 truncate">
            <span>لوحة تحكم الأدمن</span>
            <span className="mx-2" aria-hidden="true">/</span>
            <span className="text-zinc-100 font-semibold">
              {navItems.find((n) => n.id === activeTab)?.label}
            </span>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <span className="text-xs text-zinc-400 font-mono-tabular hidden sm:inline">
              AES-256-GCM
            </span>
            {unacknowledgedAlerts.length > 0 && (
              <button
                type="button"
                onClick={() => setActiveTab('overview')}
                className="px-3 py-1.5 rounded-lg bg-red-500/15 border border-red-500/40 text-red-300 text-xs font-semibold whitespace-nowrap shrink-0 cursor-pointer"
              >
                تنبيهات غير مراجعة: {unacknowledgedAlerts.length}
              </button>
            )}
          </div>
        </header>

        <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
          {/* Instant Live Alert Toast */}
          {toastAlert && (
            <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/40 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="flex items-start gap-3">
                <ShieldAlert className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                <div>
                  <div className="text-sm font-bold text-red-200">{toastAlert.title}</div>
                  <div className="text-xs text-zinc-300 mt-0.5">{toastAlert.message}</div>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => handleAcknowledgeAlert(toastAlert)}
                  className="px-3 py-1.5 rounded-lg bg-red-500 text-zinc-950 text-xs font-bold cursor-pointer"
                >
                  تأكيد المراجعة
                </button>
                <button
                  type="button"
                  onClick={() => setToastAlert(null)}
                  className="p-1.5 text-zinc-400 hover:text-zinc-100 cursor-pointer"
                  aria-label="إخفاء"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {statusBanner && (
            <div
              className={`p-3.5 rounded-lg border text-xs flex items-center gap-2.5 ${
                statusBanner.type === 'ok'
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                  : 'bg-red-500/10 border-red-500/30 text-red-300'
              }`}
            >
              {statusBanner.type === 'ok' ? (
                <CheckCircle2 className="w-4 h-4 shrink-0" />
              ) : (
                <AlertTriangle className="w-4 h-4 shrink-0" />
              )}
              <span>{statusBanner.text}</span>
            </div>
          )}

          {/* TAB 1: OVERVIEW & LIVE ALERTS */}
          {activeTab === 'overview' && (
            <div className="space-y-8">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-[#0F1217] border border-zinc-800 rounded-xl p-5 space-y-1">
                  <div className="text-xs text-zinc-400">إجمالي الأعضاء المسجلين</div>
                  <div className="text-2xl font-bold text-zinc-100 font-mono-tabular">
                    {usersList.length}
                  </div>
                  <div className="text-xs text-zinc-500 font-mono-tabular">
                    موثق بالبريد: {usersList.filter((u) => u.emailVerified).length}
                  </div>
                </div>

                <div className="bg-[#0F1217] border border-zinc-800 rounded-xl p-5 space-y-1">
                  <div className="text-xs text-zinc-400">طاقم الإدارة النشط</div>
                  <div className="text-2xl font-bold text-zinc-100 font-mono-tabular">
                    {adminsList.filter((a) => a.active).length}
                  </div>
                  <div className="text-xs text-zinc-500 font-mono-tabular">
                    دعوات معلقة: {invitesList.length}
                  </div>
                </div>

                <div className="bg-[#0F1217] border border-zinc-800 rounded-xl p-5 space-y-1">
                  <div className="text-xs text-zinc-400">عناصر المحتوى بالخزنة</div>
                  <div className="text-2xl font-bold text-zinc-100 font-mono-tabular">
                    {contentList.length}
                  </div>
                  <div className="text-xs text-zinc-500 font-mono-tabular">
                    مشفر AES-256: {contentList.filter((c) => c.isEncrypted).length}
                  </div>
                </div>

                <div className="bg-[#0F1217] border border-zinc-800 rounded-xl p-5 space-y-1">
                  <div className="text-xs text-zinc-400">عمليات سجل التدقيق</div>
                  <div className="text-2xl font-bold text-zinc-100 font-mono-tabular">
                    {logsList.length}
                  </div>
                  <div className="text-xs text-red-400 font-mono-tabular">
                    تنبيهات حرجة مفتوحة: {unacknowledgedAlerts.length}
                  </div>
                </div>
              </div>

              {/* Real-time Alerts Feed */}
              <div className="bg-[#0F1217] border border-zinc-800 rounded-xl overflow-hidden">
                <div className="px-6 py-4 border-b border-zinc-800 flex items-center justify-between gap-4">
                  <div>
                    <h2 className="text-base font-bold text-zinc-100">
                      التنبيهات الأمنية الفورية للإجراءات الحساسة
                    </h2>
                    <p className="text-xs text-zinc-400 mt-0.5">
                      بث مباشر من قاعدة البيانات لكل عملية تعديل صلاحيات، حظر، حذف، أو محاولة اختراق.
                    </p>
                  </div>
                </div>

                {!hasPermission('view_alerts') ? (
                  <div className="p-8 text-center text-xs text-zinc-500">
                    لا تملك صلاحية عرض التنبيهات الأمنية (view_alerts).
                  </div>
                ) : alertsList.length === 0 ? (
                  <div className="p-10 text-center text-sm text-zinc-400">
                    لا توجد تنبيهات أمنية مسجلة حالياً.
                  </div>
                ) : (
                  <div className="divide-y divide-zinc-800/80">
                    {alertsList.map((alert) => (
                      <div
                        key={alert.id}
                        className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2 text-xs">
                            <span
                              className={
                                alert.severity === 'critical'
                                  ? 'text-red-400 font-bold'
                                  : 'text-amber-400 font-bold'
                              }
                            >
                              {alert.severity === 'critical' ? 'حرج' : 'عالي'}
                            </span>
                            <span aria-hidden="true">·</span>
                            <span className="text-zinc-400 font-mono-tabular">
                              {formatDateTime(alert.createdAt)}
                            </span>
                            <span aria-hidden="true">·</span>
                            <span className="text-zinc-500 font-mono-tabular">{alert.actorEmail}</span>
                          </div>
                          <div className="text-sm font-bold text-zinc-100">{alert.title}</div>
                          <div className="text-xs text-zinc-400">{alert.message}</div>
                        </div>

                        <div className="shrink-0">
                          {alert.acknowledged ? (
                            <span className="text-xs text-emerald-400 font-mono-tabular">
                              تمت المراجعة ({alert.acknowledgedBy})
                            </span>
                          ) : (
                            <button
                              type="button"
                              onClick={() => handleAcknowledgeAlert(alert)}
                              className="px-3.5 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-100 text-xs font-semibold cursor-pointer"
                            >
                              تأكيد المراجعة
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 2: CONTENT MANAGER */}
          {activeTab === 'content' && hasPermission('manage_content') && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
              <form
                onSubmit={handleSaveContent}
                className="lg:col-span-5 bg-[#0F1217] border border-zinc-800 rounded-xl p-6 space-y-4"
              >
                <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                  <h2 className="text-base font-bold text-zinc-100">
                    {editingContentId ? 'تعديل محتوى منشور' : 'نشر محتوى جديد في Dark Web'}
                  </h2>
                  {editingContentId && (
                    <button
                      type="button"
                      onClick={resetContentForm}
                      className="text-xs text-zinc-400 hover:text-zinc-200 cursor-pointer"
                    >
                      إلغاء التعديل
                    </button>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs text-zinc-400 mb-1">نوع المحتوى</label>
                    <select
                      value={cType}
                      onChange={(e) => setCType(e.target.value as ContentType)}
                      className="w-full bg-[#090B0E] border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 focus:outline-none"
                    >
                      <option value="message">رسالة نصية</option>
                      <option value="video">فيديو</option>
                      <option value="image">صورة</option>
                      <option value="product">منتج خاص</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs text-zinc-400 mb-1">حالة الظهور</label>
                    <select
                      value={cVisibility}
                      onChange={(e) => setCVisibility(e.target.value as ContentVisibility)}
                      className="w-full bg-[#090B0E] border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 focus:outline-none"
                    >
                      <option value="published">منشور للأعضاء المؤكدين</option>
                      <option value="hidden">مخفي (مسودة إدارية)</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-xs text-zinc-400 mb-1">العنوان</label>
                  <input
                    type="text"
                    required
                    value={cTitle}
                    onChange={(e) => setCTitle(e.target.value)}
                    placeholder="عنوان المحتوى..."
                    className="w-full bg-[#090B0E] border border-zinc-800 focus:border-emerald-500 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none"
                  />
                </div>

                <div>
                  <label className="block text-xs text-zinc-400 mb-1">وصف مختصر (اختياري)</label>
                  <input
                    type="text"
                    value={cSummary}
                    onChange={(e) => setCSummary(e.target.value)}
                    placeholder="ملخص يظهر قبل فتح المحتوى..."
                    className="w-full bg-[#090B0E] border border-zinc-800 focus:border-emerald-500 rounded-lg px-3 py-2 text-xs text-zinc-100 focus:outline-none"
                  />
                </div>

                {(cType === 'video' || cType === 'image' || cType === 'product') && (
                  <div>
                    <label className="block text-xs text-zinc-400 mb-1">
                      رابط الوسائط ({cType === 'video' ? 'MP4 / YouTube' : 'رابط الصورة المباشر'})
                    </label>
                    <input
                      type="url"
                      dir="ltr"
                      value={cMediaUrl}
                      onChange={(e) => setCMediaUrl(e.target.value)}
                      placeholder="https://..."
                      className="w-full bg-[#090B0E] border border-zinc-800 focus:border-emerald-500 rounded-lg px-3 py-2 text-xs text-zinc-100 font-mono-tabular text-left focus:outline-none"
                    />
                  </div>
                )}

                {cType === 'product' && (
                  <div>
                    <label className="block text-xs text-zinc-400 mb-1">السعر / القيمة</label>
                    <input
                      type="text"
                      value={cPrice}
                      onChange={(e) => setCPrice(e.target.value)}
                      placeholder="مثال: 250 USD"
                      className="w-full bg-[#090B0E] border border-zinc-800 focus:border-emerald-500 rounded-lg px-3 py-2 text-xs text-zinc-100 focus:outline-none"
                    />
                  </div>
                )}

                <div>
                  <label className="block text-xs text-zinc-400 mb-1">نص الرسالة أو تفاصيل المحتوى</label>
                  <textarea
                    rows={4}
                    value={cBody}
                    onChange={(e) => setCBody(e.target.value)}
                    placeholder="اكتب الرسالة أو تفاصيل المنتج أو ملاحظات الفيديو..."
                    className="w-full bg-[#090B0E] border border-zinc-800 focus:border-emerald-500 rounded-lg px-3 py-2 text-xs text-zinc-100 focus:outline-none"
                  />
                </div>

                <div className="p-3.5 rounded-lg bg-[#090B0E] border border-zinc-800 space-y-3">
                  <label className="flex items-center justify-between gap-3 cursor-pointer">
                    <span className="text-xs font-semibold text-zinc-200 flex items-center gap-2">
                      <KeyRound className="w-4 h-4 text-emerald-400" />
                      تشفير الحزمة بخوارزمية AES-256-GCM
                    </span>
                    <input
                      type="checkbox"
                      checked={cEncrypt}
                      onChange={(e) => setCEncrypt(e.target.checked)}
                      className="accent-emerald-500 w-4 h-4"
                    />
                  </label>
                  {cEncrypt ? (
                    <input
                      type="password"
                      value={cPassphrase}
                      onChange={(e) => setCPassphrase(e.target.value)}
                      placeholder="أدخل مفتاح التشفير (لن يُحفظ في قاعدة البيانات)..."
                      className="w-full bg-[#0F1217] border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 focus:outline-none"
                    />
                  ) : (
                    <select
                      value={cClassification}
                      onChange={(e) =>
                        setCClassification(e.target.value as ContentClassification)
                      }
                      className="w-full bg-[#0F1217] border border-zinc-800 rounded-lg px-3 py-1.5 text-xs text-zinc-300 focus:outline-none"
                    >
                      <option value="standard">تصنيف: خاص بالأعضاء المؤكدين</option>
                      <option value="confidential">تصنيف: سري للغاية</option>
                    </select>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={cSubmitting}
                  className="w-full py-2.5 px-4 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-60 text-zinc-950 text-xs font-bold flex items-center justify-center gap-2 cursor-pointer"
                >
                  <Plus className="w-4 h-4" />
                  {cSubmitting
                    ? 'جاري التشفير والنشر...'
                    : editingContentId
                      ? 'حفظ التعديلات'
                      : 'نشر في Dark Web'}
                </button>
              </form>

              <div className="lg:col-span-7 bg-[#0F1217] border border-zinc-800 rounded-xl overflow-hidden">
                <div className="px-6 py-4 border-b border-zinc-800 flex items-center justify-between">
                  <h2 className="text-base font-bold text-zinc-100">
                    المحتوى المنشور ({contentList.length})
                  </h2>
                </div>
                {contentList.length === 0 ? (
                  <div className="p-10 text-center text-sm text-zinc-400">
                    لم تنشر أي مواد بعد. أضف أول فيديو أو صورة أو رسالة أو منتج من النموذج المجاور.
                  </div>
                ) : (
                  <div className="divide-y divide-zinc-800/80">
                    {contentList.map((item) => (
                      <div
                        key={item.id}
                        className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                      >
                        <div className="space-y-1 min-w-0">
                          <div className="flex items-center gap-2 text-xs text-zinc-400">
                            {item.type === 'video' && <Film className="w-3.5 h-3.5 text-emerald-400" />}
                            {item.type === 'image' && <ImageIcon className="w-3.5 h-3.5 text-emerald-400" />}
                            {item.type === 'message' && <FileText className="w-3.5 h-3.5 text-emerald-400" />}
                            {item.type === 'product' && <ShoppingBag className="w-3.5 h-3.5 text-emerald-400" />}
                            <span>{item.type}</span>
                            <span aria-hidden="true">·</span>
                            <span>{item.visibility === 'published' ? 'منشور' : 'مخفي'}</span>
                            {item.isEncrypted && (
                              <>
                                <span aria-hidden="true">·</span>
                                <span className="text-amber-400">AES-256-GCM</span>
                              </>
                            )}
                          </div>
                          <div className="text-sm font-bold text-zinc-100 truncate">{item.title}</div>
                          <div className="text-xs text-zinc-500 font-mono-tabular">
                            {item.authorName} · {formatDateTime(item.createdAt)}
                          </div>
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          <button
                            type="button"
                            onClick={() => handleToggleVisibility(item)}
                            className="p-2 rounded-lg bg-[#090B0E] border border-zinc-800 text-zinc-300 hover:border-zinc-700 cursor-pointer"
                            title={item.visibility === 'published' ? 'إخفاء' : 'نشر'}
                          >
                            {item.visibility === 'published' ? (
                              <EyeOff className="w-4 h-4" />
                            ) : (
                              <Eye className="w-4 h-4" />
                            )}
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setEditingContentId(item.id);
                              setCType(item.type);
                              setCTitle(item.title);
                              setCSummary(item.summary || '');
                              setCBody(item.isEncrypted ? '' : item.body || '');
                              setCMediaUrl(item.mediaUrl || '');
                              setCPrice(item.price || '');
                              setCClassification(item.classification);
                              setCVisibility(item.visibility);
                              setCEncrypt(false);
                            }}
                            className="p-2 rounded-lg bg-[#090B0E] border border-zinc-800 text-zinc-300 hover:border-zinc-700 cursor-pointer"
                            title="تعديل"
                          >
                            <Edit3 className="w-4 h-4" />
                          </button>
                          <button
                            type="button"
                            onClick={() => handleDeleteContent(item)}
                            className="p-2 rounded-lg bg-[#090B0E] border border-red-500/30 text-red-400 hover:bg-red-500/10 cursor-pointer"
                            title="حذف نهائي"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: USERS & FULL DATA INSPECTOR */}
          {activeTab === 'users' && hasPermission('manage_users') && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="relative w-full sm:w-96">
                  <Search className="w-4 h-4 text-zinc-500 absolute right-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="search"
                    value={userSearch}
                    onChange={(e) => setUserSearch(e.target.value)}
                    placeholder="ابحث بالاسم، الهاتف، البريد أو البصمة..."
                    className="w-full bg-[#0F1217] border border-zinc-800 rounded-lg pr-10 pl-3 py-2 text-xs text-zinc-100 focus:outline-none"
                  />
                </div>

                <div className="flex items-center gap-1 p-1 bg-[#0F1217] border border-zinc-800 rounded-lg">
                  {(['all', 'active', 'suspended', 'banned'] as const).map((st) => (
                    <button
                      key={st}
                      type="button"
                      onClick={() => setUserStatusFilter(st)}
                      className={`px-3 py-1.5 rounded-md text-xs font-semibold cursor-pointer ${
                        userStatusFilter === st
                          ? 'bg-zinc-800 text-zinc-100'
                          : 'text-zinc-400 hover:text-zinc-200'
                      }`}
                    >
                      {st === 'all'
                        ? 'الكل'
                        : st === 'active'
                          ? 'نشط'
                          : st === 'suspended'
                            ? 'معلّق'
                            : 'محظور'}
                    </button>
                  ))}
                </div>
              </div>

              <div className="bg-[#0F1217] border border-zinc-800 rounded-xl overflow-x-auto">
                <table className="w-full text-right text-xs">
                  <thead className="bg-[#090B0E] border-b border-zinc-800 text-zinc-400">
                    <tr>
                      <th className="py-3 px-4 font-semibold">الاسم الثنائي</th>
                      <th className="py-3 px-4 font-semibold">رقم الهاتف</th>
                      <th className="py-3 px-4 font-semibold">البريد الإلكتروني</th>
                      <th className="py-3 px-4 font-semibold">توثيق البريد</th>
                      <th className="py-3 px-4 font-semibold">الحالة</th>
                      <th className="py-3 px-4 font-semibold">البصمة الأمنية</th>
                      <th className="py-3 px-4 font-semibold">الإجراءات</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/80">
                    {filteredUsers.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="py-10 text-center text-zinc-500">
                          لا يوجد مستخدمون مسجلون مطابقون.
                        </td>
                      </tr>
                    ) : (
                      filteredUsers.map((u) => (
                        <tr key={u.uid} className="hover:bg-zinc-900/40">
                          <td className="py-3 px-4 font-semibold text-zinc-100">{u.fullName}</td>
                          <td className="py-3 px-4 font-mono-tabular text-zinc-300" dir="ltr">
                            {u.phone}
                          </td>
                          <td className="py-3 px-4 font-mono-tabular text-zinc-300">{u.email}</td>
                          <td className="py-3 px-4">
                            {u.emailVerified ? (
                              <span className="text-emerald-400">مؤكد</span>
                            ) : (
                              <span className="text-amber-400">بانتظار التفعيل</span>
                            )}
                          </td>
                          <td className="py-3 px-4">
                            <span
                              className={
                                u.status === 'active'
                                  ? 'text-emerald-400'
                                  : u.status === 'suspended'
                                    ? 'text-amber-400'
                                    : 'text-red-400'
                              }
                            >
                              {u.status === 'active'
                                ? 'نشط'
                                : u.status === 'suspended'
                                  ? 'معلّق'
                                  : 'محظور'}
                            </span>
                          </td>
                          <td className="py-3 px-4 font-mono-tabular text-zinc-500">
                            {u.securityFingerprint.slice(0, 12)}
                          </td>
                          <td className="py-3 px-4">
                            <div className="flex items-center gap-2">
                              <button
                                type="button"
                                onClick={() => {
                                  setInspectedUser(u);
                                  setEditNotes(u.notes || '');
                                }}
                                className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-100 font-semibold cursor-pointer"
                              >
                                فحص كافة البيانات
                              </button>
                              {u.status === 'active' ? (
                                <button
                                  type="button"
                                  onClick={() => handleUpdateUserStatus(u, 'banned')}
                                  className="px-2.5 py-1 rounded bg-red-500/15 border border-red-500/30 text-red-300 cursor-pointer"
                                >
                                  حظر
                                </button>
                              ) : (
                                <button
                                  type="button"
                                  onClick={() => handleUpdateUserStatus(u, 'active')}
                                  className="px-2.5 py-1 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 cursor-pointer"
                                >
                                  تفعيل
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>

              {/* User Full Data Dossier Modal */}
              {inspectedUser && (
                <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
                  <div className="max-w-xl w-full bg-[#0F1217] border border-zinc-800 rounded-xl p-6 space-y-5 max-h-[90vh] overflow-y-auto">
                    <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
                      <div>
                        <h3 className="text-lg font-bold text-zinc-100">{inspectedUser.fullName}</h3>
                        <p className="text-xs text-zinc-400 font-mono-tabular">{inspectedUser.uid}</p>
                      </div>
                      <button
                        type="button"
                        onClick={() => setInspectedUser(null)}
                        className="px-3 py-1 rounded-lg bg-zinc-900 border border-zinc-800 text-xs text-zinc-300 cursor-pointer"
                      >
                        إغلاق
                      </button>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                      <div className="p-3 rounded-lg bg-[#090B0E] border border-zinc-800">
                        <span className="text-zinc-500 block">البريد الإلكتروني</span>
                        <span className="text-zinc-100 font-mono-tabular">{inspectedUser.email}</span>
                      </div>
                      <div className="p-3 rounded-lg bg-[#090B0E] border border-zinc-800">
                        <span className="text-zinc-500 block">رقم الهاتف</span>
                        <span className="text-zinc-100 font-mono-tabular" dir="ltr">
                          {inspectedUser.phone}
                        </span>
                      </div>
                      <div className="p-3 rounded-lg bg-[#090B0E] border border-zinc-800">
                        <span className="text-zinc-500 block">تاريخ التسجيل</span>
                        <span className="text-zinc-100 font-mono-tabular">
                          {formatDateTime(inspectedUser.createdAt)}
                        </span>
                      </div>
                      <div className="p-3 rounded-lg bg-[#090B0E] border border-zinc-800">
                        <span className="text-zinc-500 block">آخر تسجيل دخول</span>
                        <span className="text-zinc-100 font-mono-tabular">
                          {formatDateTime(inspectedUser.lastLoginAt)}
                        </span>
                      </div>
                      <div className="sm:col-span-2 p-3 rounded-lg bg-[#090B0E] border border-zinc-800">
                        <span className="text-zinc-500 block">البصمة الأمنية SHA-256</span>
                        <span className="text-emerald-400 font-mono-tabular break-all">
                          {inspectedUser.securityFingerprint}
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="block text-xs text-zinc-400 mb-1">الحالة الأمنية</label>
                        <select
                          value={inspectedUser.status}
                          onChange={(e) => {
                            const val = e.target.value as UserStatus;
                            void handleUpdateUserStatus(inspectedUser, val);
                            setInspectedUser({ ...inspectedUser, status: val });
                          }}
                          className="w-full bg-[#090B0E] border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100"
                        >
                          <option value="active">نشط (مسموح)</option>
                          <option value="suspended">معلق مؤقتاً</option>
                          <option value="banned">حظر دائم</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-xs text-zinc-400 mb-1">مستوى التصريح</label>
                        <select
                          value={inspectedUser.clearanceLevel}
                          onChange={(e) => {
                            const val = e.target.value as ClearanceLevel;
                            void handleUpdateClearance(inspectedUser, val);
                            setInspectedUser({ ...inspectedUser, clearanceLevel: val });
                          }}
                          className="w-full bg-[#090B0E] border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100"
                        >
                          <option value="standard">قياسي</option>
                          <option value="elevated">متقدم</option>
                          <option value="restricted">مقيد</option>
                        </select>
                      </div>
                    </div>

                    <div className="space-y-2">
                      <label className="block text-xs text-zinc-400">ملاحظات الإدارة السرية</label>
                      <textarea
                        rows={3}
                        value={editNotes}
                        onChange={(e) => setEditNotes(e.target.value)}
                        className="w-full bg-[#090B0E] border border-zinc-800 rounded-lg p-3 text-xs text-zinc-100 focus:outline-none"
                      />
                      <div className="flex items-center justify-between gap-3">
                        <button
                          type="button"
                          onClick={handleSaveUserNotes}
                          className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-zinc-950 text-xs font-bold cursor-pointer"
                        >
                          حفظ الملاحظات
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDeleteUser(inspectedUser)}
                          className="px-4 py-2 rounded-lg bg-red-500/15 border border-red-500/30 text-red-300 text-xs font-semibold cursor-pointer"
                        >
                          حذف سجل المستخدم
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 4: ADMINS & RBAC PERMISSIONS */}
          {activeTab === 'admins' && (hasPermission('manage_admins') || isOwner) && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
              <form
                onSubmit={handleAddAdmin}
                className="lg:col-span-5 bg-[#0F1217] border border-zinc-800 rounded-xl p-6 space-y-4"
              >
                <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                  <h2 className="text-base font-bold text-zinc-100 flex items-center gap-2">
                    <UserPlus className="w-4 h-4 text-emerald-400" />
                    إضافة أدمن بجانب رئيس الموقع
                  </h2>
                </div>

                <div className="flex items-center gap-1 p-1 bg-[#090B0E] border border-zinc-800 rounded-lg">
                  <button
                    type="button"
                    onClick={() => setInviteMode('promote')}
                    className={`flex-1 py-1.5 rounded-md text-xs font-semibold cursor-pointer ${
                      inviteMode === 'promote'
                        ? 'bg-zinc-800 text-zinc-100'
                        : 'text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    ترقية عضو مسجل
                  </button>
                  <button
                    type="button"
                    onClick={() => setInviteMode('email')}
                    className={`flex-1 py-1.5 rounded-md text-xs font-semibold cursor-pointer ${
                      inviteMode === 'email'
                        ? 'bg-zinc-800 text-zinc-100'
                        : 'text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    تفويض بريد جديد
                  </button>
                </div>

                {inviteMode === 'promote' ? (
                  <div>
                    <label className="block text-xs text-zinc-400 mb-1">اختر العضو الموثق</label>
                    <select
                      value={selectedUserUid}
                      onChange={(e) => setSelectedUserUid(e.target.value)}
                      className="w-full bg-[#090B0E] border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100"
                    >
                      <option value="">-- اختر عضواً --</option>
                      {usersList
                        .filter((u) => !adminsList.some((a) => a.uid === u.uid))
                        .map((u) => (
                          <option key={u.uid} value={u.uid}>
                            {u.fullName} ({u.email})
                          </option>
                        ))}
                    </select>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <div>
                      <label className="block text-xs text-zinc-400 mb-1">الاسم الثنائي للأدمن</label>
                      <input
                        type="text"
                        required
                        value={inviteName}
                        onChange={(e) => setInviteName(e.target.value)}
                        placeholder="مثال: طارق سالم"
                        className="w-full bg-[#090B0E] border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-zinc-400 mb-1">البريد الإلكتروني</label>
                      <input
                        type="email"
                        required
                        dir="ltr"
                        value={inviteEmail}
                        onChange={(e) => setInviteEmail(e.target.value)}
                        placeholder="admin@domain.com"
                        className="w-full bg-[#090B0E] border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 font-mono-tabular text-left"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-zinc-400 mb-1">رقم الهاتف (اختياري)</label>
                      <input
                        type="tel"
                        dir="ltr"
                        value={invitePhone}
                        onChange={(e) => setInvitePhone(e.target.value)}
                        placeholder="+20..."
                        className="w-full bg-[#090B0E] border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 font-mono-tabular text-left"
                      />
                    </div>
                  </div>
                )}

                <div className="space-y-2 pt-2 border-t border-zinc-800">
                  <div className="text-xs font-semibold text-zinc-300">صلاحيات الوصول (RBAC):</div>
                  {ALL_ADMIN_PERMISSIONS.map((perm) => (
                    <label
                      key={perm.id}
                      className="flex items-start gap-2.5 p-2.5 rounded-lg bg-[#090B0E] border border-zinc-800/80 cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={selectedPerms.includes(perm.id)}
                        onChange={() => togglePerm(perm.id)}
                        className="mt-0.5 accent-emerald-500"
                      />
                      <div>
                        <div className="text-xs font-semibold text-zinc-200">{perm.label}</div>
                        <div className="text-xs text-zinc-500">{perm.description}</div>
                      </div>
                    </label>
                  ))}
                </div>

                <button
                  type="submit"
                  className="w-full py-2.5 px-4 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-zinc-950 text-xs font-bold cursor-pointer"
                >
                  اعتماد وإضافة الأدمن
                </button>
              </form>

              <div className="lg:col-span-7 space-y-6">
                <div className="bg-[#0F1217] border border-zinc-800 rounded-xl overflow-hidden">
                  <div className="px-6 py-4 border-b border-zinc-800">
                    <h2 className="text-base font-bold text-zinc-100">
                      طاقم الإدارة المعتمد ({adminsList.length})
                    </h2>
                  </div>
                  <div className="divide-y divide-zinc-800/80">
                    {adminsList.map((adm) => (
                      <div key={adm.uid} className="p-5 space-y-3">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-bold text-zinc-100">{adm.fullName}</span>
                              <span className="text-xs text-emerald-400">
                                {adm.role === 'owner' ? 'رئيس الموقع' : adm.active ? 'أدمن نشط' : 'مجمّد'}
                              </span>
                            </div>
                            <div className="text-xs text-zinc-400 font-mono-tabular">
                              {adm.email} {adm.phone ? `· ${adm.phone}` : ''}
                            </div>
                          </div>

                          {adm.email.toLowerCase() !== SITE_OWNER_EMAIL && (
                            <div className="flex items-center gap-2 shrink-0">
                              <button
                                type="button"
                                onClick={() => setEditingAdmin(adm)}
                                className="px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-100 text-xs font-semibold cursor-pointer"
                              >
                                تعديل الصلاحيات
                              </button>
                              <button
                                type="button"
                                onClick={() => handleRemoveAdmin(adm)}
                                className="px-3 py-1.5 rounded-lg bg-red-500/15 border border-red-500/30 text-red-300 text-xs font-semibold cursor-pointer"
                              >
                                إزالة
                              </button>
                            </div>
                          )}
                        </div>

                        <div className="text-xs text-zinc-400">
                          الصلاحيات:{' '}
                          {adm.permissions
                            .map((p) => ALL_ADMIN_PERMISSIONS.find((x) => x.id === p)?.label || p)
                            .join(' · ')}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {invitesList.length > 0 && (
                  <div className="bg-[#0F1217] border border-zinc-800 rounded-xl overflow-hidden">
                    <div className="px-6 py-4 border-b border-zinc-800">
                      <h3 className="text-sm font-bold text-zinc-100">
                        دعوات الإدارة المعلقة ({invitesList.length})
                      </h3>
                    </div>
                    <div className="divide-y divide-zinc-800/80">
                      {invitesList.map((inv) => (
                        <div key={inv.id} className="p-4 flex items-center justify-between gap-4 text-xs">
                          <div>
                            <div className="font-bold text-zinc-100">{inv.fullName}</div>
                            <div className="text-zinc-400 font-mono-tabular">{inv.email}</div>
                          </div>
                          <button
                            type="button"
                            onClick={async () => {
                              await deleteDoc(doc(db, 'admin_invites', inv.id));
                              notify('ok', 'تم إلغاء التفويض المعلق.');
                            }}
                            className="px-3 py-1 rounded bg-zinc-900 border border-zinc-800 text-red-300 cursor-pointer"
                          >
                            إلغاء التفويض
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Edit Admin Permissions Modal */}
              {editingAdmin && (
                <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
                  <div className="max-w-md w-full bg-[#0F1217] border border-zinc-800 rounded-xl p-6 space-y-4">
                    <h3 className="text-base font-bold text-zinc-100">
                      تعديل صلاحيات {editingAdmin.fullName}
                    </h3>
                    <label className="flex items-center justify-between p-3 rounded-lg bg-[#090B0E] border border-zinc-800 text-xs">
                      <span>حالة الحساب الإداري (نشط)</span>
                      <input
                        type="checkbox"
                        checked={editingAdmin.active}
                        onChange={(e) =>
                          setEditingAdmin({ ...editingAdmin, active: e.target.checked })
                        }
                        className="accent-emerald-500"
                      />
                    </label>

                    <div className="space-y-2 max-h-64 overflow-y-auto">
                      {ALL_ADMIN_PERMISSIONS.map((p) => (
                        <label
                          key={p.id}
                          className="flex items-center gap-2.5 p-2.5 rounded-lg bg-[#090B0E] border border-zinc-800 text-xs cursor-pointer"
                        >
                          <input
                            type="checkbox"
                            checked={editingAdmin.permissions.includes(p.id)}
                            onChange={() => {
                              const exists = editingAdmin.permissions.includes(p.id);
                              setEditingAdmin({
                                ...editingAdmin,
                                permissions: exists
                                  ? editingAdmin.permissions.filter((x) => x !== p.id)
                                  : [...editingAdmin.permissions, p.id],
                              });
                            }}
                            className="accent-emerald-500"
                          />
                          <span className="text-zinc-200">{p.label}</span>
                        </label>
                      ))}
                    </div>

                    <div className="flex items-center gap-3 pt-2">
                      <button
                        type="button"
                        onClick={() =>
                          handleSaveAdminPermissions(
                            editingAdmin,
                            editingAdmin.permissions,
                            editingAdmin.active
                          )
                        }
                        className="flex-1 py-2 rounded-lg bg-emerald-600 text-zinc-950 text-xs font-bold cursor-pointer"
                      >
                        حفظ الصلاحيات
                      </button>
                      <button
                        type="button"
                        onClick={() => setEditingAdmin(null)}
                        className="px-4 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-300 text-xs cursor-pointer"
                      >
                        إلغاء
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 5: DETAILED ADMIN ACTIVITY LOGS */}
          {activeTab === 'logs' && hasPermission('view_logs') && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3 bg-[#0F1217] border border-zinc-800 rounded-xl p-4">
                <div className="flex flex-wrap items-center gap-3">
                  <select
                    value={logActorFilter}
                    onChange={(e) => setLogActorFilter(e.target.value)}
                    className="bg-[#090B0E] border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100"
                  >
                    <option value="all">كل المدراء</option>
                    {uniqueLogActors.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name} ({a.email})
                      </option>
                    ))}
                  </select>

                  <select
                    value={logSeverityFilter}
                    onChange={(e) =>
                      setLogSeverityFilter(e.target.value as 'all' | ActivityLog['severity'])
                    }
                    className="bg-[#090B0E] border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100"
                  >
                    <option value="all">كل المستويات</option>
                    <option value="info">عادي (Info)</option>
                    <option value="warning">تحذير (Warning)</option>
                    <option value="critical">حرج (Critical)</option>
                  </select>

                  <select
                    value={logTargetFilter}
                    onChange={(e) =>
                      setLogTargetFilter(e.target.value as 'all' | ActivityLog['targetType'])
                    }
                    className="bg-[#090B0E] border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100"
                  >
                    <option value="all">كل الأهداف</option>
                    <option value="content">المحتوى</option>
                    <option value="user">المستخدمون</option>
                    <option value="admin">المدراء</option>
                    <option value="system">النظام</option>
                  </select>
                </div>

                <button
                  type="button"
                  onClick={exportLogsCsv}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-100 text-xs font-semibold cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  تصدير CSV
                </button>
              </div>

              <div className="bg-[#0F1217] border border-zinc-800 rounded-xl overflow-x-auto">
                <table className="w-full text-right text-xs">
                  <thead className="bg-[#090B0E] border-b border-zinc-800 text-zinc-400">
                    <tr>
                      <th className="py-3 px-4">الوقت</th>
                      <th className="py-3 px-4">المدير المنفذ</th>
                      <th className="py-3 px-4">العملية</th>
                      <th className="py-3 px-4">التفاصيل</th>
                      <th className="py-3 px-4">الأهمية</th>
                      <th className="py-3 px-4">ختم التدقيق SHA-256</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/80">
                    {filteredLogs.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="py-10 text-center text-zinc-500">
                          لا توجد عمليات مسجلة مطابقة للفلتر.
                        </td>
                      </tr>
                    ) : (
                      filteredLogs.map((log) => (
                        <tr key={log.id} className="hover:bg-zinc-900/40">
                          <td className="py-3 px-4 font-mono-tabular text-zinc-400 whitespace-nowrap">
                            {formatDateTime(log.createdAt)}
                          </td>
                          <td className="py-3 px-4">
                            <div className="font-semibold text-zinc-100">{log.actorName}</div>
                            <div className="text-zinc-500 font-mono-tabular">{log.actorEmail}</div>
                          </td>
                          <td className="py-3 px-4 font-mono-tabular text-emerald-400">
                            {log.actionType}
                          </td>
                          <td className="py-3 px-4 text-zinc-300 max-w-md">{log.details}</td>
                          <td className="py-3 px-4">
                            <span
                              className={
                                log.severity === 'critical'
                                  ? 'text-red-400 font-bold'
                                  : log.severity === 'warning'
                                    ? 'text-amber-400'
                                    : 'text-zinc-400'
                              }
                            >
                              {log.severity}
                            </span>
                          </td>
                          <td className="py-3 px-4 font-mono-tabular text-zinc-500">
                            {log.checksum.slice(0, 14)}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 6: SYSTEM SETTINGS & RENDER STATUS */}
          {activeTab === 'settings' && hasPermission('system_settings') && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
              <form
                onSubmit={handleSaveSystemSettings}
                className="lg:col-span-7 bg-[#0F1217] border border-zinc-800 rounded-xl p-6 space-y-4"
              >
                <h2 className="text-base font-bold text-zinc-100 border-b border-zinc-800 pb-3">
                  سياسات الأمان والتحكم العام بالمنصة
                </h2>

                <div>
                  <label className="block text-xs text-zinc-400 mb-1">اسم المنصة الرئيسي</label>
                  <input
                    type="text"
                    value={sSiteTitle}
                    onChange={(e) => setSSiteTitle(e.target.value)}
                    className="w-full bg-[#090B0E] border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-100"
                  />
                </div>

                <div>
                  <label className="block text-xs text-zinc-400 mb-1">رسالة التنبيه العام في الخزنة</label>
                  <textarea
                    rows={3}
                    value={sNotice}
                    onChange={(e) => setSNotice(e.target.value)}
                    placeholder="إشعار يظهر للأعضاء الموثقين داخل Dark Web..."
                    className="w-full bg-[#090B0E] border border-zinc-800 rounded-lg p-3 text-xs text-zinc-100"
                  />
                </div>

                <div className="space-y-3 pt-2">
                  <label className="flex items-center justify-between p-3.5 rounded-lg bg-[#090B0E] border border-zinc-800 cursor-pointer">
                    <div>
                      <div className="text-xs font-semibold text-zinc-200">تفعيل التسجيل الجديد</div>
                      <div className="text-xs text-zinc-500">
                        السماح للأعضاء الجدد بإنشاء حسابات بالاسم الثنائي والهاتف والبريد.
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={sRegOpen}
                      onChange={(e) => setSRegOpen(e.target.checked)}
                      className="accent-emerald-500 w-4 h-4"
                    />
                  </label>

                  <label className="flex items-center justify-between p-3.5 rounded-lg bg-[#090B0E] border border-zinc-800 cursor-pointer">
                    <div>
                      <div className="text-xs font-semibold text-zinc-200">
                        وضع الصيانة والإغلاق المؤقت
                      </div>
                      <div className="text-xs text-zinc-500">
                        يمنع جميع الأعضاء غير الإداريين من تصفح المحتوى مؤقتاً.
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={sMaintenance}
                      onChange={(e) => setSMaintenance(e.target.checked)}
                      className="accent-red-500 w-4 h-4"
                    />
                  </label>
                </div>

                <button
                  type="submit"
                  className="px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-zinc-950 text-xs font-bold inline-flex items-center gap-2 cursor-pointer"
                >
                  <Check className="w-4 h-4" />
                  حفظ سياسات الأمان
                </button>
              </form>

              <div className="lg:col-span-5 bg-[#0F1217] border border-zinc-800 rounded-xl p-6 space-y-4">
                <div className="flex items-center gap-2.5 border-b border-zinc-800 pb-3">
                  <Server className="w-4 h-4 text-emerald-400" />
                  <h2 className="text-base font-bold text-zinc-100">جاهزية النشر على Render</h2>
                </div>

                <div className="space-y-2.5 text-xs">
                  <div className="p-3 rounded-lg bg-[#090B0E] border border-zinc-800 flex items-center justify-between">
                    <span className="text-zinc-400">حالة الخادم الحي</span>
                    <span className="text-emerald-400 font-mono-tabular">
                      {serverHealth?.status || 'active'}
                    </span>
                  </div>
                  <div className="p-3 rounded-lg bg-[#090B0E] border border-zinc-800 flex items-center justify-between">
                    <span className="text-zinc-400">إصدار Node.js</span>
                    <span className="text-zinc-200 font-mono-tabular">
                      {serverHealth?.nodeVersion || 'v22'}
                    </span>
                  </div>
                  <div className="p-3 rounded-lg bg-[#090B0E] border border-zinc-800 flex items-center justify-between">
                    <span className="text-zinc-400">بروتوكول التشفير</span>
                    <span className="text-zinc-200 font-mono-tabular">AES-256-GCM</span>
                  </div>
                  <div className="p-3 rounded-lg bg-[#090B0E] border border-zinc-800 flex items-center justify-between">
                    <span className="text-zinc-400">قاعدة البيانات السريعة</span>
                    <span className="text-emerald-400 font-mono-tabular">Cloud Firestore</span>
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-[#090B0E] border border-zinc-800 text-xs text-zinc-400 leading-relaxed space-y-2">
                  <div className="font-bold text-zinc-200 flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    مخطط render.yaml المزدوج جاهز:
                  </div>
                  <p>
                    تم إعداد خدمتين مستقلتين في ملف <span className="font-mono-tabular text-zinc-200">render.yaml</span>:
                  </p>
                  <p className="font-mono-tabular text-zinc-300">
                    1. dark-web-portal (VITE_SITE_ROLE=portal)
                    <br />
                    2. dark-web-admin (VITE_SITE_ROLE=admin)
                  </p>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Admin Change / Link Password Modal */}
      {showPasswordModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <form
            onSubmit={handleChangeOwnPassword}
            className="max-w-md w-full bg-[#0F1217] border border-zinc-800 rounded-xl p-6 space-y-4"
          >
            <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
              <div className="flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-emerald-400" />
                <h3 className="text-base font-bold text-zinc-100">
                  {hasPasswordProvider ? 'تغيير كلمة المرور' : 'تعيين كلمة مرور للدخول بالبريد'}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowPasswordModal(false)}
                className="text-zinc-400 hover:text-zinc-100 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-zinc-400 leading-relaxed">
              الحساب: <span className="font-mono-tabular text-zinc-200">{actorEmail}</span>
            </p>

            {pwdError && (
              <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-xs">
                {pwdError}
              </div>
            )}

            {hasPasswordProvider && (
              <div>
                <label className="block text-xs text-zinc-400 mb-1">كلمة المرور الحالية</label>
                <input
                  type="password"
                  required
                  dir="ltr"
                  value={currentPwd}
                  onChange={(e) => setCurrentPwd(e.target.value)}
                  className="w-full bg-[#090B0E] border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 font-mono-tabular text-left"
                />
              </div>
            )}

            <div>
              <label className="block text-xs text-zinc-400 mb-1">كلمة المرور الجديدة (8 خانات على الأقل)</label>
              <input
                type="password"
                required
                minLength={8}
                dir="ltr"
                value={newPwd}
                onChange={(e) => setNewPwd(e.target.value)}
                className="w-full bg-[#090B0E] border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 font-mono-tabular text-left"
              />
            </div>

            <div>
              <label className="block text-xs text-zinc-400 mb-1">تأكيد كلمة المرور الجديدة</label>
              <input
                type="password"
                required
                minLength={8}
                dir="ltr"
                value={confirmPwd}
                onChange={(e) => setConfirmPwd(e.target.value)}
                className="w-full bg-[#090B0E] border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 font-mono-tabular text-left"
              />
            </div>

            <div className="flex items-center gap-3 pt-2">
              <button
                type="submit"
                disabled={pwdSaving}
                className="flex-1 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-60 text-zinc-950 text-xs font-bold cursor-pointer"
              >
                {pwdSaving ? 'جاري التحديث...' : 'حفظ كلمة المرور الجديدة'}
              </button>
              <button
                type="button"
                onClick={() => setShowPasswordModal(false)}
                className="px-4 py-2.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-300 text-xs cursor-pointer"
              >
                إلغاء
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
