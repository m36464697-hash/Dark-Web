import type { Timestamp } from 'firebase/firestore';

export const BLUEPRINT_LIMITS = {
  FULL_NAME_MIN: 3,
  FULL_NAME_MAX: 120,
  PHONE_MIN: 6,
  PHONE_MAX: 32,
  EMAIL_MIN: 5,
  EMAIL_MAX: 160,
  NOTES_MAX: 1000,
  TITLE_MIN: 1,
  TITLE_MAX: 200,
  SUMMARY_MAX: 600,
  BODY_MAX: 20000,
  MEDIA_URL_MAX: 2000,
  PRICE_MAX: 64,
  DETAILS_MAX: 1000,
  ALERT_TITLE_MAX: 160,
  ALERT_MSG_MAX: 800,
  VAULT_NOTICE_MAX: 500,
} as const;

export const SITE_OWNER_EMAIL = 'm36464697@gmail.com';

export type AdminPermission =
  | 'manage_content'
  | 'manage_users'
  | 'manage_admins'
  | 'view_logs'
  | 'view_alerts'
  | 'system_settings';

export const ALL_ADMIN_PERMISSIONS: { id: AdminPermission; label: string; description: string }[] = [
  {
    id: 'manage_content',
    label: 'إدارة ونشر المحتوى',
    description: 'إنشاء وتعديل وإخفاء وحذف الفيديوهات والصور والرسائل والمنتجات المشفرة.',
  },
  {
    id: 'manage_users',
    label: 'إدارة المستخدمين والبيانات',
    description: 'الاطلاع على كافة بيانات الأعضاء وتغيير حالات التوثيق والحظر والتعليق.',
  },
  {
    id: 'manage_admins',
    label: 'إدارة المدراء والصلاحيات',
    description: 'إضافة مدراء جدد وتعديل صلاحياتهم أو تجميد حساباتهم الإدارية.',
  },
  {
    id: 'view_logs',
    label: 'سجل نشاط المدراء',
    description: 'مراقبة وتصدير سجل التدقيق التفصيلي لجميع العمليات داخل النظام.',
  },
  {
    id: 'view_alerts',
    label: 'التنبيهات الأمنية الفورية',
    description: 'استلام التنبيهات الفورية للإجراءات الحساسة وتأكيد مراجعتها.',
  },
  {
    id: 'system_settings',
    label: 'إعدادات النظام والتشفير',
    description: 'التحكم في وضع الصيانة، فتح التسجيل، وإشعارات الأمان العامة.',
  },
];

export type UserStatus = 'active' | 'suspended' | 'banned';
export type ClearanceLevel = 'standard' | 'elevated' | 'restricted';

export interface UserProfile {
  uid: string;
  fullName: string;
  phone: string;
  email: string;
  emailVerified: boolean;
  status: UserStatus;
  clearanceLevel: ClearanceLevel;
  securityFingerprint: string;
  notes?: string;
  createdAt: Timestamp;
  updatedAt: Timestamp;
  lastLoginAt?: Timestamp;
}

export interface AdminRecord {
  uid: string;
  fullName: string;
  email: string;
  phone?: string;
  role: 'owner' | 'admin';
  permissions: AdminPermission[];
  active: boolean;
  addedBy: string;
  addedByEmail: string;
  inviteId?: string;
  createdAt: Timestamp;
  updatedAt: Timestamp;
}

export interface AdminInvite {
  id: string;
  email: string;
  fullName: string;
  phone?: string;
  permissions: AdminPermission[];
  active: boolean;
  invitedBy: string;
  invitedByEmail: string;
  createdAt: Timestamp;
}

export type ContentType = 'video' | 'image' | 'message' | 'product';
export type ContentClassification = 'standard' | 'confidential' | 'encrypted';
export type ContentVisibility = 'published' | 'hidden';

export interface VaultContent {
  id: string;
  type: ContentType;
  title: string;
  summary?: string;
  body?: string;
  mediaUrl?: string;
  price?: string;
  classification: ContentClassification;
  isEncrypted: boolean;
  encryptionIv?: string;
  encryptionSalt?: string;
  integrityHash: string;
  visibility: ContentVisibility;
  authorId: string;
  authorName: string;
  createdAt: Timestamp;
  updatedAt: Timestamp;
}

export type ActivitySeverity = 'info' | 'warning' | 'critical';
export type ActivityTargetType = 'user' | 'admin' | 'content' | 'system' | 'security';

export interface ActivityLog {
  id?: string;
  actorId: string;
  actorName: string;
  actorEmail: string;
  actorRole: 'owner' | 'admin';
  actionType: string;
  targetType: ActivityTargetType;
  targetId?: string;
  details: string;
  severity: ActivitySeverity;
  checksum: string;
  createdAt: Timestamp;
}

export type AlertCategory =
  | 'admin_change'
  | 'user_restriction'
  | 'content_removal'
  | 'policy_update'
  | 'auth_event';

export interface SecurityAlert {
  id?: string;
  title: string;
  message: string;
  category: AlertCategory;
  severity: 'high' | 'critical';
  actorId: string;
  actorEmail: string;
  acknowledged: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: Timestamp;
  createdAt: Timestamp;
}

export interface SystemSettings {
  siteTitle: string;
  maintenanceMode: boolean;
  registrationOpen: boolean;
  requireEmailVerification: boolean;
  encryptionStandard: 'AES-256-GCM';
  vaultNotice?: string;
  updatedBy: string;
  updatedAt: Timestamp;
}
