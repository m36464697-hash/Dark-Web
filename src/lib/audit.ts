import { doc, serverTimestamp, setDoc } from 'firebase/firestore';
import { BLUEPRINT_LIMITS, type ActivitySeverity, type ActivityTargetType, type AlertCategory } from '../types';
import { generateValidDocId, sha256Hex } from './crypto';
import { db, handleFirestoreError, OperationType } from './firebase';

interface LogParams {
  actorId: string;
  actorName: string;
  actorEmail: string;
  actorRole: 'owner' | 'admin';
  actionType: string;
  targetType: ActivityTargetType;
  targetId?: string;
  details: string;
  severity: ActivitySeverity;
}

export async function recordAdminAction(params: LogParams): Promise<void> {
  const logId = generateValidDocId('log');
  const safeDetails = params.details.slice(0, BLUEPRINT_LIMITS.DETAILS_MAX);
  const checksum = await sha256Hex(
    `${params.actorId}:${params.actionType}:${params.targetType}:${params.targetId || ''}:${safeDetails}:${Date.now()}`
  );

  const path = `activity_logs/${logId}`;
  try {
    await setDoc(doc(db, 'activity_logs', logId), {
      actorId: params.actorId,
      actorName: params.actorName.slice(0, 120),
      actorEmail: params.actorEmail.slice(0, 160),
      actorRole: params.actorRole,
      actionType: params.actionType.slice(0, 80),
      targetType: params.targetType,
      ...(params.targetId ? { targetId: params.targetId.slice(0, 128) } : {}),
      details: safeDetails,
      severity: params.severity,
      checksum,
      createdAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

interface AlertParams {
  title: string;
  message: string;
  category: AlertCategory;
  severity: 'high' | 'critical';
  actorId: string;
  actorEmail: string;
}

export async function emitSecurityAlert(params: AlertParams): Promise<void> {
  const alertId = generateValidDocId('alert');
  const path = `security_alerts/${alertId}`;
  try {
    await setDoc(doc(db, 'security_alerts', alertId), {
      title: params.title.slice(0, BLUEPRINT_LIMITS.ALERT_TITLE_MAX),
      message: params.message.slice(0, BLUEPRINT_LIMITS.ALERT_MSG_MAX),
      category: params.category,
      severity: params.severity,
      actorId: params.actorId,
      actorEmail: params.actorEmail.slice(0, 160),
      acknowledged: false,
      createdAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}
