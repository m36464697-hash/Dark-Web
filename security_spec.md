# Security Specification & Payload-First TDD (`security_spec.md`)

## 1. Data Invariants
1. **Identity Integrity (`users/{userId}`)**: A user cannot create or modify a profile for another UID (`uid == request.auth.uid`), cannot self-assign `status: 'suspended'` or `clearanceLevel: 'elevated'`, and cannot mark `emailVerified: true` unless `request.auth.token.email_verified == true`.
2. **PII Isolation**: User profiles containing `fullName`, `phone`, and `email` are never publicly readable or listable by normal users; only the owning user (`request.auth.uid == userId`), Site Owner, or active verified Admins can inspect them.
3. **RBAC Privilege Escalation Prevention (`admins/{adminId}`)**: Only the bootstrapped Site Owner (`m36464697@gmail.com` with `email_verified == true`) or an active verified Admin with explicit `manage_admins` permission can create or update admin records, and no admin can alter or delete the Site Owner's own privilege record.
4. **Verified Active Member Gate (`content/{contentId}`)**: Content cannot be read or listed by unauthenticated or unverified users (`email_verified == true` required), nor by suspended/banned users. Only the Site Owner or active Admins with `manage_content` permission can create, update, or delete content.
5. **Immutable Audit Trail (`activity_logs/{logId}`)**: Activity logs are strictly append-only (`update: false, delete: false`). `actorId` must equal `request.auth.uid` and `createdAt` must equal `request.time`.
6. **Temporal Integrity & Anti-Shadow-Write**: Every document enforces exact `keys().hasAll(...)` and `keys().hasOnly(...)` on create, `affectedKeys().hasOnly(...)` on update, strict string `.size()` bounds, `isValidId()` on document IDs, and `request.time` server timestamp validation.

## 2. The "Dirty Dozen" Adversarial Payloads
1. **Shadow Field Injection on User Create**: `{ uid, fullName: "Ali Hassan", phone: "+20100000000", email: "a@b.com", emailVerified: false, status: "active", clearanceLevel: "standard", securityFingerprint: "abc12345", isAdmin: true, createdAt: serverTimestamp, updatedAt: serverTimestamp }` -> `PERMISSION_DENIED` (`hasOnly` rejects `isAdmin`).
2. **Self-Verification Spoofing**: Updating `/users/{uid}` with `{ emailVerified: true }` when `request.auth.token.email_verified == false` -> `PERMISSION_DENIED`.
3. **Cross-User PII Read/List**: Non-admin authenticated user executing `getDoc(doc(db, 'users', 'other_uid'))` or `getDocs(collection(db, 'users'))` -> `PERMISSION_DENIED`.
4. **Self-Privilege Escalation to Admin**: Normal user attempting `setDoc(doc(db, 'admins', myUid), { role: 'owner', permissions: ['manage_admins'], ... })` -> `PERMISSION_DENIED`.
5. **Unverified Admin Email Spoofing**: Token claiming email `m36464697@gmail.com` with `email_verified: false` attempting admin write -> `PERMISSION_DENIED`.
6. **Unverified User Reading Dark Web Content**: Signed-in user with `email_verified: false` reading `/content/{id}` -> `PERMISSION_DENIED`.
7. **Normal User Publishing Content**: Verified non-admin user attempting `setDoc(doc(db, 'content', 'c1'), { ... })` -> `PERMISSION_DENIED`.
8. **Audit Log Tampering (Update/Delete)**: Even Site Owner attempting `updateDoc(doc(db, 'activity_logs', 'log1'), { details: 'redacted' })` or `deleteDoc` -> `PERMISSION_DENIED`.
9. **Audit Log Impersonation**: Admin A attempting to create log with `actorId: 'admin_B'` -> `PERMISSION_DENIED`.
10. **Oversized ID Poisoning**: Creating `/content/` with 500-character document ID or invalid characters `../bad` -> `PERMISSION_DENIED` (`isValidId`).
11. **Backdated Timestamp Spoofing**: Creating content or log with client-forged `createdAt: new Date('2020-01-01')` instead of `request.time` -> `PERMISSION_DENIED`.
12. **Owner Deletion Attempt**: Delegated admin with `manage_admins` attempting to delete or demote the Site Owner record -> `PERMISSION_DENIED`.
