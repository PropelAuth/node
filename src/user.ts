export type User = {
    userId: string
    orgIdToOrgMemberInfo?: OrgIdToOrgMemberInfo

    // If you used our migration APIs to migrate this user from a different system,
    //   this is their original ID from that system.
    legacyUserId?: string
}
export type Org = {
    orgId: string,
    name: string,
}

export type UserMetadata = {
    userId: string

    email: string
    emailConfirmed: boolean,

    username?: string
    firstName?: string,
    lastName?: string,
    pictureUrl?: string,

    locked: boolean,
    enabled: boolean,
    mfaEnabled: boolean,

    createdAt: number,
    lastActiveAt: number,

    orgIdToOrgInfo?: OrgIdToOrgMemberInfo

    // If you used our migration APIs to migrate this user from a different system,
    //   this is their original ID from that system.
    legacyUserId?: string
}

export enum UserRole {
    Member = 0,
    Admin = 1,
    Owner = 2,
}

export type OrgMemberInfo = {
    orgId: string
    orgName: string
    urlSafeOrgName: string
    userRole: UserRole
}

export type UserAndOrgMemberInfo = {
    user: User
    orgMemberInfo: OrgMemberInfo
}

export type OrgIdToOrgMemberInfo = {
    [orgId: string]: OrgMemberInfo
}

// These Internal types exist since the server returns snake case, but typescript/javascript
// convention is camelCase.
export type InternalOrgMemberInfo = {
    org_id: string
    org_name: string
    url_safe_org_name: string
    user_role: string
}
export type InternalUser = {
    user_id: string
    org_id_to_org_member_info?: { [org_id: string]: InternalOrgMemberInfo }

    // If you used our migration APIs to migrate this user from a different system, this is their original ID from that system.
    legacy_user_id?: string
}

export function toUser(snake_case: InternalUser): User {
    return {
        userId: snake_case.user_id,
        orgIdToOrgMemberInfo: toOrgIdToOrgMemberInfo(snake_case.org_id_to_org_member_info),
        legacyUserId: snake_case.legacy_user_id,
    }
}

export function toOrgIdToOrgMemberInfo(snake_case?: {
    [org_id: string]: InternalOrgMemberInfo
}): OrgIdToOrgMemberInfo | undefined {
    if (snake_case === undefined) {
        return undefined
    }
    const camelCase: OrgIdToOrgMemberInfo = {}

    for (const key of Object.keys(snake_case)) {
        const snakeCaseValue = snake_case[key]
        if (snakeCaseValue) {
            camelCase[key] = {
                orgId: snakeCaseValue.org_id,
                orgName: snakeCaseValue.org_name,
                urlSafeOrgName: snakeCaseValue.url_safe_org_name,
                userRole: toUserRole(snakeCaseValue.user_role),
            }
        }
    }

    return camelCase
}

export function toUserRole(userRole: string): UserRole {
    return UserRole[userRole as keyof typeof UserRole]
}

export function toUserRoleStr(userRole: UserRole): string {
    switch (userRole) {
        case UserRole.Owner:
            return "Owner"
        case UserRole.Admin:
            return "Admin"
        case UserRole.Member:
            return "Member"
    }
}
