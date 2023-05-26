export type User = {
    userId: string
    orgIdToOrgMemberInfo?: OrgIdToOrgMemberInfo

    // Metadata about the user
    email: string
    firstName?: string,
    lastName?: string,
    username?: string,

    // If you used our migration APIs to migrate this user from a different system,
    //   this is their original ID from that system.
    legacyUserId?: string
    impersonatorUserId?: string
    metadata?: {[key: string]: any}
}

export type Org = {
    orgId: string,
    name: string,
    maxUsers?: number,
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
    canCreateOrgs: boolean,

    createdAt: number,
    lastActiveAt: number,

    orgIdToOrgInfo?: OrgIdToOrgMemberInfo

    // If you used our migration APIs to migrate this user from a different system,
    //   this is their original ID from that system.
    legacyUserId?: string
    impersonatorUserId?: string
    metadata?: {[key: string]: any}
}

export class OrgMemberInfo {
    public readonly orgId: string
    public readonly orgName: string
    public readonly orgMetadata: {[key: string]: any}
    public readonly urlSafeOrgName: string

    private readonly userAssignedRole: string
    private readonly userInheritedRolesPlusCurrentRole: string[]
    private readonly userPermissions: string[]

    constructor(orgId: string, orgName: string, orgMetadata: {[key: string]: any}, urlSafeOrgName: string, userAssignedRole: string, userInheritedRolesPlusCurrentRole: string[], userPermissions: string[]) {
        this.orgId = orgId
        this.orgName = orgName
        this.orgMetadata = orgMetadata
        this.urlSafeOrgName = urlSafeOrgName

        this.userAssignedRole = userAssignedRole
        this.userInheritedRolesPlusCurrentRole = userInheritedRolesPlusCurrentRole
        this.userPermissions = userPermissions
    }

    // validation methods

    public isRole(role: string): boolean {
        return this.userAssignedRole === role
    }

    public isAtLeastRole(role: string): boolean {
        return this.userInheritedRolesPlusCurrentRole.includes(role)
    }

    public hasPermission(permission: string): boolean {
        return this.userPermissions.includes(permission)
    }

    public hasAllPermissions(permissions: string[]): boolean {
        return permissions.every(permission => this.hasPermission(permission))
    }

    public get assignedRole(): string {
        return this.userAssignedRole
    }

    public get permissions(): string[] {
        return this.userPermissions
    }

    // getters for the private fields
    get inheritedRolesPlusCurrentRole(): string[] {
        return this.userInheritedRolesPlusCurrentRole
    }
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
    org_metadata: {[key: string]: any}
    url_safe_org_name: string
    user_role: string
    inherited_user_roles_plus_current_role: string[]
    user_permissions: string[]
}

export type InternalUser = {
    user_id: string
    org_id_to_org_member_info?: { [org_id: string]: InternalOrgMemberInfo }

    email: string
    first_name?: string,
    last_name?: string,
    username?: string,

    // If you used our migration APIs to migrate this user from a different system, this is their original ID from that system.
    legacy_user_id?: string
    impersonator_user_id?: string
    metadata?: {[key: string]: any}
}

export function toUser(snake_case: InternalUser): User {
    return {
        userId: snake_case.user_id,
        orgIdToOrgMemberInfo: toOrgIdToOrgMemberInfo(snake_case.org_id_to_org_member_info),
        email: snake_case.email,
        firstName: snake_case.first_name,
        lastName: snake_case.last_name,
        username: snake_case.username,
        legacyUserId: snake_case.legacy_user_id,
        impersonatorUserId: snake_case.impersonator_user_id,
        metadata: snake_case.metadata,
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
            camelCase[key] = new OrgMemberInfo(
                snakeCaseValue.org_id,
                snakeCaseValue.org_name,
                snakeCaseValue.org_metadata,
                snakeCaseValue.url_safe_org_name,
                snakeCaseValue.user_role,
                snakeCaseValue.inherited_user_roles_plus_current_role,
                snakeCaseValue.user_permissions,
            )
        }
    }

    return camelCase
}


export type ApiKeyNew ={
    apiKeyId: string
    apiKeyToken: string
}

export type ApiKeyFull = {
    apiKeyId: string
    createdAt: number
    expiresAtSeconds: number
    metadata: {[key: string]: any}
    userId: string
    orgId: string
}

export type ApiKeyResultPage = {
    apiKeys: ApiKeyFull[]
    totalApiKeys: number
    currentPage: number
    pageSize: number
    hasMoreResults: boolean
}

export type ApiKeyValidation = {
    metadata?: {[key: string]: any}
    user?: UserMetadata,
    org?: Org,
    userInOrg?: OrgMemberInfo
}

export type PersonalApiKeyValidation = {
    metadata?: {[key: string]: any}
    user?: UserMetadata,
}

export type OrgApiKeyValidation = {
    metadata?: {[key: string]: any}
    org: Org,
    user?: UserMetadata,
    userInOrg?: OrgMemberInfo
}