export type UserProperties = { [key: string]: unknown }

export type User = {
    userId: string
    orgIdToOrgMemberInfo?: OrgIdToOrgMemberInfo
    email: string
    firstName?: string
    lastName?: string
    username?: string
    legacyUserId?: string
    impersonatorUserId?: string
    metadata?: { [key: string]: any }
    properties?: UserProperties
    createdAt: number
    pictureUrl?: string
    hasPassword?: boolean
    hasMfaEnabled?: boolean
    canCreateOrgs?: boolean
}

export class UserClass {
    public userId: string
    public orgIdToUserOrgInfo?: { [orgId: string]: OrgMemberInfo }

    // Metadata about the user
    public email: string
    public createdAt: number
    public firstName?: string
    public lastName?: string
    public username?: string
    public properties?: UserProperties
    public pictureUrl?: string
    public hasPassword?: boolean
    public hasMfaEnabled?: boolean
    public canCreateOrgs?: boolean

    // If you used our migration APIs to migrate this user from a different system,
    // this is their original ID from that system.
    public legacyUserId?: string
    public impersonatorUserId?: string

    constructor(userFields: User, orgIdToUserOrgInfo?: { [orgId: string]: OrgMemberInfo }) {
        this.userId = userFields.userId
        this.orgIdToUserOrgInfo = orgIdToUserOrgInfo

        this.email = userFields.email
        this.firstName = userFields.firstName
        this.lastName = userFields.lastName
        this.username = userFields.username
        this.createdAt = userFields.createdAt
        this.pictureUrl = userFields.pictureUrl
        this.hasPassword = userFields.hasPassword
        this.hasMfaEnabled = userFields.hasMfaEnabled
        this.canCreateOrgs = userFields.canCreateOrgs

        this.legacyUserId = userFields.legacyUserId
        this.impersonatorUserId = userFields.impersonatorUserId
        this.properties = userFields.properties
    }

    public getOrg(orgId: string): OrgMemberInfo | undefined {
        if (!this.orgIdToUserOrgInfo) {
            return undefined
        }

        return this.orgIdToUserOrgInfo[orgId]
    }

    public getOrgByName(orgName: string): OrgMemberInfo | undefined {
        if (!this.orgIdToUserOrgInfo) {
            return undefined
        }

        const urlSafeOrgName = orgName.toLowerCase().replace(/ /g, "-")
        for (const orgId in this.orgIdToUserOrgInfo) {
            const orgMemberInfo = this.orgIdToUserOrgInfo[orgId]
            if (orgMemberInfo?.urlSafeOrgName === urlSafeOrgName) {
                return orgMemberInfo
            }
        }

        return undefined
    }

    public getUserProperty(key: string): unknown | undefined {
        if (!this.properties) {
            return undefined
        }

        return this.properties[key]
    }

    public getOrgs(): OrgMemberInfo[] {
        if (!this.orgIdToUserOrgInfo) {
            return []
        }

        return Object.values(this.orgIdToUserOrgInfo)
    }

    public isImpersonating(): boolean {
        return !!this.impersonatorUserId
    }

    public isRole(orgId: string, role: string): boolean {
        const orgMemberInfo = this.getOrg(orgId)
        if (!orgMemberInfo) {
            return false
        }

        return orgMemberInfo.isRole(role)
    }

    public isAtLeastRole(orgId: string, role: string): boolean {
        const orgMemberInfo = this.getOrg(orgId)
        if (!orgMemberInfo) {
            return false
        }

        return orgMemberInfo.isAtLeastRole(role)
    }

    public hasPermission(orgId: string, permission: string): boolean {
        const orgMemberInfo = this.getOrg(orgId)
        if (!orgMemberInfo) {
            return false
        }

        return orgMemberInfo.hasPermission(permission)
    }

    public hasAllPermissions(orgId: string, permissions: string[]): boolean {
        const orgMemberInfo = this.getOrg(orgId)
        if (!orgMemberInfo) {
            return false
        }

        return orgMemberInfo.hasAllPermissions(permissions)
    }

    public static fromJSON(json: string): UserClass {
        const obj = JSON.parse(json)
        const orgIdToUserOrgInfo: { [orgId: string]: OrgMemberInfo } = {}
        for (const orgId in obj.orgIdToUserOrgInfo) {
            orgIdToUserOrgInfo[orgId] = OrgMemberInfo.fromJSON(JSON.stringify(obj.orgIdToUserOrgInfo[orgId]))
        }
        try {
            return new UserClass(
                {
                    userId: obj.userId,
                    email: obj.email,
                    createdAt: obj.createdAt,
                    firstName: obj.firstName,
                    lastName: obj.lastName,
                    username: obj.username,
                    legacyUserId: obj.legacyUserId,
                    impersonatorUserId: obj.impersonatorUserId,
                    properties: obj.properties,
                    pictureUrl: obj.pictureUrl,
                    hasPassword: obj.hasPassword,
                    hasMfaEnabled: obj.hasMfaEnabled,
                    canCreateOrgs: obj.canCreateOrgs,
                },
                orgIdToUserOrgInfo
            )
        } catch (e) {
            console.error("Unable to parse User. Make sure the JSON string is a stringified `UserClass` type.", e)
            throw e
        }
    }
}

export type Org = {
    orgId: string
    name: string
    maxUsers?: number
    isSamlConfigured: boolean
    metadata: { [key: string]: any }
}

export type CreatedOrg = {
    orgId: string
    name: string
}

export type CreatedUser = {
    userId: string
}

export type UserMetadata = {
    userId: string

    email: string
    emailConfirmed: boolean
    hasPassword: boolean

    username?: string
    firstName?: string
    lastName?: string
    pictureUrl?: string

    locked: boolean
    enabled: boolean
    mfaEnabled: boolean
    canCreateOrgs: boolean

    createdAt: number
    lastActiveAt: number

    orgIdToOrgInfo?: OrgIdToOrgMemberInfo

    // If you used our migration APIs to migrate this user from a different system,
    //   this is their original ID from that system.
    legacyUserId?: string
    impersonatorUserId?: string
    metadata?: { [key: string]: any }
    properties?: { [key: string]: unknown }
}

export class OrgMemberInfo {
    public readonly orgId: string
    public readonly orgName: string
    public readonly orgMetadata: { [key: string]: unknown }
    public readonly urlSafeOrgName: string

    private readonly userAssignedRole: string
    private readonly userInheritedRolesPlusCurrentRole: string[]
    private readonly userPermissions: string[]

    constructor(
        orgId: string,
        orgName: string,
        orgMetadata: { [key: string]: any },
        urlSafeOrgName: string,
        userAssignedRole: string,
        userInheritedRolesPlusCurrentRole: string[],
        userPermissions: string[]
    ) {
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
        return permissions.every((permission) => this.hasPermission(permission))
    }

    public static fromJSON(json: string): OrgMemberInfo {
        const obj = JSON.parse(json)
        try {
            return new OrgMemberInfo(
                obj.orgId,
                obj.orgName,
                obj.orgMetadata,
                obj.urlSafeOrgName,
                obj.userAssignedRole,
                obj.userInheritedRolesPlusCurrentRole,
                obj.userPermissions
            )
        } catch (e) {
            console.error(
                "Unable to parse UserOrgInfo. Make sure the JSON string is a stringified `UserOrgInfo` type.",
                e
            )
            throw e
        }
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
    org_metadata: { [key: string]: any }
    url_safe_org_name: string
    user_role: string
    inherited_user_roles_plus_current_role: string[]
    user_permissions: string[]
}

export type InternalUser = {
    user_id: string
    org_id_to_org_member_info?: { [org_id: string]: InternalOrgMemberInfo }

    email: string
    first_name?: string
    last_name?: string
    username?: string
    picture_url?: string
    has_password?: boolean
    has_mfa_enabled?: boolean
    can_create_orgs?: boolean
    created_at: number

    // If you used our migration APIs to migrate this user from a different system, this is their original ID from that system.
    legacy_user_id?: string
    impersonator_user_id?: string
    metadata?: { [key: string]: any }
    properties?: { [key: string]: unknown }
}

export function toUser(snake_case: InternalUser): User {
    const camelCase: User = {
        userId: snake_case.user_id,
        orgIdToOrgMemberInfo: toOrgIdToOrgMemberInfo(snake_case.org_id_to_org_member_info),
        email: snake_case.email,
        firstName: snake_case.first_name,
        lastName: snake_case.last_name,
        username: snake_case.username,
        legacyUserId: snake_case.legacy_user_id,
        impersonatorUserId: snake_case.impersonator_user_id,
        metadata: snake_case.metadata,
        properties: snake_case.properties,
        createdAt: snake_case.created_at,
        pictureUrl: snake_case.picture_url,
        hasPassword: snake_case.has_password,
        hasMfaEnabled: snake_case.has_mfa_enabled,
        canCreateOrgs: snake_case.can_create_orgs,
    }

    return camelCase
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
                snakeCaseValue.user_permissions
            )
        }
    }

    return camelCase
}

export type ApiKeyNew = {
    apiKeyId: string
    apiKeyToken: string
}

export type ApiKeyFull = {
    apiKeyId: string
    createdAt: number
    expiresAtSeconds: number
    metadata: { [key: string]: any }
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
    metadata?: { [key: string]: any }
    user?: UserMetadata
    org?: Org
    userInOrg?: OrgMemberInfo
}

export type PersonalApiKeyValidation = {
    metadata?: { [key: string]: any }
    user: UserMetadata
}

export type OrgApiKeyValidation = {
    metadata?: { [key: string]: any }
    org: Org
    user?: UserMetadata
    userInOrg?: OrgMemberInfo
}
