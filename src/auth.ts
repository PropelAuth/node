import {
    ForbiddenException,
    getApis,
    InternalUser,
    OrgIdToOrgMemberInfo,
    OrgMemberInfo,
    TokenVerificationMetadata,
    toUser,
    UnauthorizedException,
    User,
    UserAndOrgMemberInfo,
    UserClass,
} from "@propelauth/node-apis"
import * as jose from "jose"
import {
    getTokenVerificationMetadataPromise,
    TokenVerificationMetadataWithPublicKey,
} from "./tokenVerificationMetadata"
import { validateAuthUrl } from "./validators"

export type BaseAuthOptions = {
    authUrl: string
    apiKey: string

    /**
     * By default, this library performs a one-time fetch on startup for
     *   token verification metadata from your authUrl using your apiKey.
     *
     * This is usually preferred to make sure you have the most up to date information,
     *   however, in environments like serverless, this one-time fetch becomes a
     *   per-request fetch.
     *
     * In those environments, you can specify the token verification metadata manually,
     *   which you can obtain from your PropelAuth project.
     */
    manualTokenVerificationMetadata?: TokenVerificationMetadata
}

export function initBaseAuth(opts: BaseAuthOptions) {
    const authUrl: URL = validateAuthUrl(opts.authUrl)
    const integrationApiKey: string = opts.apiKey
    const apis = getApis(authUrl, integrationApiKey)

    // A promise that resolves to the token verification metadata, whether it's fetched or manually provided
    const tokenVerificationMetadataPromise = opts.manualTokenVerificationMetadata
        ? Promise.resolve(opts.manualTokenVerificationMetadata)
        : apis.fetchTokenVerificationMetadata().catch((err: unknown) => {
              console.error("Error initializing auth library. ", err)
          })

    // A promise that resolves to the token verification metadata with the public key imported
    const tokenVerificationMetadataWithPublicKeyPromise = getTokenVerificationMetadataPromise(
        tokenVerificationMetadataPromise
    )

    const validateAccessTokenAndGetUserClass = wrapValidateAccessTokenAndGetUserClass(
        tokenVerificationMetadataWithPublicKeyPromise
    )
    const validateAccessTokenAndGetUser = wrapValidateAccessTokenAndGetUser(
        tokenVerificationMetadataWithPublicKeyPromise
    )
    const validateAccessTokenAndGetUserWithOrgInfo = wrapValidateAccessTokenAndGetUserWithOrgInfo(
        tokenVerificationMetadataWithPublicKeyPromise
    )
    const validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole =
        wrapValidateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(tokenVerificationMetadataWithPublicKeyPromise)
    const validateAccessTokenAndGetUserWithOrgInfoWithExactRole =
        wrapValidateAccessTokenAndGetUserWithOrgInfoWithExactRole(tokenVerificationMetadataWithPublicKeyPromise)
    const validateAccessTokenAndGetUserWithOrgInfoWithPermission =
        wrapValidateAccessTokenAndGetUserWithOrgInfoWithPermission(tokenVerificationMetadataWithPublicKeyPromise)
    const validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions =
        wrapValidateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(tokenVerificationMetadataWithPublicKeyPromise)

    return {
        // validate functions
        validateAccessTokenAndGetUserClass,
        validateAccessTokenAndGetUser,
        validateAccessTokenAndGetUserWithOrgInfo,
        validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole,
        validateAccessTokenAndGetUserWithOrgInfoWithExactRole,
        validateAccessTokenAndGetUserWithOrgInfoWithPermission,
        validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions,
        // fetching functions
        fetchUserMetadataByUserId: apis.fetchUserMetadataByUserId,
        fetchUserMetadataByEmail: apis.fetchUserMetadataByEmail,
        fetchUserMetadataByUsername: apis.fetchUserMetadataByUsername,
        fetchUserSignupQueryParams: apis.fetchUserSignupQueryParams,
        fetchBatchUserMetadataByUserIds: apis.fetchBatchUserMetadataByUserIds,
        fetchBatchUserMetadataByEmails: apis.fetchBatchUserMetadataByEmails,
        fetchBatchUserMetadataByUsernames: apis.fetchBatchUserMetadataByUsernames,
        fetchOrg: apis.fetchOrg,
        fetchOrgByQuery: apis.fetchOrgByQuery,
        fetchUsersByQuery: apis.fetchUsersByQuery,
        fetchUsersInOrg: apis.fetchUsersInOrg,
        // user management functions
        createUser: apis.createUser,
        clearUserPassword: apis.clearUserPassword,
        updateUserMetadata: apis.updateUserMetadata,
        updateUserEmail: apis.updateUserEmail,
        updateUserPassword: apis.updateUserPassword,
        createMagicLink: apis.createMagicLink,
        createAccessToken: apis.createAccessToken,
        migrateUserFromExternalSource: apis.migrateUserFromExternalSource,
        deleteUser: apis.deleteUser,
        disableUser: apis.disableUser,
        enableUser: apis.enableUser,
        disableUser2fa: apis.disableUser2fa,
        enableUserCanCreateOrgs: apis.enableUserCanCreateOrgs,
        disableUserCanCreateOrgs: apis.disableUserCanCreateOrgs,
        // org management functions
        createOrg: apis.createOrg,
        addUserToOrg: apis.addUserToOrg,
        changeUserRoleInOrg: apis.changeUserRoleInOrg,
        removeUserFromOrg: apis.removeUserFromOrg,
        updateOrg: apis.updateOrg,
        deleteOrg: apis.deleteOrg,
        allowOrgToSetupSamlConnection: apis.allowOrgToSetupSamlConnection,
        disallowOrgToSetupSamlConnection: apis.disallowOrgToSetupSamlConnection,
        inviteUserToOrg: apis.inviteUserToOrg,
        // api keys functions
        fetchApiKey: apis.fetchApiKey,
        fetchCurrentApiKeys: apis.fetchCurrentApiKeys,
        fetchArchivedApiKeys: apis.fetchArchivedApiKeys,
        createApiKey: apis.createApiKey,
        updateApiKey: apis.updateApiKey,
        deleteApiKey: apis.deleteApiKey,
        validateApiKey: apis.validateApiKey,
        validatePersonalApiKey: apis.validatePersonalApiKey,
        validateOrgApiKey: apis.validateOrgApiKey,
    }
}

// wrapper function that returns a UserClass object
function wrapValidateAccessTokenAndGetUserClass(
    tokenVerificationMetadataWithPublicKeyPromise: Promise<TokenVerificationMetadataWithPublicKey>
) {
    return async function validateAccessTokenAndGetUser(authorizationHeader?: string): Promise<UserClass> {
        const user = await extractAndVerifyBearerToken(
            tokenVerificationMetadataWithPublicKeyPromise,
            authorizationHeader
        )
        return new UserClass(user)
    }
}

// wrapper function with no validation
function wrapValidateAccessTokenAndGetUser(
    tokenVerificationMetadataWithPublicKeyPromise: Promise<TokenVerificationMetadataWithPublicKey>
) {
    return async function validateAccessTokenAndGetUser(authorizationHeader?: string): Promise<User> {
        return extractAndVerifyBearerToken(tokenVerificationMetadataWithPublicKeyPromise, authorizationHeader)
    }
}

// The following four functions are wrappers around our four validations: isRole, atLeastRole, hasPermission, hasAllPermissions
// Each function returns an OrgMemberInfo object

function wrapValidateAccessTokenAndGetUserWithOrgInfo(
    tokenVerificationMetadataWithPublicKeyPromise: Promise<TokenVerificationMetadataWithPublicKey>
) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequiredOrgInfo
    ): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(
            tokenVerificationMetadataWithPublicKeyPromise,
            authorizationHeader
        )
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfo(user, requiredOrgInfo)
        return { user, orgMemberInfo }
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(
    tokenVerificationMetadataWithPublicKeyPromise: Promise<TokenVerificationMetadataWithPublicKey>
) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequiredOrgInfo,
        minimumRole: string
    ): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(
            tokenVerificationMetadataWithPublicKeyPromise,
            authorizationHeader
        )
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithMinimumRole(user, requiredOrgInfo, minimumRole)
        return { user, orgMemberInfo }
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithExactRole(
    tokenVerificationMetadataWithPublicKeyPromise: Promise<TokenVerificationMetadataWithPublicKey>
) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequiredOrgInfo,
        exactRole: string
    ): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(
            tokenVerificationMetadataWithPublicKeyPromise,
            authorizationHeader
        )
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithExactRole(user, requiredOrgInfo, exactRole)
        return { user, orgMemberInfo }
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithPermission(
    tokenVerificationMetadataWithPublicKeyPromise: Promise<TokenVerificationMetadataWithPublicKey>
) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequiredOrgInfo,
        permission: string
    ): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(
            tokenVerificationMetadataWithPublicKeyPromise,
            authorizationHeader
        )
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithPermission(user, requiredOrgInfo, permission)
        return { user, orgMemberInfo }
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(
    tokenVerificationMetadataWithPublicKeyPromise: Promise<TokenVerificationMetadataWithPublicKey>
) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequiredOrgInfo,
        permissions: string[]
    ): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(
            tokenVerificationMetadataWithPublicKeyPromise,
            authorizationHeader
        )
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithAllPermissions(user, requiredOrgInfo, permissions)
        return { user, orgMemberInfo }
    }
}

export type RequiredOrgInfo = {
    orgId?: string
    orgName?: string
}

// Validator functions

function validateOrgAccessAndGetOrgMemberInfo(user: User, requiredOrgInfo: RequiredOrgInfo): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    return orgMemberInfo
}

function validateOrgAccessAndGetOrgMemberInfoWithMinimumRole(
    user: User,
    requiredOrgInfo: RequiredOrgInfo,
    minimumRole: string
): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    if (!orgMemberInfo.isAtLeastRole(minimumRole)) {
        throw new ForbiddenException(`User's roles don't contain the minimum role (${minimumRole})`)
    }

    return orgMemberInfo
}

function validateOrgAccessAndGetOrgMemberInfoWithExactRole(
    user: User,
    requiredOrgInfo: RequiredOrgInfo,
    exactRole: string
): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    if (!orgMemberInfo.isRole(exactRole)) {
        throw new ForbiddenException(`User's assigned role isn't the required role (${exactRole})`)
    }

    return orgMemberInfo
}

function validateOrgAccessAndGetOrgMemberInfoWithPermission(
    user: User,
    requiredOrgInfo: RequiredOrgInfo,
    permission: string
): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    if (!orgMemberInfo.hasPermission(permission)) {
        throw new ForbiddenException(`User's permissions don't contain the required permission (${permission})`)
    }

    return orgMemberInfo
}

function validateOrgAccessAndGetOrgMemberInfoWithAllPermissions(
    user: User,
    requiredOrgInfo: RequiredOrgInfo,
    permissions: string[]
): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    if (!orgMemberInfo.hasAllPermissions(permissions)) {
        throw new ForbiddenException(`User's permissions don't contain all the required permissions (${permissions})`)
    }

    return orgMemberInfo
}

// Miscellaneous functions

function getUserInfoInOrg(
    requiredOrgInfo: RequiredOrgInfo,
    orgIdToOrgMemberInfo?: OrgIdToOrgMemberInfo
): OrgMemberInfo | undefined {
    if (!orgIdToOrgMemberInfo) {
        return undefined
    } else if (requiredOrgInfo.orgId) {
        // If we are looking for an orgId, we can do a direct lookup
        if (!orgIdToOrgMemberInfo.hasOwnProperty(requiredOrgInfo.orgId)) {
            return undefined
        }
        const orgMemberInfo = orgIdToOrgMemberInfo[requiredOrgInfo.orgId]

        // We also need to verify the orgName matches, if specified
        if (requiredOrgInfo.orgName && orgNameMatches(requiredOrgInfo.orgName, orgMemberInfo)) {
            return orgMemberInfo
        } else if (requiredOrgInfo.orgName) {
            return undefined
        } else {
            return orgMemberInfo
        }
    } else if (requiredOrgInfo.orgName) {
        // We know there's no required orgId so just iterate over orgMemberInfos looking for a matching urlSafeOrgName
        for (const orgMemberInfo of Object.values(orgIdToOrgMemberInfo)) {
            if (orgNameMatches(requiredOrgInfo.orgName, orgMemberInfo)) {
                return orgMemberInfo
            }
        }
        return undefined
    } else {
        return undefined
    }
}

function orgNameMatches(orgName: string, orgMemberInfo: OrgMemberInfo) {
    return orgName === orgMemberInfo.orgName || orgName === orgMemberInfo.urlSafeOrgName
}

async function extractAndVerifyBearerToken(
    tokenVerificationMetadataWithPublicKeyPromise: Promise<TokenVerificationMetadataWithPublicKey>,
    authorizationHeader: string | undefined,
    allowMissingBearerPrefix = false
) {
    const tokenVerificationMetadataWithPublicKey = await tokenVerificationMetadataWithPublicKeyPromise

    const { publicKey, tokenVerificationMetadata } = tokenVerificationMetadataWithPublicKey

    const bearerToken = extractBearerToken(authorizationHeader, allowMissingBearerPrefix)
    return verifyToken(bearerToken, tokenVerificationMetadata, publicKey)
}

function extractBearerToken(authHeader: string | undefined, allowMissingBearerPrefix: boolean = false): string {
    if (!authHeader) {
        throw new UnauthorizedException("No authorization header found.")
    }

    const authHeaderParts = authHeader.split(" ")
    if (authHeaderParts.length === 1 && allowMissingBearerPrefix) {
        return authHeaderParts[0]
    } else if (authHeaderParts.length !== 2 || authHeaderParts[0].toLowerCase() !== "bearer") {
        throw new UnauthorizedException("Invalid authorization header. Expected: Bearer {accessToken}")
    }

    return authHeaderParts[1]
}

async function verifyToken(
    bearerToken: string,
    tokenVerificationMetadata: TokenVerificationMetadata,
    publicKey: jose.KeyLike
): Promise<User> {
    try {
        const { payload } = await jose.jwtVerify(bearerToken, publicKey, {
            algorithms: ["RS256"],
            issuer: tokenVerificationMetadata.issuer,
        })
        return toUser(<InternalUser>payload)
    } catch (e: unknown) {
        if (e instanceof Error) {
            throw new UnauthorizedException(e.message)
        } else {
            throw new UnauthorizedException("Unable to decode jwt")
        }
    }
}

export type HandleErrorOptions = {
    logError?: boolean
    returnDetailedErrorToUser?: boolean
}

export type HandleErrorResponse = {
    status: number
    message: string
}

export function handleError(e: unknown, opts?: HandleErrorOptions): HandleErrorResponse {
    if (opts && opts.logError) {
        console.error(e)
    }

    const detailedError = opts && opts.returnDetailedErrorToUser
    if (e instanceof UnauthorizedException) {
        return {
            status: 401,
            message: detailedError ? e.message : "Unauthorized",
        }
    } else if (e instanceof ForbiddenException) {
        return {
            status: 403,
            message: detailedError ? e.message : "Forbidden",
        }
    } else {
        return {
            status: 401,
            message: "Unauthorized",
        }
    }
}
