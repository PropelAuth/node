import {
    ForbiddenException,
    getApis,
    InternalUser,
    OrgIdToOrgMemberInfo,
    OrgMemberInfo,
    toUser,
    UnauthorizedException,
    User,
    UserAndOrgMemberInfo,
    UserClass,
} from "@propelauth/node-apis"
import * as jose from "jose"
import { KeyLike } from "jose"
import { validateAuthUrl } from "./validators"

export type AuthOptions = {
    authUrl: string
    apiKey: string
    verifierKey: string
}

export type AuthHeader = string | null | undefined

export function initAuth(opts: AuthOptions) {
    const authUrl: URL = validateAuthUrl(opts.authUrl)
    const integrationApiKey: string = opts.apiKey
    const apis = getApis(authUrl, integrationApiKey)

    const publicKeyPromise = jose.importSPKI(opts.verifierKey, "RS256")

    const validateAccessTokenAndGetUserClass = wrapValidateAccessTokenAndGetUserClass(publicKeyPromise, authUrl.origin)
    const validateAccessTokenAndGetUser = wrapValidateAccessTokenAndGetUser(publicKeyPromise, authUrl.origin)
    const validateAccessTokenAndGetUserWithOrgInfo = wrapValidateAccessTokenAndGetUserWithOrgInfo(
        publicKeyPromise,
        authUrl.origin
    )
    const validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole =
        wrapValidateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(publicKeyPromise, authUrl.origin)
    const validateAccessTokenAndGetUserWithOrgInfoWithExactRole =
        wrapValidateAccessTokenAndGetUserWithOrgInfoWithExactRole(publicKeyPromise, authUrl.origin)
    const validateAccessTokenAndGetUserWithOrgInfoWithPermission =
        wrapValidateAccessTokenAndGetUserWithOrgInfoWithPermission(publicKeyPromise, authUrl.origin)
    const validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions =
        wrapValidateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(publicKeyPromise, authUrl.origin)

    // Note: We exclude fetchTokenVerificationMetadata from the returned object
    // because we have explicit usage of it above. Thus, it is not used in the returned object.
    const { fetchTokenVerificationMetadata, ...nodeApis } = apis

    return {
        // validate functions
        validateAccessTokenAndGetUserClass,
        validateAccessTokenAndGetUser,
        validateAccessTokenAndGetUserWithOrgInfo,
        validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole,
        validateAccessTokenAndGetUserWithOrgInfoWithExactRole,
        validateAccessTokenAndGetUserWithOrgInfoWithPermission,
        validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions,
        // older versions of the library used validateAuthHeaderAndGetUser
        validateAuthHeaderAndGetUserClass: validateAccessTokenAndGetUserClass,
        validateAuthHeaderAndGetUser: validateAccessTokenAndGetUser,
        validateAuthHeaderAndGetUserWithOrgInfo: validateAccessTokenAndGetUserWithOrgInfo,
        validateAuthHeaderAndGetUserWithOrgInfoWithMinimumRole: validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole,
        validateAuthHeaderAndGetUserWithOrgInfoWithExactRole: validateAccessTokenAndGetUserWithOrgInfoWithExactRole,
        validateAuthHeaderAndGetUserWithOrgInfoWithPermission: validateAccessTokenAndGetUserWithOrgInfoWithPermission,
        validateAuthHeaderAndGetUserWithOrgInfoWithAllPermissions:
            validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions,
        ...nodeApis,
    }
}

// wrapper function that returns a UserClass object
function wrapValidateAccessTokenAndGetUserClass(publicKeyPromise: Promise<KeyLike>, authUrl: string) {
    return async function validateAccessTokenAndGetUser(authorizationHeader: string | null): Promise<UserClass> {
        const user = await extractAndVerifyBearerToken(publicKeyPromise, authUrl, authorizationHeader, true)
        return new UserClass(user)
    }
}

// wrapper function with no validation
function wrapValidateAccessTokenAndGetUser(publicKeyPromise: Promise<KeyLike>, authUrl: string) {
    return async function validateAccessTokenAndGetUser(authorizationHeader: string | null): Promise<User> {
        return extractAndVerifyBearerToken(publicKeyPromise, authUrl, authorizationHeader)
    }
}

// The following four functions are wrappers around our four validations: isRole, atLeastRole, hasPermission, hasAllPermissions
// Each function returns an OrgMemberInfo object

function wrapValidateAccessTokenAndGetUserWithOrgInfo(publicKeyPromise: Promise<KeyLike>, authUrl: string) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(
        authorizationHeader: string | null,
        requiredOrgInfo: RequiredOrgInfo
    ): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(publicKeyPromise, authUrl, authorizationHeader)
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfo(user, requiredOrgInfo)
        return { user, orgMemberInfo }
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(
    publicKeyPromise: Promise<KeyLike>,
    authUrl: string
) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(
        authorizationHeader: string | null,
        requiredOrgInfo: RequiredOrgInfo,
        minimumRole: string
    ): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(publicKeyPromise, authUrl, authorizationHeader)
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithMinimumRole(user, requiredOrgInfo, minimumRole)
        return { user, orgMemberInfo }
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithExactRole(
    publicKeyPromise: Promise<KeyLike>,
    authUrl: string
) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(
        authorizationHeader: string | null,
        requiredOrgInfo: RequiredOrgInfo,
        exactRole: string
    ): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(publicKeyPromise, authUrl, authorizationHeader)
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithExactRole(user, requiredOrgInfo, exactRole)
        return { user, orgMemberInfo }
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithPermission(
    publicKeyPromise: Promise<KeyLike>,
    authUrl: string
) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(
        authorizationHeader: string | null,
        requiredOrgInfo: RequiredOrgInfo,
        permission: string
    ): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(publicKeyPromise, authUrl, authorizationHeader)
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithPermission(user, requiredOrgInfo, permission)
        return { user, orgMemberInfo }
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(
    publicKeyPromise: Promise<KeyLike>,
    authUrl: string
) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(
        authorizationHeader: string | null,
        requiredOrgInfo: RequiredOrgInfo,
        permissions: string[]
    ): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(publicKeyPromise, authUrl, authorizationHeader)
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
    publicKeyPromise: Promise<KeyLike>,
    authUrl: string,
    authorizationHeader: string | null,
    allowMissingBearerPrefix = false
) {
    const publicKey = await publicKeyPromise
    const bearerToken = extractBearerToken(authorizationHeader, allowMissingBearerPrefix)
    return verifyToken(bearerToken, authUrl, publicKey)
}

function extractBearerToken(authHeader: string | null, allowMissingBearerPrefix: boolean = false): string {
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

async function verifyToken(bearerToken: string, authUrl: string, publicKey: jose.KeyLike): Promise<User> {
    try {
        const { payload } = await jose.jwtVerify(bearerToken, publicKey, {
            algorithms: ["RS256"],
            issuer: authUrl,
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
