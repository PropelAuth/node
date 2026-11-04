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
import { createJwksTokenVerifier, createManualTokenVerifier, TokenVerifier } from "./tokenVerificationMetadata"
import { validateAuthUrl } from "./validators"

export type BaseAuthOptions = {
    authUrl: string
    apiKey: string

    /**
     * By default, this library verifies access tokens against the public keys
     *   published at `{authUrl}/.well-known/jwks.json`, which are fetched on first
     *   use and cached.
     *
     * If your environment can't reach that endpoint, you can specify the token
     *   verification metadata manually, which you can obtain from your PropelAuth project.
     *   `fallbackVerifierKey` is optional and lets tokens signed by the previous key
     *   verify during a key rotation.
     */
    manualTokenVerificationMetadata?: TokenVerificationMetadata
}

export function initBaseAuth(opts: BaseAuthOptions) {
    const authUrl: URL = validateAuthUrl(opts.authUrl)
    const integrationApiKey: string = opts.apiKey
    const apis = getApis(authUrl, integrationApiKey)

    // A promise that resolves to the token verifier, backed by the JWKS endpoint or the manually provided keys
    const tokenVerifierPromise: Promise<TokenVerifier> = opts.manualTokenVerificationMetadata
        ? createManualTokenVerifier(opts.manualTokenVerificationMetadata)
        : createJwksTokenVerifier(authUrl)

    const validateAccessTokenAndGetUserClass = wrapValidateAccessTokenAndGetUserClass(tokenVerifierPromise)
    const validateAccessTokenAndGetUser = wrapValidateAccessTokenAndGetUser(tokenVerifierPromise)
    const validateAccessTokenAndGetUserWithOrgInfo = wrapValidateAccessTokenAndGetUserWithOrgInfo(tokenVerifierPromise)
    const validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole =
        wrapValidateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(tokenVerifierPromise)
    const validateAccessTokenAndGetUserWithOrgInfoWithExactRole =
        wrapValidateAccessTokenAndGetUserWithOrgInfoWithExactRole(tokenVerifierPromise)
    const validateAccessTokenAndGetUserWithOrgInfoWithPermission =
        wrapValidateAccessTokenAndGetUserWithOrgInfoWithPermission(tokenVerifierPromise)
    const validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions =
        wrapValidateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(tokenVerifierPromise)

    // Note: We exclude fetchTokenVerificationMetadata from the returned object.
    // Token verification uses the JWKS endpoint (or manual metadata) instead.
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
        ...nodeApis,
    }
}

// wrapper function that returns a UserClass object
function wrapValidateAccessTokenAndGetUserClass(tokenVerifierPromise: Promise<TokenVerifier>) {
    return async function validateAccessTokenAndGetUser(authorizationHeader?: string): Promise<UserClass> {
        const user = await extractAndVerifyBearerToken(tokenVerifierPromise, authorizationHeader, true)
        return new UserClass(user)
    }
}

// wrapper function with no validation
function wrapValidateAccessTokenAndGetUser(tokenVerifierPromise: Promise<TokenVerifier>) {
    return async function validateAccessTokenAndGetUser(authorizationHeader?: string): Promise<User> {
        return extractAndVerifyBearerToken(tokenVerifierPromise, authorizationHeader)
    }
}

// The following four functions are wrappers around our four validations: isRole, atLeastRole, hasPermission, hasAllPermissions
// Each function returns an OrgMemberInfo object

function wrapValidateAccessTokenAndGetUserWithOrgInfo(tokenVerifierPromise: Promise<TokenVerifier>) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequiredOrgInfo
    ): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(tokenVerifierPromise, authorizationHeader)
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfo(user, requiredOrgInfo)
        return { user, orgMemberInfo }
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(tokenVerifierPromise: Promise<TokenVerifier>) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequiredOrgInfo,
        minimumRole: string
    ): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(tokenVerifierPromise, authorizationHeader)
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithMinimumRole(user, requiredOrgInfo, minimumRole)
        return { user, orgMemberInfo }
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithExactRole(tokenVerifierPromise: Promise<TokenVerifier>) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequiredOrgInfo,
        exactRole: string
    ): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(tokenVerifierPromise, authorizationHeader)
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithExactRole(user, requiredOrgInfo, exactRole)
        return { user, orgMemberInfo }
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithPermission(tokenVerifierPromise: Promise<TokenVerifier>) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequiredOrgInfo,
        permission: string
    ): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(tokenVerifierPromise, authorizationHeader)
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithPermission(user, requiredOrgInfo, permission)
        return { user, orgMemberInfo }
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(tokenVerifierPromise: Promise<TokenVerifier>) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequiredOrgInfo,
        permissions: string[]
    ): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(tokenVerifierPromise, authorizationHeader)
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
    tokenVerifierPromise: Promise<TokenVerifier>,
    authorizationHeader: string | undefined,
    allowMissingBearerPrefix = false
) {
    const tokenVerifier = await tokenVerifierPromise

    const bearerToken = extractBearerToken(authorizationHeader, allowMissingBearerPrefix)
    return verifyToken(bearerToken, tokenVerifier)
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

async function verifyToken(bearerToken: string, tokenVerifier: TokenVerifier): Promise<User> {
    try {
        const payload = await tokenVerifier.verify(bearerToken)
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
