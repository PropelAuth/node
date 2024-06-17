import { initBaseAuth, RequriedOrgInfo } from "@propelauth/node"

export type AuthOptions = {
    authUrl: string
    apiKey: string
    verifierKey: string
}

export type AuthHeader = string | null | undefined

export function initAuth(opts: AuthOptions) {
    const nodeVersion = initBaseAuth({
        authUrl: opts.authUrl,
        apiKey: opts.apiKey,
        manualTokenVerificationMetadata: {
            verifierKey: opts.verifierKey,
            issuer: opts.authUrl,
        },
    })
    return {
        ...nodeVersion,

        // For backcompat, match the style of functions in the CF worker library
        validateAuthHeaderAndGetUser: (authHeader: AuthHeader) =>
            nodeVersion.validateAccessTokenAndGetUser(convertAuthHeader(authHeader)),

        validateAuthHeaderAndGetUserWithOrgInfo: (authHeader: AuthHeader, requiredOrgInfo: RequriedOrgInfo) =>
            nodeVersion.validateAccessTokenAndGetUserWithOrgInfo(convertAuthHeader(authHeader), requiredOrgInfo),

        validateAuthHeaderAndGetUserWithOrgInfoWithMinimumRole: (
            authorizationHeader: AuthHeader,
            requiredOrgInfo: RequriedOrgInfo,
            minimumRole: string
        ) =>
            nodeVersion.validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(
                convertAuthHeader(authorizationHeader),
                requiredOrgInfo,
                minimumRole
            ),

        validateAuthHeaderAndGetUserWithOrgInfoWithExactRole: (
            authorizationHeader: AuthHeader,
            requiredOrgInfo: RequriedOrgInfo,
            exactRole: string
        ) =>
            nodeVersion.validateAccessTokenAndGetUserWithOrgInfoWithExactRole(
                convertAuthHeader(authorizationHeader),
                requiredOrgInfo,
                exactRole
            ),

        validateAuthHeaderAndGetUserWithOrgInfoWithPermission: (
            authorizationHeader: AuthHeader,
            requiredOrgInfo: RequriedOrgInfo,
            permission: string
        ) =>
            nodeVersion.validateAccessTokenAndGetUserWithOrgInfoWithPermission(
                convertAuthHeader(authorizationHeader),
                requiredOrgInfo,
                permission
            ),

        validateAuthHeaderAndGetUserWithOrgInfoWithAllPermissions: (
            authorizationHeader: string | undefined,
            requiredOrgInfo: RequriedOrgInfo,
            permissions: string[]
        ) =>
            nodeVersion.validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(
                convertAuthHeader(authorizationHeader),
                requiredOrgInfo,
                permissions
            ),
    }
}

// The CF worker library takes in string | null, but the node library takes in string | undefined
// This function is here for backcompat
function convertAuthHeader(authHeader: string | null | undefined): string | undefined {
    if (authHeader === null) {
        return undefined
    }
    return authHeader
}
