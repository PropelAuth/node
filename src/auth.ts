import jwt, {VerifyOptions} from "jsonwebtoken"
import {
    createMagicLink, CreateMagicLinkRequest,
    createUser,
    CreateUserRequest,
    fetchBatchUserMetadata,
    fetchOrg,
    fetchOrgByQuery,
    fetchTokenVerificationMetadata,
    fetchUserMetadataByQuery,
    fetchUserMetadataByUserIdWithIdCheck,
    fetchUsersByQuery,
    fetchUsersInOrg, MagicLink,
    OrgQuery,
    OrgQueryResponse,
    TokenVerificationMetadata, updateUserEmail, UpdateUserEmailRequest, updateUserMetadata, UpdateUserMetadataRequest,
    UsersInOrgQuery,
    UsersPagedResponse,
    UsersQuery,
} from "./api"
import UnauthorizedException from "./UnauthorizedException"
import UnexpectedException from "./UnexpectedException"
import {InternalUser, Org, OrgMemberInfo, toUser, User, UserAndOrgMemberInfo, UserMetadata, UserRole} from "./user"
import {validateAuthUrl} from "./validators"
import ForbiddenException from "./ForbiddenException"

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
    const apiKey: string = opts.apiKey
    const tokenVerificationMetadataPromise = fetchTokenVerificationMetadata(
        authUrl, apiKey, opts.manualTokenVerificationMetadata
    ).catch((err) => {
        console.error("Error initializing auth library. ", err)
    })

    const validateAccessTokenAndGetUser = wrapValidateAccessTokenAndGetUser(tokenVerificationMetadataPromise);
    const validateAccessTokenAndGetUserWithOrg = wrapValidateAccessTokenAndGetUserWithOrg(tokenVerificationMetadataPromise);

    function fetchUserMetadataByUserId(userId: string, includeOrgs?: boolean): Promise<UserMetadata | null> {
        return fetchUserMetadataByUserIdWithIdCheck(authUrl, apiKey, userId, includeOrgs);
    }

    function fetchUserMetadataByEmail(email: string, includeOrgs?: boolean): Promise<UserMetadata | null> {
        return fetchUserMetadataByQuery(authUrl, apiKey, "email", {email: email, include_orgs: includeOrgs || false})
    }

    function fetchUserMetadataByUsername(username: string, includeOrgs?: boolean): Promise<UserMetadata | null> {
        return fetchUserMetadataByQuery(authUrl, apiKey, "username", {
            username: username,
            include_orgs: includeOrgs || false
        })
    }

    function fetchBatchUserMetadataByUserIds(userIds: string[], includeOrgs?: boolean): Promise<{ [userId: string]: UserMetadata }> {
        return fetchBatchUserMetadata(authUrl, apiKey, "user_ids", userIds, (x) => x.userId, includeOrgs || false)
    }

    function fetchBatchUserMetadataByEmails(emails: string[], includeOrgs?: boolean): Promise<{ [email: string]: UserMetadata }> {
        return fetchBatchUserMetadata(authUrl, apiKey, "emails", emails, (x) => x.email, includeOrgs || false)
    }

    function fetchBatchUserMetadataByUsernames(usernames: string[], includeOrgs?: boolean): Promise<{ [username: string]: UserMetadata }> {
        return fetchBatchUserMetadata(authUrl, apiKey, "usernames", usernames, (x) => x.username || "", includeOrgs || false)
    }

    function fetchOrgWrapper(orgId: string): Promise<Org | null> {
        return fetchOrg(authUrl, apiKey, orgId)
    }

    function fetchOrgsByQueryWrapper(orgQuery: OrgQuery): Promise<OrgQueryResponse> {
        return fetchOrgByQuery(authUrl, apiKey, orgQuery)
    }

    function fetchUsersByQueryWrapper(usersQuery: UsersQuery): Promise<UsersPagedResponse> {
        return fetchUsersByQuery(authUrl, apiKey, usersQuery)
    }

    function fetchUsersInOrgWrapper(usersInOrgQuery: UsersInOrgQuery): Promise<UsersPagedResponse> {
        return fetchUsersInOrg(authUrl, apiKey, usersInOrgQuery)
    }

    function createUserWrapper(createUserRequest: CreateUserRequest): Promise<User> {
        return createUser(authUrl, apiKey, createUserRequest)
    }

    function updateUserMetadataWrapper(userId: string, updateUserMetadataRequest: UpdateUserMetadataRequest): Promise<boolean> {
        return updateUserMetadata(authUrl, apiKey, userId, updateUserMetadataRequest)
    }

    function updateUserEmailWrapper(userId: string, updateUserEmailRequest: UpdateUserEmailRequest): Promise<boolean> {
        return updateUserEmail(authUrl, apiKey, userId, updateUserEmailRequest)
    }

    function createMagicLinkWrapper(createMagicLinkRequest: CreateMagicLinkRequest): Promise<MagicLink> {
        return createMagicLink(authUrl, apiKey, createMagicLinkRequest)
    }

    return {
        validateAccessTokenAndGetUser,
        validateAccessTokenAndGetUserWithOrg,
        fetchUserMetadataByUserId,
        fetchUserMetadataByEmail,
        fetchUserMetadataByUsername,
        fetchBatchUserMetadataByUserIds,
        fetchBatchUserMetadataByEmails,
        fetchBatchUserMetadataByUsernames,
        fetchOrg: fetchOrgWrapper,
        fetchOrgByQuery: fetchOrgsByQueryWrapper,
        fetchUsersByQuery: fetchUsersByQueryWrapper,
        fetchUsersInOrg: fetchUsersInOrgWrapper,
        createUser: createUserWrapper,
        updateUserMetadata: updateUserMetadataWrapper,
        updateUserEmail: updateUserEmailWrapper,
        createMagicLink: createMagicLinkWrapper,
        UserRole,
    }
}

function wrapValidateAccessTokenAndGetUser(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    return async function validateAccessTokenAndGetUser(authorizationHeader?: string): Promise<User> {
        const tokenVerificationMetadata = await getTokenVerificationMetadata(tokenVerificationMetadataPromise)
        const bearerToken = extractBearerToken(authorizationHeader)
        return verifyToken(bearerToken, tokenVerificationMetadata);
    }
}

function wrapValidateAccessTokenAndGetUserWithOrg(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    return async function validateAccessTokenAndGetUserWithOrg(authorizationHeader: string | undefined,
                                                               requiredOrgId: string,
                                                               minimumRequiredRole?: UserRole): Promise<UserAndOrgMemberInfo> {
        const tokenVerificationMetadata = await getTokenVerificationMetadata(tokenVerificationMetadataPromise)
        const bearerToken = extractBearerToken(authorizationHeader)
        const user = verifyToken(bearerToken, tokenVerificationMetadata);
        const orgMemberInfo = validateOrgAccessAndGetOrg(user, requiredOrgId, minimumRequiredRole);
        return {user, orgMemberInfo}
    }
}

function validateOrgAccessAndGetOrg(user: User, requiredOrgId: string, minimumRequiredRole?: UserRole): OrgMemberInfo {
    const validRole = isValidRole(minimumRequiredRole)
    if (!validRole) {
        console.error(
            "Unknown role ",
            minimumRequiredRole,
            ". " +
            "Role must be one of [UserRole.Owner, UserRole.Admin, UserRole.Member] or undefined. " +
            "Requests will be rejected to be safe.",
        )
    }

    const orgIdToOrgMemberInfo = user.orgIdToOrgMemberInfo
    if (!orgIdToOrgMemberInfo || !orgIdToOrgMemberInfo.hasOwnProperty(requiredOrgId)) {
        throw new ForbiddenException(`User is not a member of org ${requiredOrgId}`)
    }

    // If minimumRequiredRole is specified, make sure the user is at least that role
    let orgMemberInfo = orgIdToOrgMemberInfo[requiredOrgId]
    if (!validRole) {
        throw new UnexpectedException(
            `Configuration error. Minimum required role (${minimumRequiredRole}) is invalid.`,
        )

    } else if (minimumRequiredRole !== undefined && orgMemberInfo.userRole < minimumRequiredRole) {
        throw new ForbiddenException(
            `User's role ${orgMemberInfo.userRole} doesn't meet minimum required role`,
        )
    }

    return orgMemberInfo
}

function extractBearerToken(authHeader?: string): string {
    if (!authHeader) {
        throw new UnauthorizedException("No authorization header found.")
    }

    const authHeaderParts = authHeader.split(" ")
    if (authHeaderParts.length !== 2 || authHeaderParts[0].toLowerCase() !== "bearer") {
        throw new UnauthorizedException("Invalid authorization header. Expected: Bearer {accessToken}")
    }

    return authHeaderParts[1]
}

function verifyToken(bearerToken: string, tokenVerificationMetadata: TokenVerificationMetadata): User {
    const options: VerifyOptions = {
        algorithms: ["RS256"],
        issuer: tokenVerificationMetadata.issuer,
    }
    try {
        const decoded = jwt.verify(bearerToken, tokenVerificationMetadata.verifierKey, options)
        return toUser(<InternalUser>decoded)
    } catch (e: unknown) {
        if (e instanceof Error) {
            throw new UnauthorizedException(e.message)
        } else {
            throw new UnauthorizedException("Unable to decode jwt")
        }
    }
}

async function getTokenVerificationMetadata(
    tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>,
) {
    const tokenVerificationMetadata = await tokenVerificationMetadataPromise
    // If we were unable to fetch the token verification metadata, reject all requests
    if (!tokenVerificationMetadata) {
        const errorMessage = "Auth library not initialized, rejecting request. This is likely a bad API key"
        console.error(errorMessage)
        throw new UnexpectedException(errorMessage)
    }

    return tokenVerificationMetadata
}

function isValidRole(role: UserRole | undefined) {
    return role === undefined || role === UserRole.Owner || role === UserRole.Admin || role === UserRole.Member
}