import jwt, {VerifyOptions} from "jsonwebtoken"
import {
    addUserToOrg, AddUserToOrgRequest, allowOrgToSetupSamlConnection,
    createMagicLink, CreateMagicLinkRequest, createOrg, CreateOrgRequest,
    createUser,
    CreateUserRequest, deleteUser, disableUser, disallowOrgToSetupSamlConnection, enableUser,
    fetchBatchUserMetadata,
    fetchOrg,
    fetchOrgByQuery,
    fetchTokenVerificationMetadata,
    fetchUserMetadataByQuery,
    fetchUserMetadataByUserIdWithIdCheck,
    fetchUsersByQuery,
    fetchUsersInOrg, MagicLink, migrateUserFromExternalSource, MigrateUserFromExternalSourceRequest,
    OrgQuery,
    OrgQueryResponse,
    TokenVerificationMetadata, updateUserEmail, UpdateUserEmailRequest, updateUserMetadata, UpdateUserMetadataRequest,
    UsersInOrgQuery,
    UsersPagedResponse,
    UsersQuery,
} from "./api"
import {UnauthorizedException, UnexpectedException, ForbiddenException} from "./exceptions"
import {
    InternalUser,
    Org,
    OrgIdToOrgMemberInfo,
    OrgMemberInfo,
    toUser,
    User,
    UserAndOrgMemberInfo,
    UserMetadata,
} from "./user"
import {validateAuthUrl} from "./validators"

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

    const validateAccessTokenAndGetUser = wrapValidateAccessTokenAndGetUser(tokenVerificationMetadataPromise)
    const validateAccessTokenAndGetUserWithOrgWithMinimumRole = wrapValidateAccessTokenAndGetUserWithOrgWithMinimumRole(tokenVerificationMetadataPromise)
    const validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole = wrapValidateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(tokenVerificationMetadataPromise)
    const validateAccessTokenAndGetUserWithOrgWithExactRole = wrapValidateAccessTokenAndGetUserWithOrgWithExactRole(tokenVerificationMetadataPromise)
    const validateAccessTokenAndGetUserWithOrgInfoWithExactRole = wrapValidateAccessTokenAndGetUserWithOrgInfoWithExactRole(tokenVerificationMetadataPromise)
    const validateAccessTokenAndGetUserWithOrgWithPermission = wrapValidateAccessTokenAndGetUserWithOrgWithPermission(tokenVerificationMetadataPromise)
    const validateAccessTokenAndGetUserWithOrgInfoWithPermission = wrapValidateAccessTokenAndGetUserWithOrgInfoWithPermission(tokenVerificationMetadataPromise)
    const validateAccessTokenAndGetUserWithOrgWithAllPermissions = wrapValidateAccessTokenAndGetUserWithOrgWithAllPermissions(tokenVerificationMetadataPromise)
    const validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions = wrapValidateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(tokenVerificationMetadataPromise)

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

    function deleteUserWrapper(userId: string): Promise<boolean> {
        return deleteUser(authUrl, apiKey, userId)
    }

    function disableUserWrapper(userId: string): Promise<boolean> {
        return disableUser(authUrl, apiKey, userId)
    }

    function enableUserWrapper(userId: string): Promise<boolean> {
        return enableUser(authUrl, apiKey, userId)
    }

    function updateUserEmailWrapper(userId: string, updateUserEmailRequest: UpdateUserEmailRequest): Promise<boolean> {
        return updateUserEmail(authUrl, apiKey, userId, updateUserEmailRequest)
    }

    function createMagicLinkWrapper(createMagicLinkRequest: CreateMagicLinkRequest): Promise<MagicLink> {
        return createMagicLink(authUrl, apiKey, createMagicLinkRequest)
    }

    function migrateUserFromExternalSourceWrapper(migrateUserFromExternalSourceRequest: MigrateUserFromExternalSourceRequest): Promise<User> {
        return migrateUserFromExternalSource(authUrl, apiKey, migrateUserFromExternalSourceRequest)
    }

    function createOrgWrapper(createOrgRequest: CreateOrgRequest): Promise<Org> {
        return createOrg(authUrl, apiKey, createOrgRequest)
    }

    function addUserToOrgWrapper(addUserToOrgRequest: AddUserToOrgRequest): Promise<boolean> {
        return addUserToOrg(authUrl, apiKey, addUserToOrgRequest)
    }

    function allowOrgToSetupSamlConnectionWrapper(orgId: string): Promise<boolean> {
        return allowOrgToSetupSamlConnection(authUrl, apiKey, orgId)
    }

    function disallowOrgToSetupSamlConnectionWrapper(orgId: string): Promise<boolean> {
        return disallowOrgToSetupSamlConnection(authUrl, apiKey, orgId)
    }

    return {
        // validate and fetching functions
        validateAccessTokenAndGetUser,
        validateAccessTokenAndGetUserWithOrgWithMinimumRole,
        validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole,
        validateAccessTokenAndGetUserWithOrgWithExactRole,
        validateAccessTokenAndGetUserWithOrgInfoWithExactRole,
        validateAccessTokenAndGetUserWithOrgWithPermission,
        validateAccessTokenAndGetUserWithOrgInfoWithPermission,
        validateAccessTokenAndGetUserWithOrgWithAllPermissions,
        validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions,
        // fetching functions
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
        // user management functions
        createUser: createUserWrapper,
        updateUserMetadata: updateUserMetadataWrapper,
        updateUserEmail: updateUserEmailWrapper,
        createMagicLink: createMagicLinkWrapper,
        migrateUserFromExternalSource: migrateUserFromExternalSourceWrapper,
        deleteUser: deleteUserWrapper,
        disableUser: disableUserWrapper,
        enableUser: enableUserWrapper,
        // org management functions
        createOrg: createOrgWrapper,
        addUserToOrg: addUserToOrgWrapper,
        allowOrgToSetupSamlConnection: allowOrgToSetupSamlConnectionWrapper,
        disallowOrgToSetupSamlConnection: disallowOrgToSetupSamlConnectionWrapper,
    }
}

// wrapper function with no validation
function wrapValidateAccessTokenAndGetUser(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    return async function validateAccessTokenAndGetUser(authorizationHeader?: string): Promise<User> {
        return extractAndVerifyBearerToken(tokenVerificationMetadataPromise, authorizationHeader)
    }
}

// The following eight functions are wrappers around our four validations: isRole, atLeastRole, hasRequirement, hasAllRequirements
// There are two wrappers for each validation, depending on if you want to validate the orgId or orgInfo

function wrapValidateAccessTokenAndGetUserWithOrgWithMinimumRole(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    const validateAccessTokenAndGetUserWithOrgInfo = wrapValidateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(tokenVerificationMetadataPromise)
    return async function validateAccessTokenAndGetUserWithOrgId(authorizationHeader: string | undefined,
                                                                 requiredOrgId: string,
                                                                 requiredRole?: string): Promise<UserAndOrgMemberInfo> {
        return validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader, {orgId: requiredOrgId}, requiredRole);
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader: string | undefined,
                                                                   requiredOrgInfo: RequiredOrgInfo,
                                                                   minimumRole?: string): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(tokenVerificationMetadataPromise, authorizationHeader);
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithMinimumRole(user, requiredOrgInfo, minimumRole);
        return {user, orgMemberInfo}
    }
}


function wrapValidateAccessTokenAndGetUserWithOrgWithExactRole(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    const validateAccessTokenAndGetUserWithOrgInfo = wrapValidateAccessTokenAndGetUserWithOrgInfoWithExactRole(tokenVerificationMetadataPromise)
    return async function validateAccessTokenAndGetUserWithOrgId(authorizationHeader: string | undefined,
                                                                 requiredOrgId: string,
                                                                 exactRole?: string): Promise<UserAndOrgMemberInfo> {
        return validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader, {orgId: requiredOrgId}, exactRole);
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithExactRole(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader: string | undefined,
                                                                   requiredOrgInfo: RequiredOrgInfo,
                                                                   exactRole?: string): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(tokenVerificationMetadataPromise, authorizationHeader);
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithExactRole(user, requiredOrgInfo, exactRole);
        return {user, orgMemberInfo}
    }
}


function wrapValidateAccessTokenAndGetUserWithOrgWithPermission(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    const validateAccessTokenAndGetUserWithOrgInfo = wrapValidateAccessTokenAndGetUserWithOrgInfoWithPermission(tokenVerificationMetadataPromise)
    return async function validateAccessTokenAndGetUserWithOrgId(authorizationHeader: string | undefined,
                                                                 requiredOrgId: string,
                                                                 permission?: string): Promise<UserAndOrgMemberInfo> {
        return validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader, {orgId: requiredOrgId}, permission);
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithPermission(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader: string | undefined,
                                                                   requiredOrgInfo: RequiredOrgInfo,
                                                                   permission?: string): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(tokenVerificationMetadataPromise, authorizationHeader);
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithPermission(user, requiredOrgInfo, permission);
        return {user, orgMemberInfo}
    }
}


function wrapValidateAccessTokenAndGetUserWithOrgWithAllPermissions(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    const validateAccessTokenAndGetUserWithOrgInfo = wrapValidateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(tokenVerificationMetadataPromise)
    return async function validateAccessTokenAndGetUserWithOrgId(authorizationHeader: string | undefined,
                                                                 requiredOrgId: string,
                                                                 permissions?: string[]): Promise<UserAndOrgMemberInfo> {
        return validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader, {orgId: requiredOrgId}, permissions);
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader: string | undefined,
                                                                   requiredOrgInfo: RequiredOrgInfo,
                                                                   permissions?: string[]): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(tokenVerificationMetadataPromise, authorizationHeader);
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithAllPermissions(user, requiredOrgInfo, permissions);
        return {user, orgMemberInfo}
    }
}


export type RequiredOrgInfo = {
    orgId?: string
    orgName?: string
}

// Validator functions

function validateOrgAccessAndGetOrgMemberInfoWithMinimumRole(user: User, requiredOrgInfo: RequiredOrgInfo, minimumRole?: string): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    if (minimumRole !== undefined && !orgMemberInfo.isAtLeastRole(minimumRole)) {
        throw new ForbiddenException(
            `User's roles (${orgMemberInfo.inheritedRolesPlusCurrentRole}) don't contain the minimum role (${minimumRole})`,
        )
    }

    return orgMemberInfo
}

function validateOrgAccessAndGetOrgMemberInfoWithExactRole(user: User, requiredOrgInfo: RequiredOrgInfo, exactRole?: string): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    if (exactRole !== undefined && !orgMemberInfo.isRole(exactRole)) {
        throw new ForbiddenException(
            `User's assigned role (${orgMemberInfo.assignedRole}) isn't the required role (${exactRole})`,
        )
    }

    return orgMemberInfo
}

function validateOrgAccessAndGetOrgMemberInfoWithPermission(user: User, requiredOrgInfo: RequiredOrgInfo, permission?: string): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    if (permission !== undefined && !orgMemberInfo.hasPermission(permission)) {
        throw new ForbiddenException(
            `User's permissions (${orgMemberInfo.permissions}) don't contain the required permission (${permission})`,
        )
    }

    return orgMemberInfo
}

function validateOrgAccessAndGetOrgMemberInfoWithAllPermissions(user: User, requiredOrgInfo: RequiredOrgInfo, permissions?: string[]): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    if (permissions !== undefined && !orgMemberInfo.hasAllPermissions(permissions)) {
        throw new ForbiddenException(
            `User's permissions (${orgMemberInfo.permissions}) don't contain all the required permissions (${permissions})`,
        )
    }

    return orgMemberInfo
}

// Miscellaneous functions

function getUserInfoInOrg(requiredOrgInfo: RequiredOrgInfo, orgIdToOrgMemberInfo?: OrgIdToOrgMemberInfo): OrgMemberInfo | undefined {
    if (!orgIdToOrgMemberInfo) {
        return undefined

    } else if (requiredOrgInfo.orgId) {
        // If we are looking for an orgId, we can do a direct lookup
        if (!orgIdToOrgMemberInfo.hasOwnProperty(requiredOrgInfo.orgId)) {
            return undefined;
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

async function extractAndVerifyBearerToken(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>, authorizationHeader: string | undefined) {
    const tokenVerificationMetadata = await getTokenVerificationMetadata(tokenVerificationMetadataPromise)
    const bearerToken = extractBearerToken(authorizationHeader)
    return verifyToken(bearerToken, tokenVerificationMetadata);
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
