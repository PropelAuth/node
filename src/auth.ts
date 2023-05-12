import jwt, {VerifyOptions} from "jsonwebtoken"
import {
    AccessToken,
    addUserToOrg,
    AddUserToOrgRequest,
    allowOrgToSetupSamlConnection,
    changeUserRoleInOrg,
    ChangeUserRoleInOrgRequest,
    createAccessToken,
    CreateAccessTokenRequest,
    createEndUserApiKey,
    createMagicLink,
    CreateMagicLinkRequest,
    createOrg,
    CreateOrgRequest,
    createUser,
    CreateUserRequest,
    deleteEndUserApiKey,
    deleteOrg,
    deleteUser,
    disableUser,
    disableUser2fa,
    disableUserCanCreateOrgs,
    disallowOrgToSetupSamlConnection,
    enableUser,
    enableUserCanCreateOrgs,
    EndUserApiKeysCreateRequest,
    EndUserApiKeysQueryRequest,
    EndUserApiKeyUpdateRequest,
    fetchArchivedEndUserApiKeys,
    fetchBatchUserMetadata,
    fetchCurrentEndUserApiKeys,
    fetchEndUserApiKey,
    fetchOrg,
    fetchOrgByQuery,
    fetchTokenVerificationMetadata,
    fetchUserMetadataByQuery,
    fetchUserMetadataByUserIdWithIdCheck,
    fetchUsersByQuery,
    fetchUsersInOrg,
    MagicLink,
    migrateUserFromExternalSource,
    MigrateUserFromExternalSourceRequest,
    OrgQuery,
    OrgQueryResponse,
    removeUserFromOrg,
    RemoveUserFromOrgRequest,
    TokenVerificationMetadata,
    updateEndUserApiKey,
    updateOrg,
    UpdateOrgRequest,
    updateUserEmail,
    UpdateUserEmailRequest,
    updateUserMetadata,
    UpdateUserMetadataRequest,
    updateUserPassword,
    UpdateUserPasswordRequest,
    UsersInOrgQuery,
    UsersPagedResponse,
    UsersQuery,
} from "./api"
import {ForbiddenException, UnauthorizedException, UnexpectedException} from "./exceptions"
import {
    EndUserApiKeyFull,
    EndUserApiKeyNew,
    EndUserApiKeyResultPage,
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
    const validateAccessTokenAndGetUserWithOrgInfo = wrapValidateAccessTokenAndGetUserWithOrgInfo(tokenVerificationMetadataPromise)
    const validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole = wrapValidateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(tokenVerificationMetadataPromise)
    const validateAccessTokenAndGetUserWithOrgInfoWithExactRole = wrapValidateAccessTokenAndGetUserWithOrgInfoWithExactRole(tokenVerificationMetadataPromise)
    const validateAccessTokenAndGetUserWithOrgInfoWithPermission = wrapValidateAccessTokenAndGetUserWithOrgInfoWithPermission(tokenVerificationMetadataPromise)
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

    function disableUser2faWrapper(userId: string): Promise<boolean> {
        return disableUser2fa(authUrl, apiKey, userId)
    }

    function updateUserEmailWrapper(userId: string, updateUserEmailRequest: UpdateUserEmailRequest): Promise<boolean> {
        return updateUserEmail(authUrl, apiKey, userId, updateUserEmailRequest)
    }

    function updateUserPasswordWrapper(userId: string, updateUserPasswordRequest: UpdateUserPasswordRequest): Promise<boolean> {
        return updateUserPassword(authUrl, apiKey, userId, updateUserPasswordRequest)
    }

    function enableUserCanCreateOrgsWrapper(userId: string): Promise<boolean> {
        return enableUserCanCreateOrgs(authUrl, apiKey, userId)
    }

    function disableUserCanCreateOrgsWrapper(userId: string): Promise<boolean> {
        return disableUserCanCreateOrgs(authUrl, apiKey, userId)
    }

    function createMagicLinkWrapper(createMagicLinkRequest: CreateMagicLinkRequest): Promise<MagicLink> {
        return createMagicLink(authUrl, apiKey, createMagicLinkRequest)
    }

    function createAccessTokenWrapper(createAccessTokenRequest: CreateAccessTokenRequest): Promise<AccessToken> {
        return createAccessToken(authUrl, apiKey, createAccessTokenRequest)
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

    function changeUserRoleInOrgWrapper(changeUserRoleInOrgRequest: ChangeUserRoleInOrgRequest): Promise<boolean> {
        return changeUserRoleInOrg(authUrl, apiKey, changeUserRoleInOrgRequest)
    }

    function removeUserFromOrgWrapper(removeUserFromOrgRequest: RemoveUserFromOrgRequest): Promise<boolean> {
        return removeUserFromOrg(authUrl, apiKey, removeUserFromOrgRequest)
    }

    function updateOrgWrapper(updateOrgRequest: UpdateOrgRequest): Promise<boolean> {
        return updateOrg(authUrl, apiKey, updateOrgRequest)
    }

    function deleteOrgWrapper(orgId: string): Promise<boolean> {
        return deleteOrg(authUrl, apiKey, orgId)
    }

    function allowOrgToSetupSamlConnectionWrapper(orgId: string): Promise<boolean> {
        return allowOrgToSetupSamlConnection(authUrl, apiKey, orgId)
    }

    function disallowOrgToSetupSamlConnectionWrapper(orgId: string): Promise<boolean> {
        return disallowOrgToSetupSamlConnection(authUrl, apiKey, orgId)
    }

    // end user api key wrappers
    function fetchEndUserApiKeyWrapper(endUserApiKey: string): Promise<EndUserApiKeyFull> {
        return fetchEndUserApiKey(authUrl, apiKey, endUserApiKey)
    }

    function fetchCurrentEndUserApiKeysWrapper(endUserApiKeyQuery: EndUserApiKeysQueryRequest): Promise<EndUserApiKeyResultPage> {
        return fetchCurrentEndUserApiKeys(authUrl, apiKey, endUserApiKeyQuery)
    }

    function fetchArchivedEndUserApiKeysWrapper(endUserApiKeyQuery: EndUserApiKeysQueryRequest): Promise<EndUserApiKeyResultPage> {
        return fetchArchivedEndUserApiKeys(authUrl, apiKey, endUserApiKeyQuery)
    }

    function createEndUserApiKeyWrapper(endUserApiKeyCreate: EndUserApiKeysCreateRequest): Promise<EndUserApiKeyNew> {
        return createEndUserApiKey(authUrl, apiKey, endUserApiKeyCreate)
    }

    function updateEndUserApiKeyWrapper(endUserApiKey: string, endUserApiKeyUpdate: EndUserApiKeyUpdateRequest): Promise<boolean> {
        return updateEndUserApiKey(authUrl, apiKey, endUserApiKey, endUserApiKeyUpdate)
    }

    function deleteEndUserApiKeyWrapper(endUserApiKey: string): Promise<boolean> {
        return deleteEndUserApiKey(authUrl, apiKey, endUserApiKey)
    }

    return {
        // validate and fetching functions
        validateAccessTokenAndGetUser,
        validateAccessTokenAndGetUserWithOrgInfo,
        validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole,
        validateAccessTokenAndGetUserWithOrgInfoWithExactRole,
        validateAccessTokenAndGetUserWithOrgInfoWithPermission,
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
        updateUserPassword: updateUserPasswordWrapper,
        createMagicLink: createMagicLinkWrapper,
        createAccessToken: createAccessTokenWrapper,
        migrateUserFromExternalSource: migrateUserFromExternalSourceWrapper,
        deleteUser: deleteUserWrapper,
        disableUser: disableUserWrapper,
        enableUser: enableUserWrapper,
        disableUser2fa: disableUser2faWrapper,
        enableUserCanCreateOrgs: enableUserCanCreateOrgsWrapper,
        disableUserCanCreateOrgs: disableUserCanCreateOrgsWrapper,
        // org management functions
        createOrg: createOrgWrapper,
        addUserToOrg: addUserToOrgWrapper,
        changeUserRoleInOrg: changeUserRoleInOrgWrapper,
        removeUserFromOrg: removeUserFromOrgWrapper,
        updateOrg: updateOrgWrapper,
        deleteOrg: deleteOrgWrapper,
        allowOrgToSetupSamlConnection: allowOrgToSetupSamlConnectionWrapper,
        disallowOrgToSetupSamlConnection: disallowOrgToSetupSamlConnectionWrapper,
        // end user api keys functions
        fetchEndUserApiKey: fetchEndUserApiKeyWrapper,
        fetchCurrentEndUserApiKeys: fetchCurrentEndUserApiKeysWrapper,
        fetchArchivedEndUserApiKeys: fetchArchivedEndUserApiKeysWrapper,
        createEndUserApiKey: createEndUserApiKeyWrapper,
        updateEndUserApiKey: updateEndUserApiKeyWrapper,
        deleteEndUserApiKey: deleteEndUserApiKeyWrapper,
    }
}

// wrapper function with no validation
function wrapValidateAccessTokenAndGetUser(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    return async function validateAccessTokenAndGetUser(authorizationHeader?: string): Promise<User> {
        return extractAndVerifyBearerToken(tokenVerificationMetadataPromise, authorizationHeader)
    }
}

// The following four functions are wrappers around our four validations: isRole, atLeastRole, hasPermission, hasAllPermissions
// Each function returns an OrgMemberInfo object


function wrapValidateAccessTokenAndGetUserWithOrgInfo(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader: string | undefined,
                                                                   requiredOrgInfo: RequiredOrgInfo): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(tokenVerificationMetadataPromise, authorizationHeader);
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfo(user, requiredOrgInfo);
        return {user, orgMemberInfo}
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader: string | undefined,
                                                                   requiredOrgInfo: RequiredOrgInfo,
                                                                   minimumRole: string): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(tokenVerificationMetadataPromise, authorizationHeader);
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithMinimumRole(user, requiredOrgInfo, minimumRole);
        return {user, orgMemberInfo}
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithExactRole(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader: string | undefined,
                                                                   requiredOrgInfo: RequiredOrgInfo,
                                                                   exactRole: string): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(tokenVerificationMetadataPromise, authorizationHeader);
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithExactRole(user, requiredOrgInfo, exactRole);
        return {user, orgMemberInfo}
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithPermission(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader: string | undefined,
                                                                   requiredOrgInfo: RequiredOrgInfo,
                                                                   permission: string): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(tokenVerificationMetadataPromise, authorizationHeader);
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithPermission(user, requiredOrgInfo, permission);
        return {user, orgMemberInfo}
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader: string | undefined,
                                                                   requiredOrgInfo: RequiredOrgInfo,
                                                                   permissions: string[]): Promise<UserAndOrgMemberInfo> {
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

function validateOrgAccessAndGetOrgMemberInfo(user: User, requiredOrgInfo: RequiredOrgInfo): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    return orgMemberInfo
}

function validateOrgAccessAndGetOrgMemberInfoWithMinimumRole(user: User, requiredOrgInfo: RequiredOrgInfo, minimumRole: string): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    if (!orgMemberInfo.isAtLeastRole(minimumRole)) {
        throw new ForbiddenException(
            `User's roles (${orgMemberInfo.inheritedRolesPlusCurrentRole}) don't contain the minimum role (${minimumRole})`,
        )
    }

    return orgMemberInfo
}

function validateOrgAccessAndGetOrgMemberInfoWithExactRole(user: User, requiredOrgInfo: RequiredOrgInfo, exactRole: string): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    if (!orgMemberInfo.isRole(exactRole)) {
        throw new ForbiddenException(
            `User's assigned role (${orgMemberInfo.assignedRole}) isn't the required role (${exactRole})`,
        )
    }

    return orgMemberInfo
}

function validateOrgAccessAndGetOrgMemberInfoWithPermission(user: User, requiredOrgInfo: RequiredOrgInfo, permission: string): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    if (!orgMemberInfo.hasPermission(permission)) {
        throw new ForbiddenException(
            `User's permissions (${orgMemberInfo.permissions}) don't contain the required permission (${permission})`,
        )
    }

    return orgMemberInfo
}

function validateOrgAccessAndGetOrgMemberInfoWithAllPermissions(user: User, requiredOrgInfo: RequiredOrgInfo, permissions: string[]): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    if (!orgMemberInfo.hasAllPermissions(permissions)) {
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

export type HandleErrorOptions = {
    logError?: boolean,
    returnDetailedErrorToUser?: boolean
}

export type HandleErrorResponse = {
    status: number,
    message: string
}

export function handleError(e: unknown, opts?: HandleErrorOptions): HandleErrorResponse {
    if (opts && opts.logError) {
        console.error(e);
    }

    const detailedError = opts && opts.returnDetailedErrorToUser
    if (e instanceof UnauthorizedException) {
        return {
            status: 401, message: detailedError ? e.message : "Unauthorized"
        }
    } else if (e instanceof ForbiddenException) {
        return {
            status: 403, message: detailedError ? e.message : "Forbidden"
        }
    } else {
        return {
            status: 401, message: "Unauthorized"
        }
    }
}