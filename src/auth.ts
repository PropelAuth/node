import * as jose from "jose"
import { AccessToken, createAccessToken, CreateAccessTokenRequest } from "./api/accessToken"
import {
    ApiKeysCreateRequest,
    ApiKeysQueryRequest,
    ApiKeyUpdateRequest,
    createApiKey,
    deleteApiKey,
    fetchApiKey,
    fetchArchivedApiKeys,
    fetchCurrentApiKeys,
    updateApiKey,
    validateApiKey,
} from "./api/endUserApiKeys"
import { createMagicLink, CreateMagicLinkRequest, MagicLink } from "./api/magicLink"
import { migrateUserFromExternalSource, MigrateUserFromExternalSourceRequest } from "./api/migrateUser"
import {
    addUserToOrg,
    AddUserToOrgRequest,
    allowOrgToSetupSamlConnection,
    changeUserRoleInOrg,
    ChangeUserRoleInOrgRequest,
    createOrg,
    CreateOrgRequest,
    deleteOrg,
    disallowOrgToSetupSamlConnection,
    fetchOrg,
    fetchOrgByQuery,
    fetchCustomRoleMappings,
    OrgQuery,
    OrgQueryResponse,
    removeUserFromOrg,
    RemoveUserFromOrgRequest,
    updateOrg,
    UpdateOrgRequest,
} from "./api/org"
import {
    fetchTokenVerificationMetadata,
    getTokenVerificationMetadataPromise,
    TokenVerificationMetadata,
    TokenVerificationMetadataWithPublicKey,
} from "./api/tokenVerificationMetadata"
import {
    clearUserPassword,
    createUser,
    CreateUserRequest,
    deleteUser,
    disableUser,
    disableUser2fa,
    disableUserCanCreateOrgs,
    enableUser,
    enableUserCanCreateOrgs,
    fetchBatchUserMetadata,
    fetchUserMetadataByQuery,
    fetchUserMetadataByUserIdWithIdCheck,
    fetchUsersByQuery,
    fetchUserSignupQueryParams,
    fetchUsersInOrg,
    inviteUserToOrg,
    InviteUserToOrgRequest,
    updateUserEmail,
    UpdateUserEmailRequest,
    updateUserMetadata,
    UpdateUserMetadataRequest,
    updateUserPassword,
    UpdateUserPasswordRequest,
    UserSignupQueryParams,
    UsersInOrgQuery,
    UsersPagedResponse,
    UsersQuery,
} from "./api/user"
import { ForbiddenException, UnauthorizedException } from "./exceptions"
import {
    ApiKeyFull,
    ApiKeyNew,
    ApiKeyResultPage,
    ApiKeyValidation,
    CreatedOrg,
    CreatedUser,
    InternalUser,
    Organization,
    OrgApiKeyValidation,
    OrgIdToOrgMemberInfo,
    OrgMemberInfo,
    PersonalApiKeyValidation,
    toUser,
    User,
    UserAndOrgMemberInfo,
    UserMetadata,
} from "./user"
import { validateAuthUrl, validateOrgApiKey, validatePersonalApiKey } from "./validators"
import { CustomRoleMappings } from "./customRoleMappings"

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

    // A promise that resolves to the token verification metadata, whether it's fetched or manually provided
    const tokenVerificationMetadataPromise = fetchTokenVerificationMetadata(
        authUrl,
        integrationApiKey,
        opts.manualTokenVerificationMetadata
    ).catch((err) => {
        console.error("Error initializing auth library. ", err)
    })

    // A promise that resolves to the token verification metadata with the public key imported
    const tokenVerificationMetadataWithPublicKeyPromise = getTokenVerificationMetadataPromise(
        tokenVerificationMetadataPromise
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

    function fetchUserMetadataByUserId(userId: string, includeOrgs?: boolean): Promise<UserMetadata | null> {
        return fetchUserMetadataByUserIdWithIdCheck(authUrl, integrationApiKey, userId, includeOrgs)
    }

    function fetchUserMetadataByEmail(email: string, includeOrgs?: boolean): Promise<UserMetadata | null> {
        return fetchUserMetadataByQuery(authUrl, integrationApiKey, "email", {
            email: email,
            include_orgs: includeOrgs || false,
        })
    }

    function fetchUserMetadataByUsername(username: string, includeOrgs?: boolean): Promise<UserMetadata | null> {
        return fetchUserMetadataByQuery(authUrl, integrationApiKey, "username", {
            username: username,
            include_orgs: includeOrgs || false,
        })
    }

    function fetchUserSignupQueryParamsWrapper(userId: string): Promise<UserSignupQueryParams | null> {
        return fetchUserSignupQueryParams(authUrl, integrationApiKey, userId)
    }

    function fetchBatchUserMetadataByUserIds(
        userIds: string[],
        includeOrgs?: boolean
    ): Promise<{ [userId: string]: UserMetadata }> {
        return fetchBatchUserMetadata(
            authUrl,
            integrationApiKey,
            "user_ids",
            userIds,
            (x) => x.userId,
            includeOrgs || false
        )
    }

    function fetchBatchUserMetadataByEmails(
        emails: string[],
        includeOrgs?: boolean
    ): Promise<{ [email: string]: UserMetadata }> {
        return fetchBatchUserMetadata(
            authUrl,
            integrationApiKey,
            "emails",
            emails,
            (x) => x.email,
            includeOrgs || false
        )
    }

    function fetchBatchUserMetadataByUsernames(
        usernames: string[],
        includeOrgs?: boolean
    ): Promise<{ [username: string]: UserMetadata }> {
        return fetchBatchUserMetadata(
            authUrl,
            integrationApiKey,
            "usernames",
            usernames,
            (x) => x.username || "",
            includeOrgs || false
        )
    }

    function fetchOrgWrapper(orgId: string): Promise<Organization | null> {
        return fetchOrg(authUrl, integrationApiKey, orgId)
    }

    function fetchOrgsByQueryWrapper(orgQuery: OrgQuery): Promise<OrgQueryResponse> {
        return fetchOrgByQuery(authUrl, integrationApiKey, orgQuery)
    }

    function fetchCustomRoleMappingsWrapper(): Promise<CustomRoleMappings> {
        return fetchCustomRoleMappings(authUrl, integrationApiKey)
    }

    function fetchUsersByQueryWrapper(usersQuery: UsersQuery): Promise<UsersPagedResponse> {
        return fetchUsersByQuery(authUrl, integrationApiKey, usersQuery)
    }

    function fetchUsersInOrgWrapper(usersInOrgQuery: UsersInOrgQuery): Promise<UsersPagedResponse> {
        return fetchUsersInOrg(authUrl, integrationApiKey, usersInOrgQuery)
    }

    function createUserWrapper(createUserRequest: CreateUserRequest): Promise<CreatedUser> {
        return createUser(authUrl, integrationApiKey, createUserRequest)
    }

    function clearUserPasswordWrapper(userId: string): Promise<boolean> {
        return clearUserPassword(authUrl, integrationApiKey, userId)
    }

    function updateUserMetadataWrapper(
        userId: string,
        updateUserMetadataRequest: UpdateUserMetadataRequest
    ): Promise<boolean> {
        return updateUserMetadata(authUrl, integrationApiKey, userId, updateUserMetadataRequest)
    }

    function deleteUserWrapper(userId: string): Promise<boolean> {
        return deleteUser(authUrl, integrationApiKey, userId)
    }

    function disableUserWrapper(userId: string): Promise<boolean> {
        return disableUser(authUrl, integrationApiKey, userId)
    }

    function enableUserWrapper(userId: string): Promise<boolean> {
        return enableUser(authUrl, integrationApiKey, userId)
    }

    function disableUser2faWrapper(userId: string): Promise<boolean> {
        return disableUser2fa(authUrl, integrationApiKey, userId)
    }

    function updateUserEmailWrapper(userId: string, updateUserEmailRequest: UpdateUserEmailRequest): Promise<boolean> {
        return updateUserEmail(authUrl, integrationApiKey, userId, updateUserEmailRequest)
    }

    function updateUserPasswordWrapper(
        userId: string,
        updateUserPasswordRequest: UpdateUserPasswordRequest
    ): Promise<boolean> {
        return updateUserPassword(authUrl, integrationApiKey, userId, updateUserPasswordRequest)
    }

    function enableUserCanCreateOrgsWrapper(userId: string): Promise<boolean> {
        return enableUserCanCreateOrgs(authUrl, integrationApiKey, userId)
    }

    function disableUserCanCreateOrgsWrapper(userId: string): Promise<boolean> {
        return disableUserCanCreateOrgs(authUrl, integrationApiKey, userId)
    }

    function createMagicLinkWrapper(createMagicLinkRequest: CreateMagicLinkRequest): Promise<MagicLink> {
        return createMagicLink(authUrl, integrationApiKey, createMagicLinkRequest)
    }

    function createAccessTokenWrapper(createAccessTokenRequest: CreateAccessTokenRequest): Promise<AccessToken> {
        return createAccessToken(authUrl, integrationApiKey, createAccessTokenRequest)
    }

    function migrateUserFromExternalSourceWrapper(
        migrateUserFromExternalSourceRequest: MigrateUserFromExternalSourceRequest
    ): Promise<User> {
        return migrateUserFromExternalSource(authUrl, integrationApiKey, migrateUserFromExternalSourceRequest)
    }

    function createOrgWrapper(createOrgRequest: CreateOrgRequest): Promise<CreatedOrg> {
        return createOrg(authUrl, integrationApiKey, createOrgRequest)
    }

    function addUserToOrgWrapper(addUserToOrgRequest: AddUserToOrgRequest): Promise<boolean> {
        return addUserToOrg(authUrl, integrationApiKey, addUserToOrgRequest)
    }

    function changeUserRoleInOrgWrapper(changeUserRoleInOrgRequest: ChangeUserRoleInOrgRequest): Promise<boolean> {
        return changeUserRoleInOrg(authUrl, integrationApiKey, changeUserRoleInOrgRequest)
    }

    function removeUserFromOrgWrapper(removeUserFromOrgRequest: RemoveUserFromOrgRequest): Promise<boolean> {
        return removeUserFromOrg(authUrl, integrationApiKey, removeUserFromOrgRequest)
    }

    function updateOrgWrapper(updateOrgRequest: UpdateOrgRequest): Promise<boolean> {
        return updateOrg(authUrl, integrationApiKey, updateOrgRequest)
    }

    function deleteOrgWrapper(orgId: string): Promise<boolean> {
        return deleteOrg(authUrl, integrationApiKey, orgId)
    }

    function allowOrgToSetupSamlConnectionWrapper(orgId: string): Promise<boolean> {
        return allowOrgToSetupSamlConnection(authUrl, integrationApiKey, orgId)
    }

    function disallowOrgToSetupSamlConnectionWrapper(orgId: string): Promise<boolean> {
        return disallowOrgToSetupSamlConnection(authUrl, integrationApiKey, orgId)
    }

    function inviteUserToOrgWrapper(inviteUserToOrgRequest: InviteUserToOrgRequest): Promise<boolean> {
        return inviteUserToOrg(authUrl, integrationApiKey, inviteUserToOrgRequest)
    }

    // end user api key wrappers
    function fetchApiKeyWrapper(apiKeyId: string): Promise<ApiKeyFull> {
        return fetchApiKey(authUrl, integrationApiKey, apiKeyId)
    }

    function fetchCurrentApiKeysWrapper(apiKeyQuery: ApiKeysQueryRequest): Promise<ApiKeyResultPage> {
        return fetchCurrentApiKeys(authUrl, integrationApiKey, apiKeyQuery)
    }

    function fetchArchivedApiKeysWrapper(apiKeyQuery: ApiKeysQueryRequest): Promise<ApiKeyResultPage> {
        return fetchArchivedApiKeys(authUrl, integrationApiKey, apiKeyQuery)
    }

    function createApiKeyWrapper(apiKeyCreate: ApiKeysCreateRequest): Promise<ApiKeyNew> {
        return createApiKey(authUrl, integrationApiKey, apiKeyCreate)
    }

    function updateApiKeyWrapper(apiKeyId: string, ApiKeyUpdate: ApiKeyUpdateRequest): Promise<boolean> {
        return updateApiKey(authUrl, integrationApiKey, apiKeyId, ApiKeyUpdate)
    }

    function deleteApiKeyWrapper(apiKeyId: string): Promise<boolean> {
        return deleteApiKey(authUrl, integrationApiKey, apiKeyId)
    }

    function validatePersonalApiKeyWrapper(apiKeyToken: string): Promise<PersonalApiKeyValidation> {
        return validatePersonalApiKey(authUrl, integrationApiKey, apiKeyToken)
    }

    function validateOrgApiKeyWrapper(apiKeyToken: string): Promise<OrgApiKeyValidation> {
        return validateOrgApiKey(authUrl, integrationApiKey, apiKeyToken)
    }

    function validateApiKeyWrapper(apiKeyToken: string): Promise<ApiKeyValidation> {
        return validateApiKey(authUrl, integrationApiKey, apiKeyToken)
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
        fetchUserSignupQueryParams: fetchUserSignupQueryParamsWrapper,
        fetchBatchUserMetadataByUserIds,
        fetchBatchUserMetadataByEmails,
        fetchBatchUserMetadataByUsernames,
        fetchOrg: fetchOrgWrapper,
        fetchOrgByQuery: fetchOrgsByQueryWrapper,
        fetchCustomRoleMappings: fetchCustomRoleMappingsWrapper,
        fetchUsersByQuery: fetchUsersByQueryWrapper,
        fetchUsersInOrg: fetchUsersInOrgWrapper,
        // user management functions
        createUser: createUserWrapper,
        clearUserPassword: clearUserPasswordWrapper,
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
        inviteUserToOrg: inviteUserToOrgWrapper,
        // api keys functions
        fetchApiKey: fetchApiKeyWrapper,
        fetchCurrentApiKeys: fetchCurrentApiKeysWrapper,
        fetchArchivedApiKeys: fetchArchivedApiKeysWrapper,
        createApiKey: createApiKeyWrapper,
        updateApiKey: updateApiKeyWrapper,
        deleteApiKey: deleteApiKeyWrapper,
        validateApiKey: validateApiKeyWrapper,
        validatePersonalApiKey: validatePersonalApiKeyWrapper,
        validateOrgApiKey: validateOrgApiKeyWrapper,
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
    authorizationHeader: string | undefined
) {
    const tokenVerificationMetadataWithPublicKey = await tokenVerificationMetadataWithPublicKeyPromise

    const { publicKey, tokenVerificationMetadata } = tokenVerificationMetadataWithPublicKey

    const bearerToken = extractBearerToken(authorizationHeader)
    return verifyToken(bearerToken, tokenVerificationMetadata, publicKey)
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
