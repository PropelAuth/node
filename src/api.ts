import {
    AccessTokenCreationException,
    ApiKeyCreateException,
    ApiKeyDeleteException,
    ApiKeyFetchException,
    ApiKeyUpdateException,
    ApiKeyValidateException,
    MagicLinkCreationException,
    MigrateUserException,
    UserNotFoundException,
} from "./exceptions"
import { httpRequest } from "./http"
import {
    ApiKeyFull,
    ApiKeyNew,
    ApiKeyResultPage,
    ApiKeyValidation,
    OrgApiKeyValidation,
    OrgMemberInfo,
    PersonalApiKeyValidation,
    User,
} from "./user"

export type TokenVerificationMetadata = {
    verifierKey: string
    issuer: string
}

export function fetchTokenVerificationMetadata(
    authUrl: URL,
    integrationApiKey: string,
    manualTokenVerificationMetadata?: TokenVerificationMetadata
): Promise<TokenVerificationMetadata> {
    if (manualTokenVerificationMetadata) {
        return Promise.resolve(manualTokenVerificationMetadata)
    }

    return httpRequest(authUrl, integrationApiKey, "/api/v1/token_verification_metadata", "GET").then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when fetching token verification metadata")
            }

            const jsonParse = JSON.parse(httpResponse.response)
            return {
                verifierKey: jsonParse.verifier_key_pem,
                issuer: formatIssuer(authUrl),
            }
        }
    )
}

export type CreateMagicLinkRequest = {
    email: string
    redirectToUrl?: string
    expiresInHours?: string
    createNewUserIfOneDoesntExist?: boolean
}

export type MagicLink = {
    url: string
}

export function createMagicLink(
    authUrl: URL,
    integrationApiKey: string,
    createMagicLinkRequest: CreateMagicLinkRequest
): Promise<MagicLink> {
    const request = {
        email: createMagicLinkRequest.email,
        redirect_to_url: createMagicLinkRequest.redirectToUrl,
        expires_in_hours: createMagicLinkRequest.expiresInHours,
        create_new_user_if_one_doesnt_exist: createMagicLinkRequest.createNewUserIfOneDoesntExist,
    }
    return httpRequest(authUrl, integrationApiKey, `/api/backend/v1/magic_link`, "POST", JSON.stringify(request)).then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new MagicLinkCreationException(httpResponse.response)
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when creating magic link")
            }

            return JSON.parse(httpResponse.response)
        }
    )
}

export type CreateAccessTokenRequest = {
    userId: string
    durationInMinutes: number
}

export type AccessToken = {
    access_token: string
}

export function createAccessToken(
    authUrl: URL,
    integrationApiKey: string,
    createAccessTokenRequest: CreateAccessTokenRequest
): Promise<AccessToken> {
    if (!isValidId(createAccessTokenRequest.userId)) {
        throw new UserNotFoundException()
    }

    const request = {
        user_id: createAccessTokenRequest.userId,
        duration_in_minutes: createAccessTokenRequest.durationInMinutes,
    }
    return httpRequest(
        authUrl,
        integrationApiKey,
        `/api/backend/v1/access_token`,
        "POST",
        JSON.stringify(request)
    ).then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 400) {
            throw new AccessTokenCreationException(httpResponse.response)
        } else if (httpResponse.statusCode === 403) {
            throw new UserNotFoundException()
        } else if (httpResponse.statusCode === 404) {
            throw new Error("Access token creation is not enabled")
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when creating access token")
        }

        return JSON.parse(httpResponse.response)
    })
}

export type MigrateUserFromExternalSourceRequest = {
    email: string
    emailConfirmed: boolean

    existingUserId?: string
    existingPasswordHash?: string
    existingMfaBase32EncodedSecret?: string
    askUserToUpdatePasswordOnLogin?: boolean

    enabled?: boolean

    firstName?: string
    lastName?: string
    username?: string
    properties?: { [key: string]: any }
}

export function migrateUserFromExternalSource(
    authUrl: URL,
    integrationApiKey: string,
    migrateUserFromExternalSourceRequest: MigrateUserFromExternalSourceRequest
): Promise<User> {
    const request = {
        email: migrateUserFromExternalSourceRequest.email,
        email_confirmed: migrateUserFromExternalSourceRequest.emailConfirmed,

        existing_user_id: migrateUserFromExternalSourceRequest.existingUserId,
        existing_password_hash: migrateUserFromExternalSourceRequest.existingPasswordHash,
        existing_mfa_base32_encoded_secret: migrateUserFromExternalSourceRequest.existingMfaBase32EncodedSecret,
        update_password_required: migrateUserFromExternalSourceRequest.askUserToUpdatePasswordOnLogin,

        enabled: migrateUserFromExternalSourceRequest.enabled,

        first_name: migrateUserFromExternalSourceRequest.firstName,
        last_name: migrateUserFromExternalSourceRequest.lastName,
        username: migrateUserFromExternalSourceRequest.username,
        properties: migrateUserFromExternalSourceRequest.properties,
    }
    return httpRequest(
        authUrl,
        integrationApiKey,
        `/api/backend/v1/migrate_user/`,
        "POST",
        JSON.stringify(request)
    ).then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 400) {
            throw new MigrateUserException(httpResponse.response)
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when migrating user")
        }

        return parseSnakeCaseToCamelCase(httpResponse.response)
    })
}

// functions for managing end user api keys
export function fetchApiKey(authUrl: URL, integrationApiKey: string, apiKeyId: string): Promise<ApiKeyFull> {
    if (!isValidHex(apiKeyId)) {
        throw new ApiKeyFetchException("Invalid api key")
    }

    return httpRequest(authUrl, integrationApiKey, `/api/backend/v1/end_user_api_keys/${apiKeyId}`, "GET").then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new ApiKeyFetchException(httpResponse.response)
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when creating the end user api key")
            }

            return parseSnakeCaseToCamelCase(httpResponse.response)
        }
    )
}

export type ApiKeysQueryRequest = {
    orgId?: string
    userId?: string
    userEmail?: string
    pageSize?: number
    pageNumber?: number
}

export function fetchCurrentApiKeys(
    authUrl: URL,
    integrationApiKey: string,
    apiKeyQuery: ApiKeysQueryRequest
): Promise<ApiKeyResultPage> {
    const request = {
        org_id: apiKeyQuery.orgId,
        user_id: apiKeyQuery.userId,
        user_email: apiKeyQuery.userEmail,
        page_size: apiKeyQuery.pageSize,
        page_number: apiKeyQuery.pageNumber,
    }
    const queryString = formatQueryParameters(request)

    return httpRequest(authUrl, integrationApiKey, `/api/backend/v1/end_user_api_keys?${queryString}`, "GET").then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new ApiKeyFetchException(httpResponse.response)
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when creating the end user api key")
            }

            return parseSnakeCaseToCamelCase(httpResponse.response)
        }
    )
}

export function fetchArchivedApiKeys(
    authUrl: URL,
    integrationApiKey: string,
    apiKeyQuery: ApiKeysQueryRequest
): Promise<ApiKeyResultPage> {
    const request = {
        org_id: apiKeyQuery.orgId,
        user_id: apiKeyQuery.userId,
        user_email: apiKeyQuery.userEmail,
        page_size: apiKeyQuery.pageSize,
        page_number: apiKeyQuery.pageNumber,
    }
    const queryString = formatQueryParameters(request)

    return httpRequest(
        authUrl,
        integrationApiKey,
        `/api/backend/v1/end_user_api_keys/archived?${queryString}`,
        "GET"
    ).then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 400) {
            throw new ApiKeyFetchException(httpResponse.response)
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when creating the end user api key")
        }

        return parseSnakeCaseToCamelCase(httpResponse.response)
    })
}

export type ApiKeysCreateRequest = {
    orgId?: string
    userId?: string
    expiresAtSeconds?: number
    metadata?: object
}

export function createApiKey(
    authUrl: URL,
    integrationApiKey: string,
    apiKeyCreate: ApiKeysCreateRequest
): Promise<ApiKeyNew> {
    const request = {
        org_id: apiKeyCreate.orgId,
        user_id: apiKeyCreate.userId,
        expires_at_seconds: apiKeyCreate.expiresAtSeconds,
        metadata: apiKeyCreate.metadata,
    }

    return httpRequest(
        authUrl,
        integrationApiKey,
        `/api/backend/v1/end_user_api_keys`,
        "POST",
        JSON.stringify(request)
    ).then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 400) {
            throw new ApiKeyCreateException(httpResponse.response)
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when creating the end user api key")
        }

        return parseSnakeCaseToCamelCase(httpResponse.response)
    })
}

export type ApiKeyUpdateRequest = {
    expiresAtSeconds?: number
    metadata?: string
}

export function updateApiKey(
    authUrl: URL,
    integrationApiKey: string,
    apiKeyId: string,
    apiKeyUpdate: ApiKeyUpdateRequest
): Promise<boolean> {
    if (!isValidHex(apiKeyId)) {
        throw new ApiKeyUpdateException("Invalid api key")
    }

    const request = {
        expires_at_seconds: apiKeyUpdate.expiresAtSeconds,
        metadata: apiKeyUpdate.metadata,
    }

    return httpRequest(
        authUrl,
        integrationApiKey,
        `/api/backend/v1/end_user_api_keys/${apiKeyId}`,
        "PATCH",
        JSON.stringify(request)
    ).then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 400) {
            throw new ApiKeyUpdateException(httpResponse.response)
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when updating the end user api key")
        }

        return true
    })
}

export function deleteApiKey(authUrl: URL, integrationApiKey: string, apiKeyId: string): Promise<boolean> {
    if (!isValidHex(apiKeyId)) {
        throw new ApiKeyDeleteException("Invalid api key")
    }

    return httpRequest(authUrl, integrationApiKey, `/api/backend/v1/end_user_api_keys/${apiKeyId}`, "DELETE").then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new ApiKeyDeleteException(httpResponse.response)
            } else if (httpResponse.statusCode === 404) {
                return false
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when deleting the end user api key")
            }

            return true
        }
    )
}

export async function validatePersonalApiKey(
    authUrl: URL,
    integrationApiKey: string,
    apiKeyToken: string
): Promise<PersonalApiKeyValidation> {
    const apiKeyValidation = await validateApiKey(authUrl, integrationApiKey, apiKeyToken)
    if (!apiKeyValidation.user || apiKeyValidation.org) {
        throw new ApiKeyValidateException(JSON.stringify({ api_key_token: ["Not a personal API Key"] }))
    }
    return {
        user: apiKeyValidation.user,
        metadata: apiKeyValidation.metadata,
    }
}

export async function validateOrgApiKey(
    authUrl: URL,
    integrationApiKey: string,
    apiKeyToken: string
): Promise<OrgApiKeyValidation> {
    const apiKeyValidation = await validateApiKey(authUrl, integrationApiKey, apiKeyToken)
    if (!apiKeyValidation.org) {
        throw new ApiKeyValidateException(JSON.stringify({ api_key_token: ["Not an org API Key"] }))
    }
    return {
        org: apiKeyValidation.org,
        metadata: apiKeyValidation.metadata,
        user: apiKeyValidation.user,
        userInOrg: apiKeyValidation.userInOrg,
    }
}

export function validateApiKey(
    authUrl: URL,
    integrationApiKey: string,
    apiKeyToken: string
): Promise<ApiKeyValidation> {
    const request = {
        api_key_token: removeBearerIfExists(apiKeyToken),
    }

    return httpRequest(
        authUrl,
        integrationApiKey,
        `/api/backend/v1/end_user_api_keys/validate`,
        "POST",
        JSON.stringify(request)
    ).then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 400) {
            throw new ApiKeyValidateException(httpResponse.response)
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when updating the end user api key")
        }

        return parseSnakeCaseToCamelCase(httpResponse.response)
    })
}

const idRegex = /^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$/i
const hexRegex = /^[0-9a-fA-F]{32}$/i

export function isValidId(id: string): boolean {
    return idRegex.test(id)
}

function isValidHex(id: string): boolean {
    return hexRegex.test(id)
}

function removeBearerIfExists(token: string): string {
    if (!token) {
        return token
    } else if (token.toLowerCase().startsWith("bearer ")) {
        return token.substring(7)
    } else {
        return token
    }
}

export function formatQueryParameters(obj: { [key: string]: any }): string {
    const params = new URLSearchParams()
    for (const [key, value] of Object.entries(obj)) {
        if (value !== undefined) {
            params.set(key, value)
        }
    }
    return params.toString()
}

function formatIssuer(authUrl: URL): string {
    return authUrl.origin
}

export function parseSnakeCaseToCamelCase(response: string) {
    let parsedObject = JSON.parse(response)
    return processKeys(parsedObject)
}

const keysForValueNotToModify = ["metadata", "org_metadata"]

function isOrgMemberInfo(value: any) {
    return (
        value &&
        typeof value === "object" &&
        value.hasOwnProperty("orgId") &&
        value.hasOwnProperty("orgName") &&
        value.hasOwnProperty("urlSafeOrgName") &&
        value.hasOwnProperty("orgMetadata") &&
        value.hasOwnProperty("userAssignedRole") &&
        value.hasOwnProperty("userRoles") &&
        value.hasOwnProperty("userPermissions")
    )
}

function processKeys(obj: any): any {
    let newObj: any = Array.isArray(obj) ? [] : {}
    for (let key in obj) {
        if (!obj.hasOwnProperty(key)) {
            continue
        }

        let value = obj[key]
        const doNotModifyValue = keysForValueNotToModify.includes(key)
        if (!doNotModifyValue && value && typeof value === "object") {
            value = processKeys(value)
        }

        if (isOrgMemberInfo(value)) {
            value = new OrgMemberInfo(
                value["orgId"],
                value["orgName"],
                value["orgMetadata"],
                value["urlSafeOrgName"],
                value["userAssignedRole"],
                value["userRoles"],
                value["userPermissions"]
            )
        }

        let newKey
        if (key === "user_role") {
            newKey = "userAssignedRole"
        } else if (key === "inherited_user_roles_plus_current_role") {
            newKey = "userRoles"
        } else {
            newKey = camelCase(key)
        }

        newObj[newKey] = value
    }
    return newObj
}

function camelCase(key: string): string {
    return key.replace(/_([a-z])/g, function (g) {
        return g[1].toUpperCase()
    })
}
