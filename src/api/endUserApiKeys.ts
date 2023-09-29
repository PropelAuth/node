import {
    ApiKeyCreateException,
    ApiKeyDeleteException,
    ApiKeyFetchException,
    ApiKeyUpdateException,
    ApiKeyValidateException,
} from "../exceptions"
import { httpRequest } from "../http"
import { ApiKeyFull, ApiKeyNew, ApiKeyResultPage, ApiKeyValidation } from "../user"
import { formatQueryParameters, isValidHex, parseSnakeCaseToCamelCase, removeBearerIfExists } from "../utils"

const ENDPOINT_PATH = "/api/backend/v1/end_user_api_keys"

// GET
export function fetchApiKey(authUrl: URL, integrationApiKey: string, apiKeyId: string): Promise<ApiKeyFull> {
    if (!isValidHex(apiKeyId)) {
        throw new ApiKeyFetchException("Invalid api key")
    }

    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/${apiKeyId}`, "GET").then((httpResponse) => {
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

    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}?${queryString}`, "GET").then((httpResponse) => {
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

    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/archived?${queryString}`, "GET").then(
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

// POST
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

    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}`, "POST", JSON.stringify(request)).then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new ApiKeyCreateException(httpResponse.response)
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when creating the end user api key")
            }

            return parseSnakeCaseToCamelCase(httpResponse.response)
        }
    )
}

export function validateApiKey(
    authUrl: URL,
    integrationApiKey: string,
    apiKeyToken: string
): Promise<ApiKeyValidation> {
    const request = {
        api_key_token: removeBearerIfExists(apiKeyToken),
    }

    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/validate`, "POST", JSON.stringify(request)).then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new ApiKeyValidateException(httpResponse.response)
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when updating the end user api key")
            }

            return parseSnakeCaseToCamelCase(httpResponse.response)
        }
    )
}

// PUT/PATCH
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
        `${ENDPOINT_PATH}/${apiKeyId}`,
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

// DELETE
export function deleteApiKey(authUrl: URL, integrationApiKey: string, apiKeyId: string): Promise<boolean> {
    if (!isValidHex(apiKeyId)) {
        throw new ApiKeyDeleteException("Invalid api key")
    }

    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/${apiKeyId}`, "DELETE").then((httpResponse) => {
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
    })
}
