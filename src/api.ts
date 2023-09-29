import { validateApiKey } from "./api/endUserApiKeys"
import { ApiKeyValidateException, MigrateUserException } from "./exceptions"
import { httpRequest } from "./http"
import { OrgApiKeyValidation, OrgMemberInfo, PersonalApiKeyValidation, User } from "./user"

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

const idRegex = /^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$/i
const hexRegex = /^[0-9a-fA-F]{32}$/i

export function isValidId(id: string): boolean {
    return idRegex.test(id)
}

export function isValidHex(id: string): boolean {
    return hexRegex.test(id)
}

export function removeBearerIfExists(token: string): string {
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
