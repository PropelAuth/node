import { validateApiKey } from "./api/endUserApiKeys"
import { ApiKeyValidateException } from "./exceptions"
import { OrgApiKeyValidation, PersonalApiKeyValidation } from "./user"

export function validateAuthUrl(authUrl: string): URL {
    try {
        return new URL(authUrl)
    } catch (e) {
        console.error("Invalid authUrl", e)
        throw new Error("Unable to initialize auth client")
    }
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
