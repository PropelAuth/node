import { AccessTokenCreationException, UserNotFoundException } from "../exceptions"
import { httpRequest } from "../http"
import { isValidId } from "../utils"

const ENDPOINT_PATH = "/api/backend/v1/access_token"

export type CreateAccessTokenRequest = {
    userId: string
    durationInMinutes: number
    activeOrgId?: string
    withActiveOrgSupport?: boolean
}

export type AccessToken = {
    access_token: string
}

// POST
export async function createAccessToken(
    authUrl: URL,
    integrationApiKey: string,
    createAccessTokenRequest: CreateAccessTokenRequest
): Promise<AccessToken> {
    if (!isValidId(createAccessTokenRequest.userId)) {
        throw new UserNotFoundException()
    }

    const request: Record<string, any> = {
        user_id: createAccessTokenRequest.userId,
        duration_in_minutes: createAccessTokenRequest.durationInMinutes,
        with_active_org_support: createAccessTokenRequest.withActiveOrgSupport ?? false,
    }
    if (createAccessTokenRequest.activeOrgId) {
        request["active_org_id"] = createAccessTokenRequest.activeOrgId
    }

    const httpResponse = await httpRequest(authUrl, integrationApiKey, ENDPOINT_PATH, "POST", JSON.stringify(request))
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
}
