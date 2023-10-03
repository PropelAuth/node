import { MagicLinkCreationException } from "../exceptions"
import { httpRequest } from "../http"

const ENDPOINT_PATH = "/api/backend/v1/magic_link"

export type CreateMagicLinkRequest = {
    email: string
    redirectToUrl?: string
    expiresInHours?: string
    createNewUserIfOneDoesntExist?: boolean
}

export type MagicLink = {
    url: string
}

// POST
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
    return httpRequest(authUrl, integrationApiKey, ENDPOINT_PATH, "POST", JSON.stringify(request)).then(
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
