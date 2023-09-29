import { MigrateUserException } from "../exceptions"
import { httpRequest } from "../http"
import { User } from "../user"
import { parseSnakeCaseToCamelCase } from "../utils"

const ENDPOINT_PATH = "/api/backend/v1/migrate_user"

// POST
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
    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}`, "POST", JSON.stringify(request)).then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new MigrateUserException(httpResponse.response)
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when migrating user")
            }

            return parseSnakeCaseToCamelCase(httpResponse.response)
        }
    )
}
