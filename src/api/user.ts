import {
    BadRequestException,
    CreateUserException,
    UpdateUserEmailException,
    UpdateUserMetadataException,
    UpdateUserPasswordException,
} from "../exceptions"
import { httpRequest } from "../http"
import { User, UserMetadata } from "../user"
import { formatQueryParameters, isValidId, parseSnakeCaseToCamelCase } from "../utils"

const ENDPOINT_PATH = "/api/backend/v1/user"

export type UsersQuery = {
    pageSize?: number
    pageNumber?: number
    orderBy?: "CREATED_AT_ASC" | "CREATED_AT_DESC" | "LAST_ACTIVE_AT_ASC" | "LAST_ACTIVE_AT_DESC" | "EMAIL" | "USERNAME"
    emailOrUsername?: string
    includeOrgs?: boolean
}

export type UsersPagedResponse = {
    users: UserMetadata[]
    totalUsers: number
    currentPage: number
    pageSize: number
    hasMoreResults: boolean
}

export type UsersInOrgQuery = {
    orgId: string
    pageSize?: number
    pageNumber?: number
    includeOrgs?: boolean
}

// GET
export function fetchUserMetadataByQuery(
    authUrl: URL,
    integrationApiKey: string,
    pathParam: string,
    query: any
): Promise<UserMetadata | null> {
    const queryString = formatQueryParameters(query)
    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/${pathParam}?${queryString}`, "GET").then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 404) {
                return null
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when fetching user metadata")
            }

            return parseSnakeCaseToCamelCase(httpResponse.response)
        }
    )
}

export function fetchUserMetadataByUserIdWithIdCheck(
    authUrl: URL,
    integrationApiKey: string,
    userId: string,
    includeOrgs?: boolean
): Promise<UserMetadata | null> {
    if (isValidId(userId)) {
        return fetchUserMetadataByQuery(authUrl, integrationApiKey, userId, { include_orgs: includeOrgs || false })
    } else {
        return Promise.resolve(null)
    }
}

export function fetchUsersByQuery(
    authUrl: URL,
    integrationApiKey: string,
    query: UsersQuery
): Promise<UsersPagedResponse> {
    const queryParams = {
        page_size: query.pageSize,
        page_number: query.pageNumber,
        order_by: query.orderBy,
        email_or_username: query.emailOrUsername,
        include_orgs: query.includeOrgs,
    }
    const q = formatQueryParameters(queryParams)
    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/query?${q}`, "GET").then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 400) {
            throw new Error("Invalid query " + httpResponse.response)
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when fetching users by query")
        }

        return parseSnakeCaseToCamelCase(httpResponse.response)
    })
}

export function fetchUsersInOrg(
    authUrl: URL,
    integrationApiKey: string,
    query: UsersInOrgQuery
): Promise<UsersPagedResponse> {
    if (!isValidId(query.orgId)) {
        const emptyResponse: UsersPagedResponse = {
            users: [],
            totalUsers: 0,
            currentPage: query.pageNumber || 0,
            pageSize: query.pageSize || 10,
            hasMoreResults: false,
        }
        return Promise.resolve(emptyResponse)
    }

    const queryParams = {
        page_size: query.pageSize,
        page_number: query.pageNumber,
        include_orgs: query.includeOrgs,
    }
    const queryString = formatQueryParameters(queryParams)
    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/org/${query.orgId}?${queryString}`, "GET").then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new Error("Invalid query " + httpResponse.response)
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when fetching users in org")
            }

            return parseSnakeCaseToCamelCase(httpResponse.response)
        }
    )
}

// POST
export function fetchBatchUserMetadata(
    authUrl: URL,
    integrationApiKey: string,
    type: string,
    values: string[],
    keyFunction: (x: UserMetadata) => string,
    includeOrgs?: boolean
): Promise<{ [key: string]: UserMetadata }> {
    const queryString = includeOrgs ? formatQueryParameters({ include_orgs: includeOrgs }) : ""
    const jsonBody = { [type]: values }
    return httpRequest(
        authUrl,
        integrationApiKey,
        `${ENDPOINT_PATH}/${type}?${queryString}`,
        "POST",
        JSON.stringify(jsonBody)
    ).then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 400) {
            throw new Error("Bad request " + httpResponse.response)
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when fetching batch user metadata")
        }

        const userMetadatas = parseSnakeCaseToCamelCase(httpResponse.response)

        const returnValue: { [key: string]: UserMetadata } = {}
        for (let userMetadata of userMetadatas) {
            returnValue[keyFunction(userMetadata)] = userMetadata
        }
        return returnValue
    })
}

export type CreateUserRequest = {
    email: string
    emailConfirmed?: boolean
    sendEmailToConfirmEmailAddress?: boolean

    password?: string
    askUserToUpdatePasswordOnLogin?: boolean

    username?: string
    firstName?: string
    lastName?: string
    properties?: { [key: string]: any }
}

export function createUser(
    authUrl: URL,
    integrationApiKey: string,
    createUserRequest: CreateUserRequest
): Promise<User> {
    const request = {
        email: createUserRequest.email,
        email_confirmed: createUserRequest.emailConfirmed,
        send_email_to_confirm_email_address: createUserRequest.sendEmailToConfirmEmailAddress,

        password: createUserRequest.password,
        ask_user_to_update_password_on_login: createUserRequest.askUserToUpdatePasswordOnLogin,

        username: createUserRequest.username,
        first_name: createUserRequest.firstName,
        last_name: createUserRequest.lastName,
        properties: createUserRequest.properties,
    }
    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/`, "POST", JSON.stringify(request)).then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new CreateUserException(httpResponse.response)
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when creating user")
            }

            return parseSnakeCaseToCamelCase(httpResponse.response)
        }
    )
}

export function disableUser(authUrl: URL, integrationApiKey: string, userId: string): Promise<boolean> {
    if (!isValidId(userId)) {
        return Promise.resolve(false)
    }

    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/${userId}/disable`, "POST").then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 404) {
                return false
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when disabling user")
            }

            return true
        }
    )
}

export function enableUser(authUrl: URL, integrationApiKey: string, userId: string): Promise<boolean> {
    if (!isValidId(userId)) {
        return Promise.resolve(false)
    }

    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/${userId}/enable`, "POST").then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 404) {
            return false
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when enabling user")
        }

        return true
    })
}

export function disableUser2fa(authUrl: URL, integrationApiKey: string, userId: string): Promise<boolean> {
    if (!isValidId(userId)) {
        return Promise.resolve(false)
    }

    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/${userId}/disable_2fa`, "POST").then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 404) {
                return false
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when disabling 2FA")
            }

            return true
        }
    )
}

export type InviteUserToOrgRequest = {
    orgId: string
    email: string
    role: string
}

export function inviteUserToOrg(
    authUrl: URL,
    integrationApiKey: string,
    inviteUserToOrgRequest: InviteUserToOrgRequest
): Promise<boolean> {
    const body = {
        org_id: inviteUserToOrgRequest.orgId,
        email: inviteUserToOrgRequest.email,
        role: inviteUserToOrgRequest.role,
    }

    return httpRequest(authUrl, integrationApiKey, `/api/backend/v1/invite_user`, "POST", JSON.stringify(body)).then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new BadRequestException(httpResponse.response)
            } else if (httpResponse.statusCode === 404) {
                return false
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when inviting a user to the org")
            }

            return true
        }
    )
}

// PUT/PATCH
export type UpdateUserMetadataRequest = {
    username?: string
    firstName?: string
    lastName?: string
    pictureUrl?: string
    metadata?: { [key: string]: any }
    properties?: { [key: string]: any }
    updatePasswordRequired?: boolean
}
export function updateUserMetadata(
    authUrl: URL,
    integrationApiKey: string,
    userId: string,
    updateUserMetadataRequest: UpdateUserMetadataRequest
): Promise<boolean> {
    if (!isValidId(userId)) {
        return Promise.resolve(false)
    }

    const request = {
        username: updateUserMetadataRequest.username,
        first_name: updateUserMetadataRequest.firstName,
        last_name: updateUserMetadataRequest.lastName,
        picture_url: updateUserMetadataRequest.pictureUrl,
        metadata: updateUserMetadataRequest.metadata,
        properties: updateUserMetadataRequest.properties,
        update_password_required: updateUserMetadataRequest.updatePasswordRequired,
    }
    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/${userId}`, "PUT", JSON.stringify(request)).then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new UpdateUserMetadataException(httpResponse.response)
            } else if (httpResponse.statusCode === 404) {
                return false
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when updating user metadata")
            }

            return true
        }
    )
}

export type UpdateUserEmailRequest = {
    newEmail: string
    requireEmailConfirmation: boolean
}

export function updateUserEmail(
    authUrl: URL,
    integrationApiKey: string,
    userId: string,
    updateUserEmail: UpdateUserEmailRequest
): Promise<boolean> {
    if (!isValidId(userId)) {
        return Promise.resolve(false)
    }

    const request = {
        new_email: updateUserEmail.newEmail,
        require_email_confirmation: updateUserEmail.requireEmailConfirmation,
    }
    return httpRequest(
        authUrl,
        integrationApiKey,
        `${ENDPOINT_PATH}/${userId}/email`,
        "PUT",
        JSON.stringify(request)
    ).then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 400) {
            throw new UpdateUserEmailException(httpResponse.response)
        } else if (httpResponse.statusCode === 404) {
            return false
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when creating user")
        }

        return true
    })
}

export type UpdateUserPasswordRequest = {
    password: string
    askUserToUpdatePasswordOnLogin?: boolean
}

export function updateUserPassword(
    authUrl: URL,
    integrationApiKey: string,
    userId: string,
    updateUserPasswordRequest: UpdateUserPasswordRequest
): Promise<boolean> {
    if (!isValidId(userId)) {
        return Promise.resolve(false)
    }

    const request = {
        password: updateUserPasswordRequest.password,
        ask_user_to_update_password_on_login: updateUserPasswordRequest.askUserToUpdatePasswordOnLogin,
    }
    return httpRequest(
        authUrl,
        integrationApiKey,
        `${ENDPOINT_PATH}/${userId}/password`,
        "PUT",
        JSON.stringify(request)
    ).then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 400) {
            throw new UpdateUserPasswordException(httpResponse.response)
        } else if (httpResponse.statusCode === 404) {
            return false
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when updating password")
        }

        return true
    })
}

export function enableUserCanCreateOrgs(authUrl: URL, integrationApiKey: string, userId: string): Promise<boolean> {
    if (!isValidId(userId)) {
        return Promise.resolve(false)
    }

    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/${userId}/can_create_orgs/enable`, "PUT").then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 404) {
                return false
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when enabling canCreateOrgs")
            }

            return true
        }
    )
}

export function disableUserCanCreateOrgs(authUrl: URL, integrationApiKey: string, userId: string): Promise<boolean> {
    if (!isValidId(userId)) {
        return Promise.resolve(false)
    }

    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/${userId}/can_create_orgs/disable`, "PUT").then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 404) {
                return false
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when disabling canCreateOrgs")
            }

            return true
        }
    )
}

export async function clearUserPassword(authUrl: URL, integrationApiKey: string, userId: string): Promise<boolean> {
    if (!isValidId(userId)) {
        return Promise.resolve(false)
    }

    const httpResponse = await httpRequest(
        authUrl,
        integrationApiKey,
        `${ENDPOINT_PATH}/${userId}/clear_password`,
        "PUT"
    )
    if (httpResponse.statusCode === 401) {
        throw new Error("integrationApiKey is incorrect")
    } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
        throw new Error("Unknown error when clearing password")
    }
    return true
}

// DELETE
export function deleteUser(authUrl: URL, integrationApiKey: string, userId: string): Promise<boolean> {
    if (!isValidId(userId)) {
        return Promise.resolve(false)
    }

    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/${userId}`, "DELETE").then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 404) {
            return false
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when deleting user")
        }

        return true
    })
}
