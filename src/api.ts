import {httpRequest} from "./http"
import {Org, toUserRole, User, UserMetadata} from "./user"
import CreateUserException from "./CreateUserException";
import UpdateUserMetadataException from "./UpdateUserMetadataException";
import UpdateUserEmailException from "./UpdateUserEmailException";
import MagicLinkCreationException from "./MagicLinkCreationException";

export type TokenVerificationMetadata = {
    verifierKey: string
    issuer: string
}

export function fetchTokenVerificationMetadata(authUrl: URL,
                                               apiKey: string,
                                               manualTokenVerificationMetadata?: TokenVerificationMetadata): Promise<TokenVerificationMetadata> {
    if (manualTokenVerificationMetadata) {
        return Promise.resolve(manualTokenVerificationMetadata)
    }

    return httpRequest(authUrl, apiKey, "/api/v1/token_verification_metadata", "GET").then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("apiKey is incorrect")
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when fetching token verification metadata")
        }

        const jsonParse = JSON.parse(httpResponse.response)
        return {
            verifierKey: jsonParse.verifier_key_pem,
            issuer: formatIssuer(authUrl),
        }
    })
}

export function fetchUserMetadataByUserIdWithIdCheck(authUrl: URL, apiKey: string, userId: string, includeOrgs?: boolean): Promise<UserMetadata | null> {
    if (isValidId(userId)) {
        return fetchUserMetadataByQuery(authUrl, apiKey, userId, {include_orgs: includeOrgs || false})
    } else {
        return Promise.resolve(null);
    }
}

export function fetchUserMetadataByQuery(authUrl: URL, apiKey: string, pathParam: string, query: any): Promise<UserMetadata | null> {
    const queryString = formatQueryParameters(query)
    return httpRequest(authUrl, apiKey, `/api/backend/v1/user/${pathParam}?${queryString}`, "GET").then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("apiKey is incorrect")
        } else if (httpResponse.statusCode === 404) {
            return null
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when fetching user metadata")
        }

        return parseUserMetadataAndOptionalPagingInfo(httpResponse.response)
    })
}

export function fetchBatchUserMetadata(
    authUrl: URL,
    apiKey: string,
    type: string,
    values: string[],
    keyFunction: (x: UserMetadata) => string,
    includeOrgs?: boolean,
): Promise<{ [key: string]: UserMetadata }> {
    const queryString = includeOrgs ? formatQueryParameters({include_orgs: includeOrgs}) : ""
    const jsonBody = {[type]: values}
    return httpRequest(authUrl, apiKey, `/api/backend/v1/user/${type}?${queryString}`, "POST", JSON.stringify(jsonBody)).then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("apiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new Error("Bad request " + httpResponse.response)
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when fetching batch user metadata")
            }

            const userMetadatas = parseUserMetadataAndOptionalPagingInfo(httpResponse.response)

            const returnValue: { [key: string]: UserMetadata } = {}
            for (let userMetadata of userMetadatas) {
                returnValue[keyFunction(userMetadata)] = userMetadata
            }
            return returnValue
        },
    )
}

export function fetchOrg(authUrl: URL, apiKey: string, orgId: string): Promise<Org | null> {
    if (!isValidId(orgId)) {
        return Promise.resolve(null);
    }

    return httpRequest(authUrl, apiKey, `/api/backend/v1/org/${orgId}`, "GET").then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("apiKey is incorrect")
        } else if (httpResponse.statusCode === 404) {
            return null
        } else if (httpResponse.statusCode === 426) {
            throw new Error("Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth dashboard.")
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when fetching org")
        }

        const jsonParse = JSON.parse(httpResponse.response)
        return {
            orgId: jsonParse.org_id,
            name: jsonParse.name,
        }
    })
}

export type OrgQuery = {
    pageSize?: number
    pageNumber?: number
    orderBy?: "CREATED_AT_ASC" | "CREATED_AT_DESC" | "NAME"
}

export type OrgQueryResponse = {
    orgs: Org[],
    totalOrgs: number,
    currentPage: number,
    pageSize: number,
    hasMoreResults: boolean,
}

export function fetchOrgByQuery(authUrl: URL, apiKey: string, query: OrgQuery): Promise<OrgQueryResponse> {
    const request = {
        page_size: query.pageSize,
        page_number: query.pageNumber,
        order_by: query.orderBy,
    }
    return httpRequest(authUrl, apiKey, `/api/backend/v1/org/query`, "GET", JSON.stringify(request))
        .then((httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("apiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new Error("Invalid query " + httpResponse.response)
            } else if (httpResponse.statusCode === 426) {
                throw new Error("Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth dashboard.")
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when fetching orgs by query")
            }

            return JSON.parse(httpResponse.response, function (key, value) {
                if (key === "org_id") {
                    this.orgId = value
                } else if (key === "total_orgs") {
                    this.totalOrgs = value;
                } else if (key === "current_page") {
                    this.currentPage = value;
                } else if (key === "page_size") {
                    this.pageSize = value;
                } else if (key === "has_more_results") {
                    this.hasMoreResults = value;
                } else {
                    return value
                }
            })
        })
}

export type UsersQuery = {
    pageSize?: number,
    pageNumber?: number,
    orderBy?: "CREATED_AT_ASC" | "CREATED_AT_DESC" | "LAST_ACTIVE_AT_ASC" | "LAST_ACTIVE_AT_DESC" | "EMAIL" | "USERNAME",
    emailOrUsername?: string,
    includeOrgs?: boolean,
}

export type UsersPagedResponse = {
    users: UserMetadata[],
    totalUsers: number,
    currentPage: number,
    pageSize: number,
    hasMoreResults: boolean
}

export function fetchUsersByQuery(authUrl: URL, apiKey: string, query: UsersQuery): Promise<UsersPagedResponse> {
    const queryParams = {
        page_size: query.pageSize,
        page_number: query.pageNumber,
        order_by: query.orderBy,
        email_or_username: query.emailOrUsername,
        include_orgs: query.includeOrgs,
    }
    const q = formatQueryParameters(queryParams)
    return httpRequest(authUrl, apiKey, `/api/backend/v1/user/query?${q}`, "GET")
        .then((httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("apiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new Error("Invalid query " + httpResponse.response)
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when fetching users by query")
            }

            return parseUserMetadataAndOptionalPagingInfo(httpResponse.response)
        })
}

export type UsersInOrgQuery = {
    orgId: string,
    pageSize?: number,
    pageNumber?: number,
    includeOrgs?: boolean,
}

export function fetchUsersInOrg(authUrl: URL, apiKey: string, query: UsersInOrgQuery): Promise<UsersPagedResponse> {
    if (!isValidId(query.orgId)) {
        const emptyResponse: UsersPagedResponse = {
            users: [],
            totalUsers: 0,
            currentPage: query.pageNumber || 0,
            pageSize: query.pageSize || 10,
            hasMoreResults: false
        }
        return Promise.resolve(emptyResponse)
    }

    const queryParams = {
        page_size: query.pageSize,
        page_number: query.pageNumber,
        include_orgs: query.includeOrgs,
    }
    const queryString = formatQueryParameters(queryParams)
    return httpRequest(authUrl, apiKey, `/api/backend/v1/user/org/${query.orgId}?${queryString}`, "GET")
        .then((httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("apiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new Error("Invalid query " + httpResponse.response)
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when fetching users in org")
            }

            return parseUserMetadataAndOptionalPagingInfo(httpResponse.response)
        })
}

export type CreateUserRequest = {
    email: string,
    emailConfirmed?: boolean,
    sendEmailToConfirmEmailAddress?: boolean,

    password?: string,
    username?: string,

    firstName?: string,
    lastName?: string,
}

export function createUser(authUrl: URL, apiKey: string, createUserRequest: CreateUserRequest): Promise<User> {
    const request = {
        email: createUserRequest.email,
        email_confirmed: createUserRequest.emailConfirmed,
        send_email_to_confirm_email_address: createUserRequest.sendEmailToConfirmEmailAddress,

        password: createUserRequest.password,
        username: createUserRequest.username,

        first_name: createUserRequest.firstName,
        last_name: createUserRequest.lastName,
    }
    return httpRequest(authUrl, apiKey, `/api/backend/v1/user/`, "POST", JSON.stringify(request))
        .then((httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("apiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new CreateUserException(httpResponse.response)
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when creating user")
            }

            return JSON.parse(httpResponse.response, function (key, value) {
                if (key === "user_id") {
                    this.userId = value
                } else {
                    return value
                }
            })
        })
}

export type UpdateUserMetadataRequest = {
    username?: string,
    firstName?: string,
    lastName?: string,
}

export function updateUserMetadata(authUrl: URL, apiKey: string, userId: string, updateUserMetadataRequest: UpdateUserMetadataRequest): Promise<boolean> {
    if (!isValidId(userId)) {
        return Promise.resolve(false)
    }

    const request = {
        username: updateUserMetadataRequest.username,
        first_name: updateUserMetadataRequest.firstName,
        last_name: updateUserMetadataRequest.lastName,
    }
    return httpRequest(authUrl, apiKey, `/api/backend/v1/user/${userId}`, "PUT", JSON.stringify(request))
        .then((httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("apiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new UpdateUserMetadataException(httpResponse.response)
            } else if (httpResponse.statusCode === 404) {
                return false
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when creating user")
            }

            return true
        })
}

export type UpdateUserEmailRequest = {
    newEmail: string,
    requireEmailConfirmation: boolean,
}

export function updateUserEmail(authUrl: URL, apiKey: string, userId: string, updateUserEmail: UpdateUserEmailRequest): Promise<boolean> {
    if (!isValidId(userId)) {
        return Promise.resolve(false)
    }

    const request = {
        new_email: updateUserEmail.newEmail,
        require_email_confirmation: updateUserEmail.requireEmailConfirmation,
    }
    return httpRequest(authUrl, apiKey, `/api/backend/v1/user/${userId}/email`, "PUT", JSON.stringify(request))
        .then((httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("apiKey is incorrect")
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

export type CreateMagicLinkRequest = {
    email: string,
    redirectToUrl?: string,
    expiresInHours?: string,
    createNewUserIfOneDoesntExist?: boolean,
}

export type MagicLink = {
    url: string
}

export function createMagicLink(authUrl: URL, apiKey: string, createMagicLinkRequest: CreateMagicLinkRequest): Promise<MagicLink> {
    const request = {
        email: createMagicLinkRequest.email,
        redirect_to_url: createMagicLinkRequest.redirectToUrl,
        expires_in_hours: createMagicLinkRequest.expiresInHours,
        create_new_user_if_one_doesnt_exist: createMagicLinkRequest.createNewUserIfOneDoesntExist,
    }
    return httpRequest(authUrl, apiKey, `/api/backend/v1/magic_link`, "POST", JSON.stringify(request))
        .then((httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("apiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new MagicLinkCreationException(httpResponse.response)
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when creating magic link")
            }

            return JSON.parse(httpResponse.response)
        })
}

const idRegex = /^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$/i;
function isValidId(id: string): boolean {
    return idRegex.test(id)
}

function formatQueryParameters(obj: {[key: string]: any}): string {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(obj)) {
        if (value !== undefined) {
            params.set(key, value);
        }
    }
    return params.toString()
}

function formatIssuer(authUrl: URL): string {
    return authUrl.origin
}

function parseUserMetadataAndOptionalPagingInfo(response: string) {
    return JSON.parse(response, function (key, value) {
        if (key === "user_id") {
            this.userId = value
        } else if (key === "email_confirmed") {
            this.emailConfirmed = value;
        } else if (key === "first_name") {
            this.firstName = value;
        } else if (key === "last_name") {
            this.lastName = value;
        } else if (key === "picture_url") {
            this.pictureUrl = value;
        } else if (key === "mfa_enabled") {
            this.mfaEnabled = value;
        } else if (key === "created_at") {
            this.createdAt = value;
        } else if (key === "last_active_at") {
            this.lastActiveAt = value;
        } else if (key === "org_id_to_org_info") {
            this.orgIdToOrgInfo = value;
        } else if (key === "org_id") {
            this.orgId = value;
        } else if (key === "org_name") {
            this.orgName = value;
        } else if (key === "user_role") {
            this.userRole = toUserRole(value);
        } else if (key === "total_users") {
            this.totalUsers = value;
        } else if (key === "current_page") {
            this.currentPage = value;
        } else if (key === "page_size") {
            this.pageSize = value;
        } else if (key === "has_more_results") {
            this.hasMoreResults = value;
        } else {
            return value
        }
    });
}