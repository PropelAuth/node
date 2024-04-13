import {
    AddUserToOrgException,
    ChangeUserRoleInOrgException,
    CreateOrgException,
    RemoveUserFromOrgException,
    UpdateOrgException,
} from "../exceptions"
import { httpRequest } from "../http"
import { CreatedOrg, Org } from "../user"
import { isValidId, parseSnakeCaseToCamelCase } from "../utils"

const ENDPOINT_PATH = "/api/backend/v1/org"

// GET
export function fetchOrg(authUrl: URL, integrationApiKey: string, orgId: string): Promise<Org | null> {
    if (!isValidId(orgId)) {
        return Promise.resolve(null)
    }

    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/${orgId}`, "GET").then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 404) {
            return null
        } else if (httpResponse.statusCode === 426) {
            throw new Error(
                "Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth dashboard."
            )
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when fetching org")
        }

        return parseSnakeCaseToCamelCase(httpResponse.response)
    })
}

// POST
export type OrgQuery = {
    pageSize?: number
    pageNumber?: number
    orderBy?: "CREATED_AT_ASC" | "CREATED_AT_DESC" | "NAME"
    name?: string
}

export type OrgQueryResponse = {
    orgs: Org[]
    totalOrgs: number
    currentPage: number
    pageSize: number
    hasMoreResults: boolean
}

export function fetchOrgByQuery(authUrl: URL, integrationApiKey: string, query: OrgQuery): Promise<OrgQueryResponse> {
    const request = {
        page_size: query.pageSize,
        page_number: query.pageNumber,
        order_by: query.orderBy,
        name: query.name,
    }
    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/query`, "POST", JSON.stringify(request)).then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new Error("Invalid query " + httpResponse.response)
            } else if (httpResponse.statusCode === 426) {
                throw new Error(
                    "Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth dashboard."
                )
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when fetching orgs by query")
            }

            return JSON.parse(httpResponse.response, function (key, value) {
                if (key === "org_id") {
                    this.orgId = value
                } else if (key === "org_name") {
                    this.name = value
                } else if (key === "max_users") {
                    this.maxUsers = value
                } else if (key === "total_orgs") {
                    this.totalOrgs = value
                } else if (key === "current_page") {
                    this.currentPage = value
                } else if (key === "page_size") {
                    this.pageSize = value
                } else if (key === "has_more_results") {
                    this.hasMoreResults = value
                } else {
                    return value
                }
            })
        }
    )
}

export type CreateOrgRequest = {
    name: string
    domain?: string
    enableAutoJoiningByDomain?: boolean
    membersMustHaveMatchingDomain?: boolean
    maxUsers?: number
}

type CreateOrgApiRequest = {
    name: string
    domain?: string
    enable_auto_joining_by_domain?: boolean
    members_must_have_matching_domain?: boolean
    max_users?: number
}

export function createOrg(
    authUrl: URL,
    integrationApiKey: string,
    createOrgRequest: CreateOrgRequest
): Promise<CreatedOrg> {
    const {
        name,
        domain,
        enableAutoJoiningByDomain = false,
        membersMustHaveMatchingDomain = false,
        maxUsers,
    } = createOrgRequest
    const request: CreateOrgApiRequest = {
        name,
        enable_auto_joining_by_domain: enableAutoJoiningByDomain,
        members_must_have_matching_domain: membersMustHaveMatchingDomain,
    }
    if (domain) {
        request["domain"] = domain
    }
    if (maxUsers) {
        request["max_users"] = maxUsers
    }
    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/`, "POST", JSON.stringify(request)).then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new CreateOrgException(httpResponse.response)
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when creating org")
            }

            return parseSnakeCaseToCamelCase(httpResponse.response)
        }
    )
}

export type AddUserToOrgRequest = {
    userId: string
    orgId: string
    role: string
}

export function addUserToOrg(
    authUrl: URL,
    integrationApiKey: string,
    addUserToOrgRequest: AddUserToOrgRequest
): Promise<boolean> {
    const request = {
        user_id: addUserToOrgRequest.userId,
        org_id: addUserToOrgRequest.orgId,
        role: addUserToOrgRequest.role,
    }
    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/add_user`, "POST", JSON.stringify(request)).then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 400) {
                throw new AddUserToOrgException(httpResponse.response)
            } else if (httpResponse.statusCode === 404) {
                return false
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when adding user to org")
            }

            return true
        }
    )
}

export type ChangeUserRoleInOrgRequest = {
    userId: string
    orgId: string
    role: string
}

export function changeUserRoleInOrg(
    authUrl: URL,
    integrationApiKey: string,
    changeUserRoleInOrgRequest: ChangeUserRoleInOrgRequest
): Promise<boolean> {
    const request = {
        user_id: changeUserRoleInOrgRequest.userId,
        org_id: changeUserRoleInOrgRequest.orgId,
        role: changeUserRoleInOrgRequest.role,
    }
    return httpRequest(
        authUrl,
        integrationApiKey,
        `${ENDPOINT_PATH}/change_role`,
        "POST",
        JSON.stringify(request)
    ).then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 400) {
            throw new ChangeUserRoleInOrgException(httpResponse.response)
        } else if (httpResponse.statusCode === 404) {
            return false
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when changing users role in org")
        }

        return true
    })
}

export type RemoveUserFromOrgRequest = {
    userId: string
    orgId: string
}

export function removeUserFromOrg(
    authUrl: URL,
    integrationApiKey: string,
    removeUserFromOrgRequest: RemoveUserFromOrgRequest
): Promise<boolean> {
    const request = {
        user_id: removeUserFromOrgRequest.userId,
        org_id: removeUserFromOrgRequest.orgId,
    }
    return httpRequest(
        authUrl,
        integrationApiKey,
        `${ENDPOINT_PATH}/remove_user`,
        "POST",
        JSON.stringify(request)
    ).then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 400) {
            throw new RemoveUserFromOrgException(httpResponse.response)
        } else if (httpResponse.statusCode === 404) {
            return false
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when removing users from org")
        }

        return true
    })
}

export function allowOrgToSetupSamlConnection(
    authUrl: URL,
    integrationApiKey: string,
    orgId: string
): Promise<boolean> {
    if (!isValidId(orgId)) {
        return Promise.resolve(false)
    }

    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/${orgId}/allow_saml`, "POST").then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 404) {
                return false
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when allowing org to setup SAML connection")
            }

            return true
        }
    )
}

export function disallowOrgToSetupSamlConnection(
    authUrl: URL,
    integrationApiKey: string,
    orgId: string
): Promise<boolean> {
    if (!isValidId(orgId)) {
        return Promise.resolve(false)
    }

    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/${orgId}/disallow_saml`, "POST").then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw new Error("integrationApiKey is incorrect")
            } else if (httpResponse.statusCode === 404) {
                return false
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw new Error("Unknown error when disallowing org to setup SAML connection")
            }

            return true
        }
    )
}

// PUT/PATCH
export type UpdateOrgRequest = {
    orgId: string
    name?: string
    canSetupSaml?: boolean
    maxUsers?: number
    metadata?: { [key: string]: any }
    canJoinOnEmailDomainMatch?: boolean // In the backend, this is the `domain_autojoin` argument.
    membersMustHaveEmailDomainMatch?: boolean // In the backend, this is the `domain_restrict` argument.
    domain?: string
    // TODO: Add `require_2fa_by` optional argument.
}

export function updateOrg(
    authUrl: URL,
    integrationApiKey: string,
    updateOrgRequest: UpdateOrgRequest
): Promise<boolean> {
    if (!isValidId(updateOrgRequest.orgId)) {
        return Promise.resolve(false)
    }

    const request = {
        name: updateOrgRequest.name,
        can_setup_saml: updateOrgRequest.canSetupSaml,
        metadata: updateOrgRequest.metadata,
        max_users: updateOrgRequest.maxUsers,
        autojoin_by_domain: updateOrgRequest.canJoinOnEmailDomainMatch,
        restrict_to_domain: updateOrgRequest.membersMustHaveEmailDomainMatch,
        domain: updateOrgRequest.domain,
    }
    return httpRequest(
        authUrl,
        integrationApiKey,
        `${ENDPOINT_PATH}/${updateOrgRequest.orgId}`,
        "PUT",
        JSON.stringify(request)
    ).then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 400) {
            throw new UpdateOrgException(httpResponse.response)
        } else if (httpResponse.statusCode === 404) {
            return false
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when updating org")
        }

        return true
    })
}

// DELETE
export function deleteOrg(authUrl: URL, integrationApiKey: string, orgId: string): Promise<boolean> {
    if (!isValidId(orgId)) {
        return Promise.resolve(false)
    }

    return httpRequest(authUrl, integrationApiKey, `${ENDPOINT_PATH}/${orgId}`, "DELETE").then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw new Error("integrationApiKey is incorrect")
        } else if (httpResponse.statusCode === 404) {
            return false
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw new Error("Unknown error when deleting org")
        }

        return true
    })
}
