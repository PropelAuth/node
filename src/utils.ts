import { OrgMemberInfo } from "./user"

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
