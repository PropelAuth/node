import { generateKeyPair } from "crypto"
import { v4 as uuid } from "uuid"
import { OrgRoleStructure } from "@propelauth/node-apis"

import {
    ForbiddenException,
    initAuth,
    InternalOrgMemberInfo,
    InternalUser,
    OrgMemberInfo,
    toUser,
    UnauthorizedException,
    User,
} from "../src"
import * as jose from "jose"
import { RequiredOrgInfo } from "@propelauth/node/dist/auth"

const AUTH_URL = "https://auth.example.com"
const ALGO = "RS256"

afterEach(() => {
    jest.useRealTimers()
})

test("bad authUrl is rejected", async () => {
    expect(() => {
        initAuth({
            authUrl: "not.a.url",
            apiKey: "apiKey",
            verifierKey: "",
        })
    }).toThrow()
})

test("validateAuthHeaderAndGetUser gets correct user", async () => {
    const { privateKey, publicKey } = await generateRsaKeyPair()
    const { validateAuthHeaderAndGetUser } = initAuth({ authUrl: AUTH_URL, verifierKey: publicKey, apiKey: "" })

    const internalUser = randomInternalUser()
    const accessToken = await createAccessToken({ internalUser, privateKey })

    const authHeader = `Bearer ${accessToken}`

    const user = await validateAuthHeaderAndGetUser(authHeader)
    expect(user).toEqual(toUser(internalUser))
})

test("validateAuthHeaderAndGetUser rejects expired access tokens", async () => {
    jest.useFakeTimers("modern")
    const { privateKey, publicKey } = await generateRsaKeyPair()
    const { validateAuthHeaderAndGetUser } = initAuth({ authUrl: AUTH_URL, verifierKey: publicKey, apiKey: "" })

    const internalUser = randomInternalUser()
    const accessToken = await createAccessToken({ internalUser, expiresIn: "30m", privateKey })

    // 31 minutes
    jest.advanceTimersByTime(1000 * 60 * 31)

    const authHeader = `Bearer ${accessToken}`

    await expect(validateAuthHeaderAndGetUser(authHeader)).rejects.toThrow(UnauthorizedException)
})

test("validateAuthHeaderAndGetUser rejects invalid access tokens", async () => {
    const { publicKey } = await generateRsaKeyPair()
    const { validateAuthHeaderAndGetUser } = initAuth({ authUrl: AUTH_URL, verifierKey: publicKey, apiKey: "" })

    const accessToken = "invalid"
    const authHeader = `Bearer ${accessToken}`

    await expect(validateAuthHeaderAndGetUser(authHeader)).rejects.toThrow(UnauthorizedException)
})

test("validateAuthHeaderAndGetUser rejects missing authorization header", async () => {
    const { publicKey } = await generateRsaKeyPair()
    const { validateAuthHeaderAndGetUser } = initAuth({ authUrl: AUTH_URL, verifierKey: publicKey, apiKey: "" })

    await expect(validateAuthHeaderAndGetUser(null)).rejects.toThrow(UnauthorizedException)
})

test("validateAccessTokenAndGetUser fails with incorrect issuer", async () => {
    const { privateKey, publicKey } = await generateRsaKeyPair()
    const { validateAuthHeaderAndGetUser } = initAuth({ authUrl: AUTH_URL, verifierKey: publicKey, apiKey: "" })

    const internalUser = randomInternalUser()
    const accessToken = await createAccessToken({ internalUser, privateKey, issuer: "bad" })

    const authHeader = `Bearer ${accessToken}`

    await expect(validateAuthHeaderAndGetUser(authHeader)).rejects.toThrow(UnauthorizedException)
})

test("toUser converts correctly with orgs", async () => {
    const internalUser: InternalUser = {
        user_id: "cbf064e2-edaa-4d35-b413-a8d857329c12",
        email: "easteregg@propelauth.com",
        first_name: "easter",
        org_id_to_org_member_info: {
            "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a": {
                org_id: "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a",
                org_name: "orgA",
                org_metadata: { orgdata_a: "orgvalue_a" },
                url_safe_org_name: "orga",
                user_role: "Owner",
                inherited_user_roles_plus_current_role: ["Owner", "Admin", "Member"],
                user_permissions: [],
                org_role_structure: OrgRoleStructure.SingleRole,
                additional_roles: [],
            },
            "4ca20d17-5021-4d62-8b3d-148214fa8d6d": {
                org_id: "4ca20d17-5021-4d62-8b3d-148214fa8d6d",
                org_name: "orgB",
                org_metadata: { orgdata_b: "orgvalue_b" },
                url_safe_org_name: "orgb",
                user_role: "Admin",
                inherited_user_roles_plus_current_role: ["Admin", "Member"],
                user_permissions: [],
                org_role_structure: OrgRoleStructure.SingleRole,
                additional_roles: [],
            },
            "15a31d0c-d284-4e7b-80a2-afb23f939cc3": {
                org_id: "15a31d0c-d284-4e7b-80a2-afb23f939cc3",
                org_name: "orgC",
                org_metadata: { orgdata_c: "orgvalue_c" },
                url_safe_org_name: "orgc",
                user_role: "Member",
                inherited_user_roles_plus_current_role: ["Member"],
                user_permissions: [],
                org_role_structure: OrgRoleStructure.SingleRole,
                additional_roles: [],
            },
        },
    }

    const user: User = {
        userId: "cbf064e2-edaa-4d35-b413-a8d857329c12",
        email: "easteregg@propelauth.com",
        firstName: "easter",
        orgIdToOrgMemberInfo: {
            "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a": new OrgMemberInfo(
                "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a",
                "orgA",
                { orgdata_a: "orgvalue_a" },
                "orga",
                "Owner",
                ["Owner", "Admin", "Member"],
                []
            ),
            "4ca20d17-5021-4d62-8b3d-148214fa8d6d": new OrgMemberInfo(
                "4ca20d17-5021-4d62-8b3d-148214fa8d6d",
                "orgB",
                { orgdata_b: "orgvalue_b" },
                "orgb",
                "Admin",
                ["Admin", "Member"],
                []
            ),
            "15a31d0c-d284-4e7b-80a2-afb23f939cc3": new OrgMemberInfo(
                "15a31d0c-d284-4e7b-80a2-afb23f939cc3",
                "orgC",
                { orgdata_c: "orgvalue_c" },
                "orgc",
                "Member",
                ["Member"],
                []
            ),
        },
        loginMethod: { loginMethod: "unknown" },
    }

    expect(toUser(internalUser)).toEqual(user)
})

test("toUser converts correctly without orgs", async () => {
    const internalUser: InternalUser = {
        user_id: "cbf064e2-edaa-4d35-b413-a8d857329c12",
        email: "easteregg@propelauth.com",
        legacy_user_id: "something",
    }
    const user: User = {
        userId: "cbf064e2-edaa-4d35-b413-a8d857329c12",
        email: "easteregg@propelauth.com",
        legacyUserId: "something",
        loginMethod: { loginMethod: "unknown" },
    }
    expect(toUser(internalUser)).toEqual(user)
})

test("validateAuthHeaderAndGetUserWithOrgInfo get user and org for extracted org", async () => {
    const { privateKey, publicKey } = await generateRsaKeyPair()
    const { validateAuthHeaderAndGetUserWithOrgInfo } = initAuth({
        authUrl: AUTH_URL,
        verifierKey: publicKey,
        apiKey: "",
    })

    const orgMemberInfo = randomOrg()
    const internalUser: InternalUser = {
        user_id: uuid(),
        email: uuid(),
        org_id_to_org_member_info: {
            [orgMemberInfo.org_id]: orgMemberInfo,
        },
    }
    const orgInfo: RequiredOrgInfo = {
        orgId: orgMemberInfo.org_id,
        orgName: orgMemberInfo.org_name,
    }
    const accessToken = await createAccessToken({ internalUser, privateKey })

    const userAndOrgMemberInfo = await validateAuthHeaderAndGetUserWithOrgInfo(`Bearer ${accessToken}`, orgInfo)

    const user = toUser(internalUser)
    expect(userAndOrgMemberInfo.user).toEqual(user)
    expect(userAndOrgMemberInfo.orgMemberInfo).toEqual(
        user.orgIdToOrgMemberInfo && user.orgIdToOrgMemberInfo[orgMemberInfo.org_id]
    )
})

test("validateAuthHeaderAndGetUserWithOrgInfo fails for valid access token but unknown org", async () => {
    const { privateKey, publicKey } = await generateRsaKeyPair()
    const { validateAuthHeaderAndGetUserWithOrgInfo } = initAuth({
        authUrl: AUTH_URL,
        verifierKey: publicKey,
        apiKey: "",
    })

    const internalUser: InternalUser = {
        user_id: uuid(),
        email: uuid(),
    }
    const orgInfo: RequiredOrgInfo = {
        orgId: uuid(),
        orgName: "orgName",
    }
    const accessToken = await createAccessToken({ internalUser, privateKey })

    await expect(validateAuthHeaderAndGetUserWithOrgInfo(`Bearer ${accessToken}`, orgInfo)).rejects.toThrow(
        ForbiddenException
    )
})

test("validateAuthHeaderAndGetUserWithOrgInfo fails for invalid access token", async () => {
    const { privateKey, publicKey } = await generateRsaKeyPair()
    const { validateAuthHeaderAndGetUserWithOrgInfo } = initAuth({
        authUrl: AUTH_URL,
        verifierKey: publicKey,
        apiKey: "",
    })

    const orgInfo: RequiredOrgInfo = {
        orgId: uuid(),
        orgName: "orgName",
    }

    await expect(validateAuthHeaderAndGetUserWithOrgInfo(null, orgInfo)).rejects.toThrow(UnauthorizedException)
})

test("validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole works with miniumumRole", async () => {
    const { privateKey, publicKey } = await generateRsaKeyPair()
    const { validateAuthHeaderAndGetUserWithOrgInfoWithMinimumRole } = initAuth({
        authUrl: AUTH_URL,
        verifierKey: publicKey,
        apiKey: "",
    })

    const orgMemberInfo = randomOrg()
    const internalUser: InternalUser = {
        user_id: uuid(),
        email: uuid(),
        org_id_to_org_member_info: {
            [orgMemberInfo.org_id]: orgMemberInfo,
        },
        metadata: {
            userdata: "uservalue",
        },
    }
    const orgInfo: RequiredOrgInfo = {
        orgId: orgMemberInfo.org_id,
        orgName: orgMemberInfo.org_name,
    }
    const user = toUser(internalUser)
    const accessToken = await createAccessToken({ internalUser, privateKey })

    const rolesThatShouldSucceed = new Set(["Admin", "Member"])
    for (let role of ["Owner", "Admin", "Member"]) {
        const authHeader = `Bearer ${accessToken}`

        if (rolesThatShouldSucceed.has(role)) {
            const userAndOrgMemberInfo = await validateAuthHeaderAndGetUserWithOrgInfoWithMinimumRole(
                authHeader,
                orgInfo,
                role
            )
            expect(userAndOrgMemberInfo.user).toEqual(user)
            expect(userAndOrgMemberInfo.orgMemberInfo).toEqual(
                user.orgIdToOrgMemberInfo && user.orgIdToOrgMemberInfo[orgMemberInfo.org_id]
            )
        } else {
            await expect(
                validateAuthHeaderAndGetUserWithOrgInfoWithMinimumRole(authHeader, orgInfo, role)
            ).rejects.toThrow(ForbiddenException)
        }
    }
})

test("validateAuthHeaderAndGetUserWithOrgInfoWithExactRole works with requiredRole", async () => {
    const { privateKey, publicKey } = await generateRsaKeyPair()
    const { validateAuthHeaderAndGetUserWithOrgInfoWithExactRole } = initAuth({
        authUrl: AUTH_URL,
        verifierKey: publicKey,
        apiKey: "",
    })

    const orgMemberInfo = randomOrg()
    const internalUser: InternalUser = {
        user_id: uuid(),
        email: uuid(),
        org_id_to_org_member_info: {
            [orgMemberInfo.org_id]: orgMemberInfo,
        },
    }
    const orgInfo: RequiredOrgInfo = {
        orgId: orgMemberInfo.org_id,
        orgName: orgMemberInfo.org_name,
    }
    const user = toUser(internalUser)
    const accessToken = await createAccessToken({ internalUser, privateKey })

    const rolesThatShouldSucceed = new Set(["Admin"])
    for (let role of ["Owner", "Admin", "Member"]) {
        const authHeader = `Bearer ${accessToken}`

        if (rolesThatShouldSucceed.has(role)) {
            const userAndOrgMemberInfo = await validateAuthHeaderAndGetUserWithOrgInfoWithExactRole(
                authHeader,
                orgInfo,
                role
            )
            expect(userAndOrgMemberInfo.user).toEqual(user)
            expect(userAndOrgMemberInfo.orgMemberInfo).toEqual(
                user.orgIdToOrgMemberInfo && user.orgIdToOrgMemberInfo[orgMemberInfo.org_id]
            )
        } else {
            await expect(
                validateAuthHeaderAndGetUserWithOrgInfoWithExactRole(authHeader, orgInfo, role)
            ).rejects.toThrow(ForbiddenException)
        }
    }
})

test("validateAuthHeaderAndGetUserWithOrgInfoWithPermission works with permission", async () => {
    const { privateKey, publicKey } = await generateRsaKeyPair()
    const { validateAuthHeaderAndGetUserWithOrgInfoWithPermission } = initAuth({
        authUrl: AUTH_URL,
        verifierKey: publicKey,
        apiKey: "",
    })

    const orgMemberInfo = randomOrg()
    const internalUser: InternalUser = {
        user_id: uuid(),
        email: uuid(),
        org_id_to_org_member_info: {
            [orgMemberInfo.org_id]: orgMemberInfo,
        },
    }
    const orgInfo: RequiredOrgInfo = {
        orgId: orgMemberInfo.org_id,
        orgName: orgMemberInfo.org_name,
    }
    const user = toUser(internalUser)
    const accessToken = await createAccessToken({ internalUser, privateKey })

    const permissionsThatShouldSucceed = new Set(["read", "write"])
    for (let permission of ["read", "write", "delete"]) {
        const authHeader = `Bearer ${accessToken}`

        if (permissionsThatShouldSucceed.has(permission)) {
            const userAndOrgMemberInfo = await validateAuthHeaderAndGetUserWithOrgInfoWithPermission(
                authHeader,
                orgInfo,
                permission
            )
            expect(userAndOrgMemberInfo.user).toEqual(user)
            expect(userAndOrgMemberInfo.orgMemberInfo).toEqual(
                user.orgIdToOrgMemberInfo && user.orgIdToOrgMemberInfo[orgMemberInfo.org_id]
            )
        } else {
            await expect(
                validateAuthHeaderAndGetUserWithOrgInfoWithPermission(authHeader, orgInfo, permission)
            ).rejects.toThrow(ForbiddenException)
        }
    }
})

test("validateAuthHeaderAndGetUserWithOrgInfoWithAllPermissions works with permission", async () => {
    const { privateKey, publicKey } = await generateRsaKeyPair()
    const { validateAuthHeaderAndGetUserWithOrgInfoWithAllPermissions } = initAuth({
        authUrl: AUTH_URL,
        verifierKey: publicKey,
        apiKey: "",
    })

    const orgMemberInfo = randomOrg()
    const internalUser: InternalUser = {
        user_id: uuid(),
        email: uuid(),
        org_id_to_org_member_info: {
            [orgMemberInfo.org_id]: orgMemberInfo,
        },
    }
    const orgInfo: RequiredOrgInfo = {
        orgId: orgMemberInfo.org_id,
        orgName: orgMemberInfo.org_name,
    }
    const user = toUser(internalUser)
    const accessToken = await createAccessToken({ internalUser, privateKey })

    // these should succeed
    for (let permissions of [["read"], ["write"], ["read", "write"], []]) {
        const authHeader = `Bearer ${accessToken}`
        const userAndOrgMemberInfo = await validateAuthHeaderAndGetUserWithOrgInfoWithAllPermissions(
            authHeader,
            orgInfo,
            permissions
        )
        expect(userAndOrgMemberInfo.user).toEqual(user)
        expect(userAndOrgMemberInfo.orgMemberInfo).toEqual(
            user.orgIdToOrgMemberInfo && user.orgIdToOrgMemberInfo[orgMemberInfo.org_id]
        )
    }

    // these should throw an error
    for (let permissions of [["read", "write", "delete"], ["delete"]]) {
        const authHeader = `Bearer ${accessToken}`
        await expect(
            validateAuthHeaderAndGetUserWithOrgInfoWithAllPermissions(authHeader, orgInfo, permissions)
        ).rejects.toThrow(ForbiddenException)
    }
})

// helper functions

async function createAccessToken({
    internalUser,
    privateKey,
    expiresIn,
    issuer,
}: CreateAccessTokenArgs): Promise<string> {
    const key = await jose.importPKCS8(privateKey, "RS256")

    return await new jose.SignJWT(internalUser)
        .setProtectedHeader({ alg: "RS256" })
        .setIssuedAt()
        .setIssuer(issuer ? issuer : AUTH_URL)
        .setExpirationTime(expiresIn ? expiresIn : "1d")
        .sign(key)
}

async function generateRsaKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
    return new Promise((resolve, reject) => {
        generateKeyPair("rsa", { modulusLength: 2048 }, (err, publicKey, privateKey) => {
            if (err) {
                reject(err)
            } else {
                resolve({
                    publicKey: publicKey
                        .export({
                            type: "spki",
                            format: "pem",
                        })
                        .toString(),
                    privateKey: privateKey
                        .export({
                            type: "pkcs8",
                            format: "pem",
                        })
                        .toString(),
                })
            }
        })
    })
}

function randomString() {
    return (Math.random() + 1).toString(36).substring(3)
}

function randomInternalUser(): InternalUser {
    return {
        user_id: uuid(),
        email: uuid(),
        org_id_to_org_member_info: randomOrgIdToOrgMemberInfo(),
    }
}

function randomOrgIdToOrgMemberInfo(): { [org_id: string]: InternalOrgMemberInfo } | undefined {
    const numOrgs = Math.floor(Math.random() * 10)
    if (numOrgs === 0) {
        return undefined
    }

    const orgIdToOrgMemberInfo: { [org_id: string]: InternalOrgMemberInfo } = {}
    for (let i = 0; i < numOrgs; i++) {
        const org = randomOrg()
        orgIdToOrgMemberInfo[org.org_id] = org
    }
    return orgIdToOrgMemberInfo
}

function randomOrg(): InternalOrgMemberInfo {
    const orgName = randomString()
    const urlSafeOrgName = orgName.replace(" ", "_").toLowerCase()
    return {
        org_id: uuid(),
        org_name: randomString(),
        org_metadata: { internalData: randomString() },
        url_safe_org_name: urlSafeOrgName,
        user_role: "Admin",
        inherited_user_roles_plus_current_role: ["Admin", "Member"],
        user_permissions: ["read", "write"],
        org_role_structure: OrgRoleStructure.SingleRole,
        additional_roles: [],
    }
}

interface CreateAccessTokenArgs {
    internalUser: InternalUser
    privateKey: string
    expiresIn?: string
    issuer?: string
}
