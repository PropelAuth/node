import {
    ForbiddenException,
    InternalOrgMemberInfo,
    InternalUser,
    OrgRoleStructure,
    TokenVerificationMetadata,
    toUser,
    UnauthorizedException,
    UnexpectedException,
} from "@propelauth/node-apis"
import { createPrivateKey, generateKeyPair } from "crypto"
import * as jose from "jose"
import nock from "nock"
import { v4 as uuid } from "uuid"
import { initBaseAuth } from "../src"
import { RequiredOrgInfo } from "../src/auth"

const BASE_API_URL = "https://propelauth-api.com"
const AUTH_HOSTNAME = "auth.example.com"
const AUTH_URL = "https://" + AUTH_HOSTNAME
const ALGO = "RS256"

afterEach(() => {
    jest.useRealTimers()
})

test("bad authUrl is rejected", async () => {
    expect(() => {
        initBaseAuth({
            authUrl: "not.a.url",
            apiKey: "apiKey",
        })
    }).toThrow()
})

test("validateAccessTokenAndGetUser gets correct user", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { validateAccessTokenAndGetUser } = initBaseAuth({ authUrl: AUTH_URL + "/", apiKey })

    const internalUser = randomInternalUser()
    const accessToken = await createAccessToken({ internalUser, privateKey })

    const authHeader = `Bearer ${accessToken}`

    const user = await validateAccessTokenAndGetUser(authHeader)
    expect(user).toEqual(toUser(internalUser))
    expect(nock.isDone()).toBe(true)
})

test("when manualTokenVerificationMetadata is specified, no fetch is made", async () => {
    // Never setup the token verification endpoint
    const { privateKey, publicKey } = await generateRsaKeyPair()
    const tokenVerificationMetadata: TokenVerificationMetadata = {
        issuer: AUTH_URL,
        verifierKey: publicKey,
    }
    const { validateAccessTokenAndGetUser } = initBaseAuth({
        authUrl: AUTH_URL + "/",
        apiKey: "irrelevant api key for this test",
        manualTokenVerificationMetadata: tokenVerificationMetadata,
    })

    const internalUser = randomInternalUser()
    const accessToken = await createAccessToken({ internalUser, privateKey })

    const authHeader = `Bearer ${accessToken}`

    const user = await validateAccessTokenAndGetUser(authHeader)
    expect(user).toEqual(toUser(internalUser))
    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUser rejects expired access tokens", async () => {
    jest.useFakeTimers("modern")
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { validateAccessTokenAndGetUser } = initBaseAuth({ authUrl: AUTH_URL + "/", apiKey })

    const internalUser = randomInternalUser()
    const accessToken = await createAccessToken({ internalUser, expiresIn: "30m", privateKey })

    // 31 minutes
    jest.advanceTimersByTime(1000 * 60 * 31)

    const authHeader = `Bearer ${accessToken}`

    await expect(validateAccessTokenAndGetUser(authHeader)).rejects.toThrow(UnauthorizedException)

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUser rejects invalid access tokens", async () => {
    const { apiKey } = await setupTokenVerificationMetadataEndpoint()
    const { validateAccessTokenAndGetUser } = initBaseAuth({ authUrl: AUTH_URL, apiKey })

    const accessToken = "invalid"
    const authHeader = `Bearer ${accessToken}`

    await expect(validateAccessTokenAndGetUser(authHeader)).rejects.toThrow(UnauthorizedException)

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUser rejects missing authorization header", async () => {
    const { apiKey } = await setupTokenVerificationMetadataEndpoint()
    const { validateAccessTokenAndGetUser } = initBaseAuth({ authUrl: AUTH_URL, apiKey })

    await expect(validateAccessTokenAndGetUser(undefined)).rejects.toThrow(UnauthorizedException)

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUser fails with incorrect apiKey", async () => {
    const { apiKey } = await setupErrorTokenVerificationMetadataEndpoint(401)
    const { validateAccessTokenAndGetUser } = initBaseAuth({ authUrl: AUTH_URL, apiKey: apiKey })

    await expect(validateAccessTokenAndGetUser("irrelevant")).rejects.toThrow(UnexpectedException)

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUser fails with incorrect issuer", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { validateAccessTokenAndGetUser } = initBaseAuth({ authUrl: AUTH_URL, apiKey })

    const internalUser = randomInternalUser()
    const accessToken = await createAccessToken({ internalUser, privateKey, issuer: "bad" })

    const authHeader = `Bearer ${accessToken}`

    await expect(validateAccessTokenAndGetUser(authHeader)).rejects.toThrow(UnauthorizedException)

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole get user and org for extracted org", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { validateAccessTokenAndGetUserWithOrgInfo } = initBaseAuth({ authUrl: AUTH_URL, apiKey })

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
    const accessToken = await createAccessToken({ internalUser, privateKey })

    const userAndOrgMemberInfo = await validateAccessTokenAndGetUserWithOrgInfo(`Bearer ${accessToken}`, orgInfo)

    const user = toUser(internalUser)
    expect(userAndOrgMemberInfo.user).toEqual(user)
    expect(userAndOrgMemberInfo.orgMemberInfo).toEqual(
        user.orgIdToOrgMemberInfo && user.orgIdToOrgMemberInfo[orgMemberInfo.org_id]
    )
    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole fails for valid access token but unknown org", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { validateAccessTokenAndGetUserWithOrgInfo } = initBaseAuth({ authUrl: AUTH_URL, apiKey })

    const internalUser: InternalUser = {
        user_id: uuid(),
        email: uuid(),
    }
    const orgInfo: RequiredOrgInfo = {
        orgId: uuid(),
        orgName: "orgName",
    }
    const accessToken = await createAccessToken({ internalUser, privateKey })

    await expect(validateAccessTokenAndGetUserWithOrgInfo(`Bearer ${accessToken}`, orgInfo)).rejects.toThrow(
        ForbiddenException
    )

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole fails for invalid access token", async () => {
    const { apiKey } = await setupTokenVerificationMetadataEndpoint()
    const { validateAccessTokenAndGetUserWithOrgInfo } = initBaseAuth({ authUrl: AUTH_URL, apiKey })

    const orgInfo: RequiredOrgInfo = {
        orgId: uuid(),
        orgName: "orgName",
    }

    await expect(validateAccessTokenAndGetUserWithOrgInfo(undefined, orgInfo)).rejects.toThrow(UnauthorizedException)

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole works with minimumRole", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole } = initBaseAuth({ authUrl: AUTH_URL, apiKey })

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

    const rolesThatShouldSucceed = new Set(["Admin", "Member"])
    for (let role of ["Owner", "Admin", "Member"]) {
        const authHeader = `Bearer ${accessToken}`

        if (rolesThatShouldSucceed.has(role)) {
            const userAndOrgMemberInfo = await validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(
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
                validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(authHeader, orgInfo, role)
            ).rejects.toThrow(ForbiddenException)
        }
    }
    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUserWithOrgWithExactRole works with requiredRole", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { validateAccessTokenAndGetUserWithOrgInfoWithExactRole } = initBaseAuth({ authUrl: AUTH_URL, apiKey })

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
            const userAndOrgMemberInfo = await validateAccessTokenAndGetUserWithOrgInfoWithExactRole(
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
                validateAccessTokenAndGetUserWithOrgInfoWithExactRole(authHeader, orgInfo, role)
            ).rejects.toThrow(ForbiddenException)
        }
    }
    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUserWithOrgWithPermission works with permission", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { validateAccessTokenAndGetUserWithOrgInfoWithPermission } = initBaseAuth({ authUrl: AUTH_URL, apiKey })

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
            const userAndOrgMemberInfo = await validateAccessTokenAndGetUserWithOrgInfoWithPermission(
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
                validateAccessTokenAndGetUserWithOrgInfoWithPermission(authHeader, orgInfo, permission)
            ).rejects.toThrow(ForbiddenException)
        }
    }
    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUserWithOrgWithAllPermissions works with permission", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions } = initBaseAuth({ authUrl: AUTH_URL, apiKey })

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
        const userAndOrgMemberInfo = await validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(
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
            validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(authHeader, orgInfo, permissions)
        ).rejects.toThrow(ForbiddenException)
    }

    expect(nock.isDone()).toBe(true)
})

// helper functions

async function setupTokenVerificationMetadataEndpoint() {
    const { publicKey, privateKey } = await generateRsaKeyPair()
    const apiKey = randomString()

    const scope = nock(BASE_API_URL)
        .get("/api/v1/token_verification_metadata")
        .matchHeader("authorization", `Bearer ${apiKey}`)
        .matchHeader("X-Propelauth-url", AUTH_HOSTNAME)
        .reply(
            200,
            JSON.stringify({
                verifier_key_pem: publicKey,
            })
        )

    return { privateKey, apiKey, scope }
}

async function setupErrorTokenVerificationMetadataEndpoint(statusCode: number) {
    const apiKey = randomString()

    const scope = nock(BASE_API_URL)
        .get("/api/v1/token_verification_metadata")
        .matchHeader("X-Propelauth-url", AUTH_HOSTNAME)
        .matchHeader("authorization", `Bearer ${apiKey}`)
        .reply(statusCode)

    return { apiKey, scope }
}

async function createAccessToken({
    internalUser,
    privateKey,
    expiresIn,
    issuer,
}: CreateAccessTokenArgs): Promise<string> {
    const accessToken = await new jose.SignJWT(internalUser)
        .setProtectedHeader({ alg: ALGO })
        .setIssuer(issuer ? issuer : AUTH_URL)
        .setExpirationTime(expiresIn ? expiresIn : "1d")
        .sign(createPrivateKey(privateKey))
    return accessToken
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
        org_role_structure: OrgRoleStructure.SingleRole,
        user_role: "Admin",
        inherited_user_roles_plus_current_role: ["Admin", "Member"],
        user_permissions: ["read", "write"],
        additional_roles: [],
    }
}

interface CreateAccessTokenArgs {
    internalUser: InternalUser
    privateKey: string
    expiresIn?: string
    issuer?: string
}
