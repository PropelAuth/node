import { createPrivateKey, generateKeyPair } from "crypto"
import * as jose from "jose"
import nock from "nock"
import { v4 as uuid } from "uuid"
import { initBaseAuth } from "../src"
import { TokenVerificationMetadata } from "../src/api/tokenVerificationMetadata"
import { RequiredOrgInfo } from "../src/auth"
import { ForbiddenException, UnauthorizedException, UnexpectedException } from "../src/exceptions"
import { InternalOrgMemberInfo, InternalUser, OrgMemberInfo, toUser, User } from "../src/user"
import { parseSnakeCaseToCamelCase } from "../src/utils"

const AUTH_URL = "https://auth.example.com"
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
            },
            "4ca20d17-5021-4d62-8b3d-148214fa8d6d": {
                org_id: "4ca20d17-5021-4d62-8b3d-148214fa8d6d",
                org_name: "orgB",
                org_metadata: { orgdata_b: "orgvalue_b" },
                url_safe_org_name: "orgb",
                user_role: "Admin",
                inherited_user_roles_plus_current_role: ["Admin", "Member"],
                user_permissions: [],
            },
            "15a31d0c-d284-4e7b-80a2-afb23f939cc3": {
                org_id: "15a31d0c-d284-4e7b-80a2-afb23f939cc3",
                org_name: "orgC",
                org_metadata: { orgdata_c: "orgvalue_c" },
                url_safe_org_name: "orgc",
                user_role: "Member",
                inherited_user_roles_plus_current_role: ["Member"],
                user_permissions: [],
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
        username: "easteregg",
        legacy_user_id: "something",
    }
    const user: User = {
        userId: "cbf064e2-edaa-4d35-b413-a8d857329c12",
        email: "easteregg@propelauth.com",
        username: "easteregg",
        legacyUserId: "something",
        loginMethod: { loginMethod: "unknown" },
    }
    expect(toUser(internalUser)).toEqual(user)
})

test("toUser converts login_method correctly", async () => {
    const internalUser: InternalUser = {
        user_id: "cbf064e2-edaa-4d35-b413-a8d857329c12",
        email: "easteregg@propelauth.com",
        username: "easteregg",
        legacy_user_id: "something",
        login_method: { login_method: "saml_sso", org_id: "someOrgId", provider: "Okta" },
    }
    const user: User = {
        userId: "cbf064e2-edaa-4d35-b413-a8d857329c12",
        email: "easteregg@propelauth.com",
        username: "easteregg",
        legacyUserId: "something",
        loginMethod: { loginMethod: "saml_sso", orgId: "someOrgId", provider: "Okta" },
    }
    expect(toUser(internalUser)).toEqual(user)
})

test("parseSnakeCaseToCamelCase converts correctly", async () => {
    const snakeCase = {
        user_id: "cbf064e2-edaa-4d35-b413-a8d857329c12",
        email: "easteregg@propelauth.com",
        first_name: "easter",
        org_id_to_org_member_info: {
            "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a": {
                org_id: "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a",
                org_name: "orgA",
                org_metadata: { orgdata_a: "orgvalue_a" },
            },
        },
        login_method: { login_method: "password" },
    }
    const camelCase = {
        userId: "cbf064e2-edaa-4d35-b413-a8d857329c12",
        email: "easteregg@propelauth.com",
        firstName: "easter",
        orgIdToOrgMemberInfo: {
            "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a": {
                orgId: "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a",
                orgName: "orgA",
                orgMetadata: { orgdata_a: "orgvalue_a" },
            },
        },
        loginMethod: { loginMethod: "password" },
    }

    expect(parseSnakeCaseToCamelCase(JSON.stringify(snakeCase))).toEqual(camelCase)
})

test("parseSnakeCaseToCamelCase adds functions to orgMemberInfo", async () => {
    const snakeCase = {
        user_id: "cbf064e2-edaa-4d35-b413-a8d857329c12",
        email: "easteregg@propelauth.com",
        first_name: "easter",
        org_id_to_org_member_info: {
            "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a": {
                org_id: "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a",
                org_name: "orgA",
                org_metadata: { orgdata_a: "orgvalue_a" },
                url_safe_org_name: "orga",
                user_role: "Admin",
                inherited_user_roles_plus_current_role: ["Admin", "Member"],
                user_permissions: ["read", "write"],
            },
        },
    }

    const camelCase = parseSnakeCaseToCamelCase(JSON.stringify(snakeCase))
    const orgMemberInfo = camelCase.orgIdToOrgMemberInfo["99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a"]
    expect(orgMemberInfo.isRole("Admin")).toEqual(true)
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

test("validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole works with miniumumRole", async () => {
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

    const scope = nock(AUTH_URL)
        .get("/api/v1/token_verification_metadata")
        .matchHeader("authorization", `Bearer ${apiKey}`)
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

    const scope = nock(AUTH_URL)
        .get("/api/v1/token_verification_metadata")
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
        user_role: "Admin",
        inherited_user_roles_plus_current_role: ["Admin", "Member"],
        user_permissions: ["read", "write"],
    }
}

interface CreateAccessTokenArgs {
    internalUser: InternalUser
    privateKey: string
    expiresIn?: string
    issuer?: string
}
