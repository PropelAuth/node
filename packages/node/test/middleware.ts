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
import { createPrivateKey, createPublicKey, generateKeyPair } from "crypto"
import * as jose from "jose"
import nock from "nock"
import { v4 as uuid } from "uuid"
import { initBaseAuth } from "../src"
import { RequiredOrgInfo } from "../src/auth"

const AUTH_HOSTNAME = "auth.example.com"
const AUTH_URL = "https://" + AUTH_HOSTNAME
const ALGO = "RS256"
const JWKS_PATH = "/.well-known/jwks.json"

afterEach(() => {
    jest.useRealTimers()
    nock.cleanAll()
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
    const { apiKey, privateKey, kid } = await setupJwksEndpoint()
    const { validateAccessTokenAndGetUser } = initBaseAuth({ authUrl: AUTH_URL + "/", apiKey })

    const internalUser = randomInternalUser()
    const accessToken = await createAccessToken({ internalUser, privateKey, kid })

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
    const { apiKey, privateKey, kid } = await setupJwksEndpoint()
    const { validateAccessTokenAndGetUser } = initBaseAuth({ authUrl: AUTH_URL + "/", apiKey })

    const internalUser = randomInternalUser()
    const accessToken = await createAccessToken({ internalUser, expiresIn: "1 minute ago", privateKey, kid })

    const authHeader = `Bearer ${accessToken}`

    await expect(validateAccessTokenAndGetUser(authHeader)).rejects.toThrow(UnauthorizedException)

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUser rejects invalid access tokens", async () => {
    const { apiKey } = await setupJwksEndpoint()
    const { validateAccessTokenAndGetUser } = initBaseAuth({ authUrl: AUTH_URL, apiKey })

    const accessToken = "invalid"
    const authHeader = `Bearer ${accessToken}`

    await expect(validateAccessTokenAndGetUser(authHeader)).rejects.toThrow(UnauthorizedException)

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUser rejects missing authorization header", async () => {
    const { apiKey } = await setupJwksEndpoint()
    const { validateAccessTokenAndGetUser } = initBaseAuth({ authUrl: AUTH_URL, apiKey })

    await expect(validateAccessTokenAndGetUser(undefined)).rejects.toThrow(UnauthorizedException)

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUser fails when the JWKS endpoint errors", async () => {
    const { privateKey } = await generateRsaKeyPair()
    // Once for the eager fetch at init, once for the retry on the first request
    const scope = nock(AUTH_URL).get(JWKS_PATH).times(2).reply(500)
    const { validateAccessTokenAndGetUser } = initBaseAuth({ authUrl: AUTH_URL, apiKey: randomString() })

    const accessToken = await createAccessToken({ internalUser: randomInternalUser(), privateKey, kid: "any" })

    await expect(validateAccessTokenAndGetUser(`Bearer ${accessToken}`)).rejects.toThrow()

    expect(scope.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUser rejects tokens signed by a key that is not in the JWKS", async () => {
    const { apiKey } = await setupJwksEndpoint()
    const { privateKey: otherPrivateKey } = await generateRsaKeyPair()
    const { validateAccessTokenAndGetUser } = initBaseAuth({ authUrl: AUTH_URL, apiKey })

    const accessToken = await createAccessToken({
        internalUser: randomInternalUser(),
        privateKey: otherPrivateKey,
        kid: "unknown",
    })

    await expect(validateAccessTokenAndGetUser(`Bearer ${accessToken}`)).rejects.toThrow(UnauthorizedException)

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUser picks the right key by kid when the JWKS holds two", async () => {
    const current = await generateRsaKeyPair()
    const previous = await generateRsaKeyPair()
    setupJwksEndpointWithKeys([
        { kid: "current", publicKey: current.publicKey },
        { kid: "previous", publicKey: previous.publicKey },
    ])
    const { validateAccessTokenAndGetUser } = initBaseAuth({ authUrl: AUTH_URL, apiKey: randomString() })

    const userA = randomInternalUser()
    const userB = randomInternalUser()
    const tokenFromCurrent = await createAccessToken({
        internalUser: userA,
        privateKey: current.privateKey,
        kid: "current",
    })
    const tokenFromPrevious = await createAccessToken({
        internalUser: userB,
        privateKey: previous.privateKey,
        kid: "previous",
    })

    expect(await validateAccessTokenAndGetUser(`Bearer ${tokenFromCurrent}`)).toEqual(toUser(userA))
    expect(await validateAccessTokenAndGetUser(`Bearer ${tokenFromPrevious}`)).toEqual(toUser(userB))

    expect(nock.isDone()).toBe(true)
})

test("manualTokenVerificationMetadata accepts tokens signed by the fallback key", async () => {
    const current = await generateRsaKeyPair()
    const previous = await generateRsaKeyPair()
    const tokenVerificationMetadata: TokenVerificationMetadata = {
        issuer: AUTH_URL,
        verifierKey: current.publicKey,
        fallbackVerifierKey: previous.publicKey,
    }
    const { validateAccessTokenAndGetUser } = initBaseAuth({
        authUrl: AUTH_URL,
        apiKey: randomString(),
        manualTokenVerificationMetadata: tokenVerificationMetadata,
    })

    const userA = randomInternalUser()
    const userB = randomInternalUser()
    const tokenFromCurrent = await createAccessToken({ internalUser: userA, privateKey: current.privateKey })
    const tokenFromPrevious = await createAccessToken({ internalUser: userB, privateKey: previous.privateKey })

    expect(await validateAccessTokenAndGetUser(`Bearer ${tokenFromCurrent}`)).toEqual(toUser(userA))
    expect(await validateAccessTokenAndGetUser(`Bearer ${tokenFromPrevious}`)).toEqual(toUser(userB))
})

test("manualTokenVerificationMetadata rejects tokens signed by neither key", async () => {
    const current = await generateRsaKeyPair()
    const previous = await generateRsaKeyPair()
    const other = await generateRsaKeyPair()
    const { validateAccessTokenAndGetUser } = initBaseAuth({
        authUrl: AUTH_URL,
        apiKey: randomString(),
        manualTokenVerificationMetadata: {
            issuer: AUTH_URL,
            verifierKey: current.publicKey,
            fallbackVerifierKey: previous.publicKey,
        },
    })

    const accessToken = await createAccessToken({ internalUser: randomInternalUser(), privateKey: other.privateKey })

    await expect(validateAccessTokenAndGetUser(`Bearer ${accessToken}`)).rejects.toThrow(UnauthorizedException)
})

test("manualTokenVerificationMetadata reports expiry for an expired token signed by the fallback key", async () => {
    const current = await generateRsaKeyPair()
    const previous = await generateRsaKeyPair()
    const { validateAccessTokenAndGetUser } = initBaseAuth({
        authUrl: AUTH_URL,
        apiKey: randomString(),
        manualTokenVerificationMetadata: {
            issuer: AUTH_URL,
            verifierKey: current.publicKey,
            fallbackVerifierKey: previous.publicKey,
        },
    })

    const accessToken = await createAccessToken({
        internalUser: randomInternalUser(),
        privateKey: previous.privateKey,
        expiresIn: "1 minute ago",
    })

    await expect(validateAccessTokenAndGetUser(`Bearer ${accessToken}`)).rejects.toThrow(/"exp"/)
})

test("validateAccessTokenAndGetUser fails with incorrect issuer", async () => {
    const { apiKey, privateKey, kid } = await setupJwksEndpoint()
    const { validateAccessTokenAndGetUser } = initBaseAuth({ authUrl: AUTH_URL, apiKey })

    const internalUser = randomInternalUser()
    const accessToken = await createAccessToken({ internalUser, privateKey, issuer: "bad" })

    const authHeader = `Bearer ${accessToken}`

    await expect(validateAccessTokenAndGetUser(authHeader)).rejects.toThrow(UnauthorizedException)

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole get user and org for extracted org", async () => {
    const { apiKey, privateKey, kid } = await setupJwksEndpoint()
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
    const accessToken = await createAccessToken({ internalUser, privateKey, kid })

    const userAndOrgMemberInfo = await validateAccessTokenAndGetUserWithOrgInfo(`Bearer ${accessToken}`, orgInfo)

    const user = toUser(internalUser)
    expect(userAndOrgMemberInfo.user).toEqual(user)
    expect(userAndOrgMemberInfo.orgMemberInfo).toEqual(
        user.orgIdToOrgMemberInfo && user.orgIdToOrgMemberInfo[orgMemberInfo.org_id]
    )
    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole fails for valid access token but unknown org", async () => {
    const { apiKey, privateKey, kid } = await setupJwksEndpoint()
    const { validateAccessTokenAndGetUserWithOrgInfo } = initBaseAuth({ authUrl: AUTH_URL, apiKey })

    const internalUser: InternalUser = {
        user_id: uuid(),
        email: uuid(),
    }
    const orgInfo: RequiredOrgInfo = {
        orgId: uuid(),
        orgName: "orgName",
    }
    const accessToken = await createAccessToken({ internalUser, privateKey, kid })

    await expect(validateAccessTokenAndGetUserWithOrgInfo(`Bearer ${accessToken}`, orgInfo)).rejects.toThrow(
        ForbiddenException
    )

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole fails for invalid access token", async () => {
    const { apiKey } = await setupJwksEndpoint()
    const { validateAccessTokenAndGetUserWithOrgInfo } = initBaseAuth({ authUrl: AUTH_URL, apiKey })

    const orgInfo: RequiredOrgInfo = {
        orgId: uuid(),
        orgName: "orgName",
    }

    await expect(validateAccessTokenAndGetUserWithOrgInfo(undefined, orgInfo)).rejects.toThrow(UnauthorizedException)

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole works with minimumRole", async () => {
    const { apiKey, privateKey, kid } = await setupJwksEndpoint()
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
    const accessToken = await createAccessToken({ internalUser, privateKey, kid })

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
    const { apiKey, privateKey, kid } = await setupJwksEndpoint()
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
    const accessToken = await createAccessToken({ internalUser, privateKey, kid })

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
    const { apiKey, privateKey, kid } = await setupJwksEndpoint()
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
    const accessToken = await createAccessToken({ internalUser, privateKey, kid })

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
    const { apiKey, privateKey, kid } = await setupJwksEndpoint()
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
    const accessToken = await createAccessToken({ internalUser, privateKey, kid })

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

async function setupJwksEndpoint() {
    const { publicKey, privateKey } = await generateRsaKeyPair()
    const apiKey = randomString()
    const kid = randomString()
    const scope = setupJwksEndpointWithKeys([{ kid, publicKey }])
    return { privateKey, apiKey, kid, scope }
}

/** Serves one JWKS response containing the given SPKI PEM public keys */
function setupJwksEndpointWithKeys(publicKeys: { kid: string; publicKey: string }[]) {
    const keys = publicKeys.map(({ kid, publicKey }) => ({
        ...createPublicKey(publicKey).export({ format: "jwk" }),
        kid,
        alg: ALGO,
        use: "sig",
    }))
    return nock(AUTH_URL).get(JWKS_PATH).reply(200, JSON.stringify({ keys }))
}

async function createAccessToken({
    internalUser,
    privateKey,
    expiresIn,
    issuer,
    kid,
}: CreateAccessTokenArgs): Promise<string> {
    const accessToken = await new jose.SignJWT(internalUser)
        .setProtectedHeader(kid ? { alg: ALGO, kid } : { alg: ALGO })
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
    kid?: string
}
