import {generateKeyPair} from "crypto"
import jwt from "jsonwebtoken"
import nock from "nock"
import {v4 as uuid} from "uuid"
import {initBaseAuth, User} from "../src"
import {InternalOrgMemberInfo, InternalUser, toUser, UserRole} from "../src/user"
import {TokenVerificationMetadata} from "../src/api"
import UnauthorizedException from "../src/UnauthorizedException";
import UnexpectedException from "../src/UnexpectedException";
import ForbiddenException from "../src/ForbiddenException";

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
    const {apiKey, privateKey} = await setupTokenVerificationMetadataEndpoint()
    const {validateAccessTokenAndGetUser} = initBaseAuth({authUrl: AUTH_URL + "/", apiKey})

    const internalUser = randomInternalUser()
    const accessToken = createAccessToken({internalUser, privateKey})

    const authHeader = `Bearer ${accessToken}`

    const user = await validateAccessTokenAndGetUser(authHeader)
    expect(user).toEqual(toUser(internalUser))
    expect(nock.isDone()).toBe(true)
})

test("when manualTokenVerificationMetadata is specified, no fetch is made", async () => {
    // Never setup the token verification endpoint
    const {privateKey, publicKey} = await generateRsaKeyPair()
    const tokenVerificationMetadata: TokenVerificationMetadata = {
        issuer: AUTH_URL,
        verifierKey: publicKey,
    };
    const {validateAccessTokenAndGetUser} = initBaseAuth({
        authUrl: AUTH_URL + "/",
        apiKey: "irrelevant api key for this test",
        manualTokenVerificationMetadata: tokenVerificationMetadata,
    })

    const internalUser = randomInternalUser()
    const accessToken = createAccessToken({internalUser, privateKey})

    const authHeader = `Bearer ${accessToken}`

    const user = await validateAccessTokenAndGetUser(authHeader)
    expect(user).toEqual(toUser(internalUser))
    expect(nock.isDone()).toBe(true)
})


test("validateAccessTokenAndGetUser rejects expired access tokens", async () => {
    jest.useFakeTimers("modern")
    const {apiKey, privateKey} = await setupTokenVerificationMetadataEndpoint()
    const {validateAccessTokenAndGetUser} = initBaseAuth({authUrl: AUTH_URL + "/", apiKey})

    const internalUser = randomInternalUser()
    const accessToken = createAccessToken({internalUser, expiresIn: "30m", privateKey})

    // 31 minutes
    jest.advanceTimersByTime(1000 * 60 * 31)

    const authHeader = `Bearer ${accessToken}`

    await expect(validateAccessTokenAndGetUser(authHeader))
        .rejects
        .toThrow(UnauthorizedException)

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUser rejects invalid access tokens", async () => {
    const {apiKey} = await setupTokenVerificationMetadataEndpoint()
    const {validateAccessTokenAndGetUser} = initBaseAuth({authUrl: AUTH_URL, apiKey})

    const accessToken = "invalid"
    const authHeader = `Bearer ${accessToken}`

    await expect(validateAccessTokenAndGetUser(authHeader))
        .rejects
        .toThrow(UnauthorizedException);

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUser rejects missing authorization header", async () => {
    const {apiKey} = await setupTokenVerificationMetadataEndpoint()
    const {validateAccessTokenAndGetUser} = initBaseAuth({authUrl: AUTH_URL, apiKey})

    await expect(validateAccessTokenAndGetUser(undefined))
        .rejects
        .toThrow(UnauthorizedException)


    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUser fails with incorrect apiKey", async () => {
    const {apiKey} = await setupErrorTokenVerificationMetadataEndpoint(401)
    const {validateAccessTokenAndGetUser} = initBaseAuth({authUrl: AUTH_URL, apiKey: apiKey})

    await expect(validateAccessTokenAndGetUser("irrelevant"))
        .rejects
        .toThrow(UnexpectedException)

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUser fails with incorrect issuer", async () => {
    const {apiKey, privateKey} = await setupTokenVerificationMetadataEndpoint()
    const {validateAccessTokenAndGetUser} = initBaseAuth({authUrl: AUTH_URL, apiKey})

    const internalUser = randomInternalUser()
    const accessToken = createAccessToken({internalUser, privateKey, issuer: "bad"})

    const authHeader = `Bearer ${accessToken}`

    await expect(validateAccessTokenAndGetUser(authHeader))
        .rejects
        .toThrow(UnauthorizedException)

    expect(nock.isDone()).toBe(true)
})

test("toUser converts correctly with orgs", async () => {
    const internalUser: InternalUser = {
        user_id: "cbf064e2-edaa-4d35-b413-a8d857329c12",
        org_id_to_org_member_info: {
            "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a": {
                org_id: "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a",
                org_name: "orgA",
                user_role: "Owner",
            },
            "4ca20d17-5021-4d62-8b3d-148214fa8d6d": {
                org_id: "4ca20d17-5021-4d62-8b3d-148214fa8d6d",
                org_name: "orgB",
                user_role: "Admin",
            },
            "15a31d0c-d284-4e7b-80a2-afb23f939cc3": {
                org_id: "15a31d0c-d284-4e7b-80a2-afb23f939cc3",
                org_name: "orgC",
                user_role: "Member",
            },
        },
    }
    const user: User = {
        userId: "cbf064e2-edaa-4d35-b413-a8d857329c12",
        orgIdToOrgMemberInfo: {
            "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a": {
                orgId: "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a",
                orgName: "orgA",
                userRole: UserRole.Owner,
            },
            "4ca20d17-5021-4d62-8b3d-148214fa8d6d": {
                orgId: "4ca20d17-5021-4d62-8b3d-148214fa8d6d",
                orgName: "orgB",
                userRole: UserRole.Admin,
            },
            "15a31d0c-d284-4e7b-80a2-afb23f939cc3": {
                orgId: "15a31d0c-d284-4e7b-80a2-afb23f939cc3",
                orgName: "orgC",
                userRole: UserRole.Member,
            },
        },
    }
    expect(toUser(internalUser)).toEqual(user)
})

test("toUser converts correctly without orgs", async () => {
    const internalUser: InternalUser = {
        user_id: "cbf064e2-edaa-4d35-b413-a8d857329c12",
    }
    const user: User = {
        userId: "cbf064e2-edaa-4d35-b413-a8d857329c12",
    }
    expect(toUser(internalUser)).toEqual(user)
})

test("validateAccessTokenAndGetUserWithOrg get user and org for extracted org", async () => {
    const {apiKey, privateKey} = await setupTokenVerificationMetadataEndpoint()
    const {validateAccessTokenAndGetUserWithOrg} = initBaseAuth({authUrl: AUTH_URL, apiKey})

    const orgMemberInfo = randomOrg()
    const internalUser: InternalUser = {
        user_id: uuid(),
        org_id_to_org_member_info: {
            [orgMemberInfo.org_id]: orgMemberInfo,
        },
    }
    const accessToken = createAccessToken({internalUser, privateKey})

    const userAndOrgMemberInfo = await validateAccessTokenAndGetUserWithOrg(`Bearer ${accessToken}`, orgMemberInfo.org_id)

    const user = toUser(internalUser)
    expect(userAndOrgMemberInfo.user).toEqual(user)
    expect(userAndOrgMemberInfo.orgMemberInfo).toEqual(user.orgIdToOrgMemberInfo && user.orgIdToOrgMemberInfo[orgMemberInfo.org_id])
    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUserWithOrg fails for valid access token but unknown org", async () => {
    const {apiKey, privateKey} = await setupTokenVerificationMetadataEndpoint()
    const {validateAccessTokenAndGetUserWithOrg} = initBaseAuth({authUrl: AUTH_URL, apiKey})

    const internalUser: InternalUser = {
        user_id: uuid(),
    }
    const accessToken = createAccessToken({internalUser, privateKey})

    await expect(validateAccessTokenAndGetUserWithOrg(`Bearer ${accessToken}`, uuid()))
        .rejects
        .toThrow(ForbiddenException)

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUserWithOrg fails for invalid access token", async () => {
    const {apiKey} = await setupTokenVerificationMetadataEndpoint()
    const {validateAccessTokenAndGetUserWithOrg} = initBaseAuth({authUrl: AUTH_URL, apiKey})

    await expect(validateAccessTokenAndGetUserWithOrg(undefined, uuid()))
        .rejects
        .toThrow(UnauthorizedException)

    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUserWithOrg works with minimumRequiredRole", async () => {
    const {apiKey, privateKey} = await setupTokenVerificationMetadataEndpoint()
    const {validateAccessTokenAndGetUserWithOrg} = initBaseAuth({authUrl: AUTH_URL, apiKey})

    const orgMemberInfo = {
        org_id: uuid(),
        org_name: randomString(),
        user_role: "Admin",
    }
    const internalUser: InternalUser = {
        user_id: uuid(),
        org_id_to_org_member_info: {
            [orgMemberInfo.org_id]: orgMemberInfo,
        },
    }
    const user = toUser(internalUser)
    const accessToken = createAccessToken({internalUser, privateKey})

    const rolesThatShouldSucceed = new Set([UserRole.Admin, UserRole.Member])
    for (let role of [UserRole.Owner, UserRole.Admin, UserRole.Member]) {
        const authHeader = `Bearer ${accessToken}`

        if (rolesThatShouldSucceed.has(role)) {
            const userAndOrgMemberInfo = await validateAccessTokenAndGetUserWithOrg(authHeader, orgMemberInfo.org_id, role)
            expect(userAndOrgMemberInfo.user).toEqual(user)
            expect(userAndOrgMemberInfo.orgMemberInfo).toEqual(user.orgIdToOrgMemberInfo && user.orgIdToOrgMemberInfo[orgMemberInfo.org_id])
        } else {
            await expect(validateAccessTokenAndGetUserWithOrg(authHeader, orgMemberInfo.org_id, role))
                .rejects
                .toThrow(ForbiddenException)
        }
    }
    expect(nock.isDone()).toBe(true)
})

test("validateAccessTokenAndGetUserWithOrg fails with invalid minimumRequiredRole", async () => {
    const {apiKey, privateKey} = await setupTokenVerificationMetadataEndpoint()
    const {validateAccessTokenAndGetUserWithOrg} = initBaseAuth({authUrl: AUTH_URL, apiKey})

    const orgMemberInfo = {
        org_id: uuid(),
        org_name: randomString(),
        user_role: "Admin",
    }
    const internalUser: InternalUser = {
        user_id: uuid(),
        org_id_to_org_member_info: {
            [orgMemberInfo.org_id]: orgMemberInfo,
        },
    }
    const accessToken = createAccessToken({internalUser, privateKey})

    // @ts-ignore
    await expect(validateAccessTokenAndGetUserWithOrg(`Bearer ${accessToken}`, orgMemberInfo.org_id, "js problems"))
        .rejects
        .toThrow(UnexpectedException)

    expect(nock.isDone()).toBe(true)
})

async function setupTokenVerificationMetadataEndpoint() {
    const {publicKey, privateKey} = await generateRsaKeyPair()
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

    return {privateKey, apiKey, scope}
}

async function setupErrorTokenVerificationMetadataEndpoint(statusCode: number) {
    const apiKey = randomString()

    const scope = nock(AUTH_URL)
        .get("/api/v1/token_verification_metadata")
        .matchHeader("authorization", `Bearer ${apiKey}`)
        .reply(statusCode)

    return {apiKey, scope}
}

function createAccessToken({internalUser, privateKey, expiresIn, issuer}: CreateAccessTokenArgs): string {
    return jwt.sign(internalUser, privateKey, {
        algorithm: ALGO,
        expiresIn: expiresIn ? expiresIn : "1d",
        issuer: issuer ? issuer : AUTH_URL,
    })
}

async function generateRsaKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
    return new Promise((resolve, reject) => {
        generateKeyPair("rsa", {modulusLength: 1024}, (err, publicKey, privateKey) => {
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
    return {
        org_id: uuid(),
        org_name: randomString(),
        user_role: choose(["Owner", "Admin", "Member"]),
    }
}

function choose<T>(choices: T[]) {
    const index = Math.floor(Math.random() * choices.length)
    return choices[index]
}

interface CreateAccessTokenArgs {
    internalUser: InternalUser
    privateKey: string
    expiresIn?: string
    issuer?: string
}
