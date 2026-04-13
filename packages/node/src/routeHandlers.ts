import { randomBytes } from "crypto"
import { User, UserClass } from "@propelauth/node-apis"

// Cookie names used for SSR auth
export const ACCESS_TOKEN_COOKIE_NAME = "__pa_at_"
export const REFRESH_TOKEN_COOKIE_NAME = "__pa_rt"
export const ACTIVE_ORG_ID_COOKIE_NAME = "__pa_active_org_id"
export const RETURN_TO_PATH_COOKIE_NAME = "__pa_return_to_path"
export const STATE_COOKIE_NAME = "__pa_state"

// Max bytes for a cookie value, leaving headroom for cookie attributes
const MAX_COOKIE_VALUE_SIZE = 4000

const LOGIN_PATH = "/api/auth/login"

type ParsedAuthCookies = {
    accessToken?: string
    // Number of __pa_at_N cookies present in the request. Used to clear stale
    // parts when the new token fits in fewer chunks. Defaults to 1.
    accessTokenCookieCount?: number
    refreshToken?: string
    activeOrgId?: string
    returnToPath?: string
    state?: string
}

export type AuthRequestParams = {
    method: string
    path: string
    queryParams: Record<string, string>
    body?: unknown
    cookies: Record<string, string>
    redirectUri: string
    frontendDomain: string
    sameSiteCookieOverride?: "none" | "lax" | "strict"
    getDefaultActiveOrgId?: (params: AuthRequestParams, user: UserClass) => string | undefined
}

type InternalAuthRequestParams = AuthRequestParams & { parsedCookies: ParsedAuthCookies }

function parseCookies(rawCookies: Record<string, string>): ParsedAuthCookies {
    const { accessToken, accessTokenCookieCount } = getAccessTokenFromCookies(rawCookies)
    return {
        accessToken,
        accessTokenCookieCount,
        refreshToken: rawCookies[REFRESH_TOKEN_COOKIE_NAME],
        activeOrgId: rawCookies[ACTIVE_ORG_ID_COOKIE_NAME],
        returnToPath: rawCookies[RETURN_TO_PATH_COOKIE_NAME],
        state: rawCookies[STATE_COOKIE_NAME],
    }
}

export type AuthResponse = {
    status: number
    headers: Record<string, string | string[]>
    body?: string
}

export function createRouteHandler(
    authUrlOrigin: string,
    integrationApiKey: string,
    validateAccessTokenAndGetUser: (authorizationHeader?: string) => Promise<User>,
    validateAccessTokenAndGetUserClass: (authorizationHeader?: string) => Promise<UserClass>
) {
    async function handleAuthRequest(params: AuthRequestParams): Promise<AuthResponse> {
        const { path } = params
        const internalParams: InternalAuthRequestParams = { ...params, parsedCookies: parseCookies(params.cookies) }

        // Strip the /api/auth prefix to get the sub-path
        const subPath = path.replace(/^\/api\/auth/, "") || "/"

        if (subPath === "/callback") {
            return handleCallback(internalParams, authUrlOrigin, integrationApiKey, validateAccessTokenAndGetUserClass)
        }

        if (subPath === "/login") {
            return handleLogin(internalParams, authUrlOrigin)
        }

        if (subPath === "/userinfo") {
            return handleUserinfo(internalParams, authUrlOrigin, integrationApiKey, validateAccessTokenAndGetUser)
        }

        if (subPath === "/set-active-org" && params.method.toUpperCase() === "POST") {
            return handleSetActiveOrg(internalParams, authUrlOrigin, integrationApiKey, validateAccessTokenAndGetUser)
        }

        if (subPath === "/logout") {
            if (params.method.toUpperCase() === "GET") {
                return handleLogoutGet(internalParams, authUrlOrigin, integrationApiKey)
            } else if (params.method.toUpperCase() === "POST") {
                return handleLogoutPost(internalParams, authUrlOrigin, integrationApiKey)
            }
        }

        return { status: 404, headers: {}, body: "Not found" }
    }

    return { handleAuthRequest }
}

function handleLogin(params: InternalAuthRequestParams, authUrlOrigin: string): AuthResponse {
    return handleLoginOrSignup(params, authUrlOrigin, false)
}

function handleLoginOrSignup(params: InternalAuthRequestParams, authUrlOrigin: string, isSignup: boolean): AuthResponse {
    const { queryParams, redirectUri, sameSiteCookieOverride } = params
    const sameSite = sameSiteCookieOverride ?? "lax"
    const returnToPath = queryParams["return_to_path"]
    const state = randomBytes(32).toString("hex")

    const authorizeParams = new URLSearchParams({
        ...queryParams,
        redirect_uri: redirectUri,
        state,
        signup: isSignup ? "true" : "false",
    })
    const authorizeUrl = `${authUrlOrigin}/propelauth/ssr/authorize?${authorizeParams.toString()}`

    const setCookies: string[] = [cookieHeader(STATE_COOKIE_NAME, state, sameSite)]

    if (returnToPath) {
        if (returnToPath.startsWith("/")) {
            setCookies.push(
                `${RETURN_TO_PATH_COOKIE_NAME}=${returnToPath}; Path=/; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=600`
            )
        } else {
            console.warn("return_to_path must start with /")
        }
    }

    return {
        status: 302,
        headers: {
            Location: authorizeUrl,
            "Set-Cookie": setCookies,
        },
    }
}

async function handleCallback(
    params: InternalAuthRequestParams,
    authUrlOrigin: string,
    integrationApiKey: string,
    validateAccessTokenAndGetUserClass: (authorizationHeader?: string) => Promise<UserClass>
): Promise<AuthResponse> {
    const { queryParams, parsedCookies: cookies, redirectUri, frontendDomain, sameSiteCookieOverride, getDefaultActiveOrgId } = params
    const sameSite = sameSiteCookieOverride ?? "lax"

    const oauthState = cookies.state
    if (!oauthState || oauthState.length !== 64) {
        return { status: 302, headers: { Location: LOGIN_PATH } }
    }

    const state = queryParams["state"]
    const code = queryParams["code"]
    if (state !== oauthState) {
        return { status: 302, headers: { Location: LOGIN_PATH } }
    }

    const tokenResponse = await fetch(`${authUrlOrigin}/propelauth/ssr/token`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${integrationApiKey}`,
        },
        body: JSON.stringify({ redirect_uri: redirectUri, code }),
    })

    if (tokenResponse.status === 200) {
        const data = (await tokenResponse.json()) as { access_token: string; refresh_token: string }
        const accessToken = data.access_token
        const returnToPath = frontendDomain + (cookies.returnToPath ?? "")

        const currentActiveOrgId = cookies.activeOrgId
        const user = await validateAccessTokenAndGetUserClass("Bearer " + accessToken)
        const isUserInCurrentActiveOrg = Boolean(currentActiveOrgId && user.getOrg(currentActiveOrgId))

        let activeOrgId: string | undefined
        if (isUserInCurrentActiveOrg) {
            activeOrgId = currentActiveOrgId
        } else if (getDefaultActiveOrgId) {
            const candidateOrgId = getDefaultActiveOrgId(params, user)
            activeOrgId = candidateOrgId && user.getOrg(candidateOrgId) ? candidateOrgId : undefined
        }

        if (activeOrgId) {
            const refreshResult = await refreshTokenWithActiveOrg(
                authUrlOrigin,
                integrationApiKey,
                data.refresh_token,
                activeOrgId
            )

            if (refreshResult.error === "unexpected") {
                return { status: 500, headers: {}, body: "Unexpected error while setting active org" }
            } else if (refreshResult.error === "unauthorized") {
                console.error(
                    "Unauthorized error while setting active org. Your user may not have access to this org"
                )
                return { status: 401, headers: {}, body: "Unauthorized" }
            } else {
                return {
                    status: 302,
                    headers: {
                        Location: returnToPath,
                        "Set-Cookie": [
                            ...accessTokenCookieHeaders(refreshResult.access_token, sameSite, cookies.accessTokenCookieCount),
                            cookieHeader(REFRESH_TOKEN_COOKIE_NAME, refreshResult.refresh_token, sameSite),
                            cookieHeader(ACTIVE_ORG_ID_COOKIE_NAME, activeOrgId, sameSite),
                            clearCookieHeader(RETURN_TO_PATH_COOKIE_NAME, sameSite),
                            clearCookieHeader(STATE_COOKIE_NAME, sameSite)
                        ],
                    },
                }
            }
        }

        return {
            status: 302,
            headers: {
                Location: returnToPath,
                "Set-Cookie": [
                    ...accessTokenCookieHeaders(accessToken, sameSite, cookies.accessTokenCookieCount),
                    cookieHeader(REFRESH_TOKEN_COOKIE_NAME, data.refresh_token, sameSite),
                    clearCookieHeader(ACTIVE_ORG_ID_COOKIE_NAME, sameSite),
                    clearCookieHeader(RETURN_TO_PATH_COOKIE_NAME, sameSite),
                    clearCookieHeader(STATE_COOKIE_NAME, sameSite)
                ],
            },
        }
    } else if (tokenResponse.status === 401) {
        const firstFour = integrationApiKey.slice(0, 4)
        console.error(
            `Couldn't finish the login process for this user. This is most likely caused by an ` +
                `incorrect PROPELAUTH_API_KEY. Your API key starts with ${firstFour}... double check ` +
                `that that matches the API key in the PropelAuth dashboard for this environment.`
        )
        return { status: 500, headers: {}, body: "Unexpected error" }
    } else {
        return { status: 500, headers: {}, body: "Unexpected error" }
    }
}

async function handleUserinfo(
    params: InternalAuthRequestParams,
    authUrlOrigin: string,
    integrationApiKey: string,
    validateAccessTokenAndGetUser: (authorizationHeader?: string) => Promise<User>
): Promise<AuthResponse> {
    const { parsedCookies: cookies, sameSiteCookieOverride } = params
    const sameSite = sameSiteCookieOverride ?? "lax"
    const oldRefreshToken = cookies.refreshToken
    const activeOrgId = cookies.activeOrgId

    const clearAuthCookies401 = (): AuthResponse => ({
        status: 401,
        headers: {
            "Set-Cookie": [
                ...clearAccessTokenCookieHeaders(sameSite, cookies.accessTokenCookieCount),
                clearCookieHeader(REFRESH_TOKEN_COOKIE_NAME, sameSite),
                clearCookieHeader(ACTIVE_ORG_ID_COOKIE_NAME, sameSite),
            ],
        },
        body: "Unauthorized",
    })

    if (!oldRefreshToken) {
        return clearAuthCookies401()
    }

    const refreshResult = await refreshTokenWithActiveOrg(authUrlOrigin, integrationApiKey, oldRefreshToken, activeOrgId)
    if (refreshResult.error === "unexpected") {
        return { status: 500, headers: {}, body: "Unexpected error while refreshing access token" }
    } else if (refreshResult.error === "unauthorized") {
        return clearAuthCookies401()
    }

    const { access_token: accessToken, refresh_token: refreshToken } = refreshResult

    const userinfoResponse = await fetch(`${authUrlOrigin}/propelauth/oauth/userinfo`, {
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${accessToken}`,
        },
    })

    if (userinfoResponse.ok) {
        const user = await validateAccessTokenAndGetUser("Bearer " + accessToken)
        const body = JSON.stringify({
            userinfo: await userinfoResponse.json(),
            accessToken,
            impersonatorUserId: user.impersonatorUserId,
            activeOrgId,
        })
        return {
            status: 200,
            headers: {
                "Content-Type": "application/json",
                "Set-Cookie": [
                    ...accessTokenCookieHeaders(accessToken, sameSite, cookies.accessTokenCookieCount),
                    cookieHeader(REFRESH_TOKEN_COOKIE_NAME, refreshToken, sameSite),
                ],
            },
            body,
        }
    } else if (userinfoResponse.status === 401) {
        return clearAuthCookies401()
    } else {
        return { status: 500, headers: {} }
    }
}

async function handleSetActiveOrg(
    params: InternalAuthRequestParams,
    authUrlOrigin: string,
    integrationApiKey: string,
    validateAccessTokenAndGetUser: (authorizationHeader?: string) => Promise<User>
): Promise<AuthResponse> {
    const { parsedCookies: cookies, body, sameSiteCookieOverride } = params
    const sameSite = sameSiteCookieOverride ?? "lax"
    const oldRefreshToken = cookies.refreshToken
    const activeOrgId = (body as { org_id?: string })?.org_id

    if (!oldRefreshToken) {
        return {
            status: 401,
            headers: {
                "Set-Cookie": [clearCookieHeader(ACTIVE_ORG_ID_COOKIE_NAME, sameSite)],
            },
        }
    }

    if (!activeOrgId) {
        return { status: 400, headers: {} }
    }

    const refreshResult = await refreshTokenWithActiveOrg(authUrlOrigin, integrationApiKey, oldRefreshToken, activeOrgId)
    if (refreshResult.error === "unexpected") {
        return { status: 500, headers: {}, body: "Unexpected error while setting active org id" }
    } else if (refreshResult.error === "unauthorized") {
        return { status: 401, headers: {}, body: "Unauthorized" }
    }

    const { access_token: accessToken, refresh_token: refreshToken } = refreshResult

    const userinfoResponse = await fetch(`${authUrlOrigin}/propelauth/oauth/userinfo`, {
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${accessToken}`,
        },
    })

    if (userinfoResponse.ok) {
        const user = await validateAccessTokenAndGetUser("Bearer " + accessToken)
        const responseBody = JSON.stringify({
            userinfo: await userinfoResponse.json(),
            accessToken,
            impersonatorUserId: user.impersonatorUserId,
            activeOrgId,
        })
        return {
            status: 200,
            headers: {
                "Content-Type": "application/json",
                "Set-Cookie": [
                    ...accessTokenCookieHeaders(accessToken, sameSite, cookies.accessTokenCookieCount),
                    cookieHeader(REFRESH_TOKEN_COOKIE_NAME, refreshToken, sameSite),
                    cookieHeader(ACTIVE_ORG_ID_COOKIE_NAME, activeOrgId, sameSite),
                ],
            },
            body: responseBody,
        }
    } else if (userinfoResponse.status === 401) {
        return { status: 401, headers: {} }
    } else {
        return { status: 500, headers: {} }
    }
}

async function handleLogoutGet(
    params: InternalAuthRequestParams,
    authUrlOrigin: string,
    integrationApiKey: string
): Promise<AuthResponse> {
    const { parsedCookies: cookies, sameSiteCookieOverride } = params
    const sameSite = sameSiteCookieOverride ?? "lax"
    const refreshToken = cookies.refreshToken

    const clearCookiesRedirect = (): AuthResponse => ({
        status: 302,
        headers: {
            Location: "/",
            "Set-Cookie": [
                ...clearAccessTokenCookieHeaders(sameSite, cookies.accessTokenCookieCount),
                clearCookieHeader(REFRESH_TOKEN_COOKIE_NAME, sameSite),
                clearCookieHeader(ACTIVE_ORG_ID_COOKIE_NAME, sameSite),
            ],
        },
    })

    if (!refreshToken) {
        return clearCookiesRedirect()
    }

    const refreshResult = await refreshTokenWithActiveOrg(
        authUrlOrigin,
        integrationApiKey,
        refreshToken,
        cookies.activeOrgId
    )

    if (refreshResult.error === "unexpected") {
        console.error("Unexpected error while refreshing access token")
        return { status: 500, headers: {}, body: "Unexpected error" }
    } else if (refreshResult.error === "unauthorized") {
        return clearCookiesRedirect()
    } else {
        return { status: 302, headers: { Location: "/" } }
    }
}

async function handleLogoutPost(
    params: InternalAuthRequestParams,
    authUrlOrigin: string,
    integrationApiKey: string
): Promise<AuthResponse> {
    const { parsedCookies: cookies, sameSiteCookieOverride } = params
    const sameSite = sameSiteCookieOverride ?? "lax"
    const refreshToken = cookies.refreshToken

    const clearedResponse = (): AuthResponse => ({
        status: 200,
        headers: {
            "Content-Type": "application/json",
            "Set-Cookie": [
                ...clearAccessTokenCookieHeaders(sameSite, cookies.accessTokenCookieCount),
                clearCookieHeader(REFRESH_TOKEN_COOKIE_NAME, sameSite),
                clearCookieHeader(ACTIVE_ORG_ID_COOKIE_NAME, sameSite),
            ],
        },
        body: JSON.stringify({ redirect_to: "/" }),
    })

    if (!refreshToken) {
        return clearedResponse()
    }

    const response = await fetch(`${authUrlOrigin}/api/backend/v1/logout`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${integrationApiKey}`,
        },
        body: JSON.stringify({ refresh_token: refreshToken }),
    })

    if (!response.ok) {
        console.warn(`Unable to logout, clearing cookies and continuing anyway: ${response.status} ${response.statusText}`)
    }

    return clearedResponse()
}

type RefreshResult =
    | { error: "unexpected" }
    | { error: "unauthorized" }
    | { error: "none"; access_token: string; refresh_token: string }

async function refreshTokenWithActiveOrg(
    authUrlOrigin: string,
    integrationApiKey: string,
    refreshToken: string,
    activeOrgId?: string
): Promise<RefreshResult> {
    try {
        const queryParams = new URLSearchParams()
        if (activeOrgId) {
            queryParams.set("with_active_org_support", "true")
            queryParams.set("active_org_id", activeOrgId)
        }
        const url = `${authUrlOrigin}/api/backend/v1/refresh_token${activeOrgId ? `?${queryParams.toString()}` : ""}`

        const response = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${integrationApiKey}`,
            },
            body: JSON.stringify({ refresh_token: refreshToken }),
        })

        if (response.status === 200) {
            const data = (await response.json()) as { access_token: { access_token: string }; refresh_token: string }
            return { error: "none", access_token: data.access_token.access_token, refresh_token: data.refresh_token }
        } else if (response.status === 400 || response.status === 401) {
            return { error: "unauthorized" }
        } else {
            return { error: "unexpected" }
        }
    } catch {
        return { error: "unexpected" }
    }
}

// Reads all __pa_at_N cookies from a raw cookie map, concatenates them in order,
// and returns the values needed to populate AuthRequestCookies.
export function getAccessTokenFromCookies(rawCookies: Record<string, string>): {
    accessToken: string | undefined
    accessTokenCookieCount: number
} {
    const parts: string[] = []
    let index = 0
    while (rawCookies[`${ACCESS_TOKEN_COOKIE_NAME}${index}`] !== undefined) {
        parts.push(rawCookies[`${ACCESS_TOKEN_COOKIE_NAME}${index}`])
        index++
    }
    return {
        accessToken: parts.length > 0 ? parts.join("") : undefined,
        accessTokenCookieCount: parts.length,
    }
}

// Returns Set-Cookie headers for a (possibly chunked) access token. Chunks are named
// __pa_at_0, __pa_at_1, … Any parts beyond the new chunk count that existed in the
// previous session (prevCount) are cleared so stale cookies don't accumulate.
function accessTokenCookieHeaders(accessToken: string, sameSite: string, prevCount: number = 1): string[] {
    const headers: string[] = []
    let index = 0
    for (let offset = 0; offset < accessToken.length; offset += MAX_COOKIE_VALUE_SIZE, index++) {
        const chunk = accessToken.slice(offset, offset + MAX_COOKIE_VALUE_SIZE)
        headers.push(cookieHeader(`${ACCESS_TOKEN_COOKIE_NAME}${index}`, chunk, sameSite))
    }
    // Ensure at least one cookie is always written (empty token edge-case)
    if (index === 0) {
        headers.push(cookieHeader(`${ACCESS_TOKEN_COOKIE_NAME}0`, "", sameSite))
        index = 1
    }
    // Clear any leftover parts from a previous session that had more chunks
    for (let i = index; i < prevCount; i++) {
        headers.push(clearCookieHeader(`${ACCESS_TOKEN_COOKIE_NAME}${i}`, sameSite))
    }
    return headers
}

// Returns Set-Cookie headers that expire all access token chunk cookies.
function clearAccessTokenCookieHeaders(sameSite: string, count: number = 1): string[] {
    const headers: string[] = []
    for (let i = 0; i < Math.max(count, 1); i++) {
        headers.push(clearCookieHeader(`${ACCESS_TOKEN_COOKIE_NAME}${i}`, sameSite))
    }
    return headers
}

function cookieHeader(name: string, value: string, sameSite: string): string {
    return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=${sameSite}`
}

function clearCookieHeader(name: string, sameSite: string): string {
    return `${name}=; Path=/; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0`
}
