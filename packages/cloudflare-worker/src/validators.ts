export function validateAuthUrl(authUrl: string): URL {
    try {
        return new URL(authUrl)
    } catch (e) {
        console.error("Invalid authUrl", e)
        throw new Error("Unable to initialize auth client")
    }
}
