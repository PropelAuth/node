export default class UnauthorizedException extends Error {
    readonly message: string;
    readonly status: number;
    constructor(message: string) {
        super(message);
        this.message = message;
        this.status = 401;
    }
}
