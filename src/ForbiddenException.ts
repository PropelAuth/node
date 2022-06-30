export default class ForbiddenException extends Error {
    readonly message: string;
    readonly status: number;
    constructor(message: string) {
        super(message);
        this.message = message;
        this.status = 403;
    }
}
