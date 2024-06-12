import NextAuth, { DefaultSession } from "next-auth";

export type ExtendedUser = DefaultSession["user"] & {
    isTwoFactorEnabled: boolean
    isOAuth: boolean
};

declare module "next-auth" {
    interface Session extends DefaultSession {
        user: ExtendedUser;
    }
}