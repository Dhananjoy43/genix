import NextAuth from "next-auth"
import authConfig from "@/auth.config"
import { PrismaAdapter } from "@auth/prisma-adapter"
import { getUserById } from "@/helpers/user"
import { getAccountByUserId } from "@/helpers/account"
import { getTwoFactorConfirmationByUserId } from "@/helpers/two-factor-confirmation"
import { db } from "@/lib/db"

export const { handlers: { GET, POST }, auth, signIn, signOut, unstable_update } = NextAuth({
    adapter: PrismaAdapter(db),
    session: { strategy: "jwt" },
    pages: {
        signIn: "/auth/login",
        error: "/auth/error",
    },
    events: {
        async linkAccount({ user }) {
            await db.user.update({
                where: {
                    id: user.id
                },
                data: {
                    emailVerified: new Date()
                }
            })
        }
    },
    callbacks: {
        async signIn({ user, account }) {
            console.log("User:", user);

            // allow OAuth providers without email verification
            if (account?.provider != "credentials") return true;

            const existingUser = await getUserById(user.id as string);

            // Prevent signIn without email verification
            if (!existingUser || !existingUser.emailVerified) {
                return false;
            }

            // Check two factor authentication
            if (existingUser.isTwoFactorEnabled) {
                const twoFactorConfirmation = await getTwoFactorConfirmationByUserId(existingUser.id);

                if (!twoFactorConfirmation) {
                    return false;
                }

                // Delete two factor confirmation for next sign in
                await db.twoFactorConfirmation.delete({
                    where: {
                        id: twoFactorConfirmation.id
                    }
                })
            }

            return true;
        },
        async session({ token, session }) {
            // console.log({ sessionToken: token });
            // console.log({ session: session });
            if (token.sub && session.user) {

                session.user.id = token.sub;
            }

            if (session.user) {
                session.user.isTwoFactorEnabled = token.isTwoFactorEnabled as boolean;
            }

            if (session.user) {
                session.user.name = token.name;
                session.user.email = token.email as string;
                session.user.isOAuth = token.isOAuth as boolean;
            }

            return session;
        },
        async jwt({ token }) {
            // console.log({ JWTToken: token });
            if (!token.sub) return token;

            const existingUser = await getUserById(token.sub);

            if (!existingUser) return token;

            const existingAccount = await getAccountByUserId(existingUser.id);

            token.isOAuth = !!existingAccount;
            token.name = existingUser.name;
            token.email = existingUser.email;
            token.isTwoFactorEnabled = existingUser.isTwoFactorEnabled;

            return token;
        }
    },
    ...authConfig,
})