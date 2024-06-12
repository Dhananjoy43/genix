import GitHub from "next-auth/providers/github"
import Google from "next-auth/providers/google"
import Credentials from "next-auth/providers/credentials"
import type { NextAuthConfig } from "next-auth"
import { LoginSchema } from "./schemas/auth.schema"
import { getUserByEmail } from "./helpers/user"
import bcrypt from "bcryptjs"

export default {
    providers: [
        GitHub,
        Google,
        Credentials({
            async authorize(credentials) {
                const validatedFields = LoginSchema.safeParse(credentials);

                if (validatedFields.success) {
                    const { email, password } = validatedFields.data;

                    const user = await getUserByEmail(email);

                    if (!user || !user.password) return null;

                    const isValidPassword = await bcrypt.compare(password, user.password);

                    if (isValidPassword) return user;
                }

                return null;
            }
        })],
} satisfies NextAuthConfig