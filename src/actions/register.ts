"use server"

import { RegisterSchema } from "@/schemas/auth.schema";
import * as z from "zod";
import bcrypt from "bcryptjs";

import { db } from "@/lib/db";
import { getUserByEmail } from "@/helpers/user";
import { generateVerificationToken } from "@/lib/tokens";
import { sendVerificationEmail } from "@/lib/mail";

export const register = async (values: z.infer<typeof RegisterSchema>) => {
    const validatefields = RegisterSchema.safeParse(values);

    if (!validatefields.success) {
        return { error: "Invalid fields!" };
    }

    const { name, email, password } = validatefields.data;
    const hashedPassword = await bcrypt.hash(password, 10);

    const existingUser = await getUserByEmail(email);

    if (existingUser) {
        return { error: "Email already in use!" };
    }

    await db.user.create({
        data: {
            name,
            email,
            password: hashedPassword,
        }
    });

    // Generate verification token
    const verificationToken = await generateVerificationToken(email);

    // SEND verification token email
    await sendVerificationEmail(verificationToken.email, verificationToken.token);


    return { success: "Confirmation email sent!" }
}