"use server"

import * as z from "zod";
import { ResetPasswordSchema } from "@/schemas/auth.schema";
import { getUserByEmail } from "@/helpers/user";
import { generatePasswordResetToken } from "@/lib/tokens";
import { sendPasswordResetEmail } from "@/lib/mail";

export const resetPassword = async (values: z.infer<typeof ResetPasswordSchema>) => {
    const validateFields = ResetPasswordSchema.safeParse(values);

    if (!validateFields.success) {
        return { error: "Invalid email!", status: 400 };
    }

    const { email } = validateFields.data;

    const existingUser = await getUserByEmail(email);

    if (!existingUser) return { error: "Email not found!" };

    // TODO:Generate token and send reset email
    const passwordResetToken = await generatePasswordResetToken(email);
    await sendPasswordResetEmail(
        passwordResetToken.email,
        passwordResetToken.token
    )

    return { success: "Reset email sent!", status: 200 }
}