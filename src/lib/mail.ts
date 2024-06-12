import { Resend } from 'resend';

const resend = new Resend(process.env.RESEND_API_KEY);

export const sendVerificationEmail = async (
    email: string,
    token: string,
) => {
    const confirmLink = `${process.env.NEXT_PUBLIC_SERVER_URL}/auth/new-verification?token=${token}`;

    await resend.emails.send({
        from: process.env.RESEND_EMAIL_ID as string,
        to: email,
        subject: `Confirm your email for ${process.env.APP_NAME}`,
        html: `<p>Please click <a href="${confirmLink}">here</a> to verify your account.</p>`
    })
}


export const sendPasswordResetEmail = async (
    email: string,
    token: string,
) => {
    const resetPasswordLink = `${process.env.NEXT_PUBLIC_SERVER_URL}/auth/new-password?token=${token}`;

    await resend.emails.send({
        from: process.env.RESEND_EMAIL_ID as string,
        to: email,
        subject: `Reset your password for ${process.env.APP_NAME}`,
        html: `<p>Please click <a href="${resetPasswordLink}">here</a> to reset your password.</p>`
    })
}


export const sendTwoFactorTokenEmail = async (
    email: string,
    token: string,
) => {

    await resend.emails.send({
        from: process.env.RESEND_EMAIL_ID as string,
        to: email,
        subject: `Two factor authentication for ${process.env.APP_NAME}`,
        html: `<p>Your two-factor authentication code is: ${token}</p>`
    })
}