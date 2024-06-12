import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { SessionProvider } from "next-auth/react";
import { auth } from "@/auth";
import { Toaster } from "@/components/ui/sonner";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
    title: "Genix",
    description: "AI-powered image generator",
};

export default async function RootLayout({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) {
    const session = await auth();
    return (
        <html lang="en">
            <SessionProvider session={session}>
                <body className={inter.className}>
                    <body className={inter.className}>
                        {children}
                        <Toaster />
                    </body>
                </body>
            </SessionProvider>
        </html>
    );
}
