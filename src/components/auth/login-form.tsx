"use client";
import { useState, useTransition } from "react";
import * as z from "zod";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { LoginSchema } from "@/schemas/auth.schema";

import {
    Form,
    FormControl,
    FormField,
    FormItem,
    FormLabel,
    FormMessage,
} from "@/components/ui/form";

import { CardWrapper } from "@/components/auth/card-wrapper";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { FormError } from "@/components/form-error";
import { FormSuccess } from "@/components/form-success";
import { login } from "@/actions/login";
import { useSearchParams } from "next/navigation";
import Link from "next/link";

export const LoginForm = () => {
    const searchParams = useSearchParams();
    const callbackUrl = searchParams.get("callbackUrl");
    const urlError =
        searchParams.get("error") === "OAuthAccountNotLinked"
            ? "Email already in use with different provider!"
            : "";
    const [isPending, startTransition] = useTransition();
    const [error, setError] = useState<string | undefined>("");
    const [success, setSuccess] = useState<string | undefined>("");
    const [showTwoFactor, setShowTwoFactor] = useState(false);

    const form = useForm<z.infer<typeof LoginSchema>>({
        resolver: zodResolver(LoginSchema),
        defaultValues: {
            email: "",
            password: "",
        },
    });
    const onSubmit = (values: z.infer<typeof LoginSchema>) => {
        setError("");
        setSuccess("");

        startTransition(() => {
            login(values, callbackUrl)
                .then((data) => {
                    if (data?.error) {
                        form.reset();
                        setError(data?.error);
                    }
                    if (data?.success) {
                        form.reset();
                        setSuccess(data?.success);
                    }
                    if (data?.twoFactor) {
                        setShowTwoFactor(true);
                        setSuccess("Confirmation code sent to your email!");
                    }
                })
                .catch(() => {
                    setError("Something went wrong!");
                });
        });
    };
    return (
        <CardWrapper
            headerLabel="Welcome back"
            backButtonLabel="Don't have an account?"
            backButtonHref="/auth/register"
            showSocial
        >
            <Form {...form}>
                <form
                    onSubmit={form.handleSubmit(onSubmit)}
                    className="space-y-6"
                >
                    <div className="space-y-4">
                        {showTwoFactor && (
                            <FormField
                                control={form.control}
                                name="code"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel>Two factor code</FormLabel>
                                        <FormControl>
                                            <Input
                                                {...field}
                                                placeholder="123456"
                                                disabled={isPending}
                                            />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />
                        )}
                        {!showTwoFactor && (
                            <>
                                <FormField
                                    control={form.control}
                                    name="email"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>Email</FormLabel>
                                            <FormControl>
                                                <Input
                                                    {...field}
                                                    placeholder="john.doe@gmail.com"
                                                    disabled={isPending}
                                                    type="email"
                                                />
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                                <FormField
                                    control={form.control}
                                    name="password"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>Password</FormLabel>
                                            <FormControl>
                                                <Input
                                                    {...field}
                                                    placeholder="password@123"
                                                    disabled={isPending}
                                                    type="password"
                                                />
                                            </FormControl>
                                            <Button
                                                className="font-normal"
                                                size={"sm"}
                                                variant={"link"}
                                                asChild
                                            >
                                                <Link href={"/auth/reset"}>
                                                    Forgot password?
                                                </Link>
                                            </Button>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                            </>
                        )}
                    </div>
                    <FormError message={error || urlError} />
                    <FormSuccess message={success} />
                    <Button
                        type="submit"
                        disabled={isPending}
                        className="w-full"
                    >
                        {showTwoFactor ? "Confirm" : "Login"}
                    </Button>
                </form>
            </Form>
        </CardWrapper>
    );
};
