"use client";

import { useCallback, useEffect, useState } from "react";
import { BeatLoader } from "react-spinners";
import { CardWrapper } from "./card-wrapper";
import { useSearchParams } from "next/navigation";
import { newVerification } from "@/actions/new-verification";
import { FormError } from "@/components/form-error";
import { FormSuccess } from "@/components/form-success";

export const NewVerificationForm = () => {
    const searchParams = useSearchParams();
    const token = searchParams.get("token");

    const [error, setError] = useState<string | undefined>();
    const [success, setSuccess] = useState<string | undefined>();

    const onSubmit = useCallback(() => {
        if (!token) {
            setError("Missing token!");
            return;
        }

        newVerification(token)
            .then((data) => {
                setSuccess(data.success);
                setError(data.error);
            })
            .catch(() => {
                setError("Something went wrong!");
            });
    }, [token]);

    useEffect(() => {
        onSubmit();
    }, [onSubmit]);

    return (
        <CardWrapper
            headerLabel="Confirming your verification"
            backButtonLabel="Back to login"
            backButtonHref="/auth/login"
        >
            <div className="w-full flex justify-center items-center">
                {!error && !success && <BeatLoader />}
                <FormError message={error} />
                {!error && <FormSuccess message={success} />}
            </div>
        </CardWrapper>
    );
};
