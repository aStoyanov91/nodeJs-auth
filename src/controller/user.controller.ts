import { Request, Response } from "express";
import { CreateUserInput, ForgotPasswordInput, ResetPasswordInput, VerifyUserInput } from "../schema/user.schema";
import { createUser, findUserByEmail, findUserById } from "../service/user.service";
import sendEmail from "../utils/mailer";
import log from "../utils/logger";
const importNanoid = async () => {
    const { nanoid } = await import("nanoid");
    return nanoid();
};

export async function createUserHandler(req:Request<{},{},CreateUserInput>,res:Response) {
    const body = req.body;

    try{
        const user = await createUser(body);

        await sendEmail({from:"test@example.com",to:user.email,subject:"Please verify your email",text:`Verification code ${user.verificationCode}. Id:${user.id}`});
        res.send("User successfully created");
    }catch(err:any){
        if(err.code === 11000){
            return res.status(409).send("Account already exists");
        }

        return res.status(500).send(err)
    }
}

export async function verifyUserHandler(req:Request<VerifyUserInput>,res:Response){
    const id = req.params.id;
    const verificationCode = req.params.verificationCode;

    // find user by id
    const user = await findUserById(id);

    if(!user) {
        return res.send("Could not verify user");
    }

    if(user.verified){
        return res.send("User is allready verified")
    }

    if(user.verificationCode === verificationCode){
        user.verified = true;
        await user.save();

        return res.send("User successfully verified")
    }
}

export async function forgotPasswordHandler(req:Request<{},{},ForgotPasswordInput>,res:Response){
    const message = "If a user with that email is registered you will receive a password reset email"
    const {email} = req.body;
    const user = await findUserByEmail(email);

    if(!user){
        log.debug(`User with email ${email} does not exists`);
        return res.send(message);
    }

    if(!user.verified){
        return res.send("User is not verified");
    }

    const passwordResetCode = await importNanoid();

    user.passwordResetCode = passwordResetCode;
    await user.save();
    await sendEmail({to:user.email,from:"test@example.com",subject:"Reset your password",text:`Password reset code : ${passwordResetCode}. Id ${user.id}`});

    log.debug(`Password reset email send to ${user.email}`);

    return res.send(message);
}

export async function resetPasswordHandler(req:Request<ResetPasswordInput['params'],{},ResetPasswordInput['body']>,res:Response){
    const {id,passwordResetCode} = req.params;
    const {password} = req.body;

    const user = await findUserById(id);

    if(!user || !user.passwordResetCode || user.passwordResetCode !== passwordResetCode){
        return res.status(400).send("Could not reset user password");
    }

    user.passwordResetCode = null;
    user.password = password;

    await user.save();

    return res.send("Successfully updated password");
}

export async function getCurrentUserHandler(req:Request,res:Response) {
    return res.send(res.locals.user);
}