import { DocumentType } from "@typegoose/typegoose";
import { User, privateFields } from "../model/user.model";
import { signJwt } from "../utils/jwt";
import { omit } from "lodash";
import SessionModel from "../model/session.model";

export async function createSession({userId}:{userId:string}) {
    return SessionModel.create({user:userId})
}

export async function signRefreshToken({userId}:{userId:string}){
    const session = await createSession({
        userId
    })

    const refreshToken = signJwt({session:session.id},'refreshTokenPrivateKey',{expiresIn:"1y"});
    return refreshToken
}

export function signAccessToken(user:DocumentType<User>){
    const payload = omit(user.toJSON(),privateFields);
    const accessToken = signJwt(payload,"accessTokenPrivateKey",{expiresIn:"15m"});
    return accessToken
}

export function findSesstionById(id:string){
    return SessionModel.findById(id);
}