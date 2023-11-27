import { DocumentType, Severity, getModelForClass, modelOptions, pre, prop,index } from "@typegoose/typegoose";
import argon2 from "argon2";
import log from "../utils/logger";


const importNanoid = async () => {
    const { nanoid } = await import("nanoid");
    return nanoid();
};

export const privateFields = ["password","__v","verificationCode","passwordResetCode","verified"];

@pre<User>("save",async function(){
    if(!this.isModified('password') || this.password === null){
        return;
    }

    const hash = await argon2.hash(this.password);
    this.password = hash;
    return;
})
@index({email:1})
@modelOptions({
    schemaOptions:{
        timestamps:true
    },
    options:{
        allowMixed:Severity.ALLOW
    }
})
export class User {
    @prop({ lowercase:true,required:true,unique:true })
    email:string;

    @prop({required:true})
    lastName:string;

    @prop({required:true})
    password:string;

    @prop({required:true,default:async()=> importNanoid()})
    verificationCode:string;

    @prop()
    passwordResetCode:string | null;

    @prop({default:false})
    verified:boolean

    async validatePassword(this:DocumentType<User>,candidatePassword:string){
        try{
            if(this.password === null) throw null
            return await argon2.verify(this.password,candidatePassword);
        }catch(err){
            log.error(err,"Coul not validate password")
            return false;
        }
    }
}

const UserModel = getModelForClass(User);

export default UserModel;