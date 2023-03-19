import mongoose from "mongoose";

const userCollections = 'usuarios';

const UserSchema = new mongoose.Schema(
    {
        email: {type: String, require: true, max: 100},
        password: {type: String, require: true}
    }
)

export const users = mongoose.model(userCollections, UserSchema);