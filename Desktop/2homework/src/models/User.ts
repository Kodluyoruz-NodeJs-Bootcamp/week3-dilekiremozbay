import mongoose from "mongoose";

export interface User {
  firstName: string;
  lastName: string;
  username: string;
  password: string;
  security: {
    tokens: { _id: string; refreshToken: string; createAt: Date }[];
  };
}

const userSchema = new mongoose.Schema<User>({
  firstName: {
    type: String,
    required: true,
    min: 3,
    max: 25,
  },

  lastName: {
    type: String,
    required: true,
    min: 3,
    max: 25,
  },

  username: {
    type: String,
    required: true,
    min: 4,
    max: 25,
  },
  password: {
    type: String,
    required: true,
    min: 6,
    max: 255,
  },
  security: {
    tokens: [
      {
        _id: String,
        refreshToken: String,
        createdAt: Date,
      },
    ],
  },
});

export const UserModel = mongoose.model<User>("User", userSchema);
