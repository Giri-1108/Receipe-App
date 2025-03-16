import mongoose from "mongoose";
import bcryptjs from "bcryptjs";

const authSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
    resetPasswordToken: String, // Token for password reset
    resetPasswordExpire: Date, // Expiration time for the reset token
  },
  { timestamps: true }
);

// Hash Password before saving
authSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  const salt = await bcryptjs.genSalt(10);
  this.password = await bcryptjs.hash(this.password, salt);
  next();
});

// Compare password (used for login)
authSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcryptjs.compare(enteredPassword, this.password);
};

const Auth = mongoose.model("Auth", authSchema);
export default Auth;
