import express from "express";
import {
  forgotPassword,
  login,
  register,
  resetPassword,
  verifyOtp,
} from "../Controllers/authController.js";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/forgotPassword", forgotPassword);
router.post("/otp", verifyOtp);
router.post("/resetPassword/:resetToken", resetPassword);

export default router;
