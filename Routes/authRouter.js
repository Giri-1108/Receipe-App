import express from "express";
import {
  forgotPassword,
  login,
  register,
  resetPassword,
} from "../Controllers/authController.js";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/forgotPassword", forgotPassword);
router.post("/resetPassword/:resetToken", resetPassword);

export default router;
