import Auth from "../Models/authSchema.js";
import jwt from "jsonwebtoken";
import bcryptjs from "bcryptjs";
import nodemailer from "nodemailer";
import crypto from "crypto";

// Register a new user

export const register = async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    // Check if email is already in use
    const existingUser = await Auth.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Create a new user
    const newUser = new Auth({ username, email, password, role });
    await newUser.save();

    // Generate JWT token
    const token = jwt.sign(
      { id: newUser._id, role: newUser.role },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    res.status(201).json({
      message: "User registered successfully",
      user: { id: newUser._id, username: newUser.username, role: newUser.role },
      token,
    });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Registration failed", error: error.message });
  }
};

// Login a user

export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user exists
    const user = await Auth.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Check if password matches
    const isMatch = await bcryptjs.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    res.json({
      message: "Login successful",
      user: { id: user._id, username: user.username, role: user.role },
      token,
    });
  } catch (error) {
    res.status(500).json({ message: "Login failed", error: error.message });
  }
};

// Forgot Password

export const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await Auth.findOne({ email });
    if (!user) {
      return res
        .status(400)
        .json({ message: "User with this email does not exist" });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    // Save the hashed token and expiration date to the user model
    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpire = Date.now() + 3600000; // 1 hour
    await user.save();

    // Check email credentials
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      return res.status(500).json({ message: "Email configuration missing" });
    }

    // Send the reset token via email
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
      tls: {
        rejectUnauthorized: false, // ✅ Fix self-signed SSL issue
      },
    });

    const resetLink = `https://book-appgd.netlify.app/reset-password/${resetToken}`;

    const mailOptions = {
      to: email,
      from: process.env.EMAIL_USER,
      subject: "Password Reset Request",
      text: `You requested a password reset. Click the link below to reset your password:\n\n${resetLink}\n\nThis link will expire in 1 hour.`,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: "Password reset link sent to email" });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error generating reset token", error: error.message });
  }
};
// Reset Password

export const resetPassword = async (req, res) => {
  const { resetToken } = req.params;
  const { newPassword } = req.body;

  try {
    // ✅ Hash the token before searching in DB (matches stored hashed token)
    const hashedToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    // ✅ Find user by hashed token and check if it's still valid
    const user = await Auth.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res
        .status(400)
        .json({ message: "Invalid or expired reset token" });
    }

    // ✅ Hash the new password before saving (important for security)
    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();

    res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};
