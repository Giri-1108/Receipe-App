import jwt from "jsonwebtoken";
import Auth from "../Models/authSchema.js";

export const protect = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      req.user = await Auth.findById(decoded.id).select("-password");

      if (!req.user) {
        return res.status(401).json({ message: "User not found" });
      }

      next();
    } catch (error) {
      console.error("Token verification failed:", error.message);
      return res.status(401).json({
        message: "Not authorized, invalid token,please Logout and Login again",
      });
    }
  } else {
    return res.status(401).json({ message: "Not authorized, token missing" });
  }
};
