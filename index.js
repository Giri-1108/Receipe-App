import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoDB } from "./Database/config.js";
import router from "./Routes/authRouter.js";
// import router1 from "./Routers/storyRouter.js";
// import router2 from "./Routers/ratingRouter.js";
dotenv.config();

// Middleware
const app = express();

app.use(express.json());
app.use(
  cors({
    origin: "https://book-appgd.netlify.app",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

// Error handler
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || "Internal Server Error";
  res.status(statusCode).json({
    success: false,
    statusCode,
    message,
  });
});

// DB connectivity
MongoDB();

// Access the .env
const port = process.env.PORT || 4000;
const message = process.env.MESSAGE || "Hello, World!";

// Default routes
app.get("/", (req, res) => {
  res.status(200).send(message);
});

// API Routes

app.use("/api/auth", router);

// Listen
app.listen(port, () => {
  console.log(`🚀 Server is running on port ${port}`);
});
